# -*- coding: utf-8 -*-
"""Tests for the incremental TLS record/handshake reassembler.

The same fixed ClientHello and Certificate samples are fed through every
possible short boundary split to prove that reassembly is independent of how
the transport chunks the byte stream.
"""
from __future__ import absolute_import

import struct
from binascii import unhexlify

import pytest

from dpkt import ssl
from dpkt import tls_reassembly as tr
from dpkt.tls_reassembly import (
    TLSHandshakeAssembler, HandshakeMessage, AlertEvent,
    ChangeCipherSpecEvent, EncryptedRecordEvent,
    MalformedRecordError, MessageLimitExceeded, BufferLimitExceeded,
    TruncatedStreamError,
)


# ---------------------------------------------------------------------------
# Fixed samples (ClientHello mirrors dpkt/ssl.py TestClientHello; the
# Certificate is a small, fully valid one-certificate message)
# ---------------------------------------------------------------------------
_CLIENT_HELLO_HEX = (
    b"01000199"
    b"0301"
    b"5008220ce5e0e78b6891afe204498c9363feffbe03235a2d9e05b7d990eb708d"
    b"2009bc0192e008e6fa8fe47998fca91311ba30ddde14a9587dc674b11c3d3e5ed1"
    b"005200ffc00ac0140088008700390038c00fc00500840035c007c009c011c0130045004400330032"
    b"c00cc00ec002c0040096004100050004002fc008c01200160013c00dc003000ac006c010c00bc00100020001"
    b"0100"
    b"00fc0000000e000c0000096c6f636c686f7374000a00080006001700180019000b000201000023"
    b"00d0a50b2e9f618a9ea9bf493ef49b421835cd2f6b05bbe1179d8edf70d58c33d656e8696d36d7e7"
    b"e0b9d3ecc0e4de339552fa06c64c0fcb550a334bc43944e2739ca342d15a9ebbe981ac87a0d38160"
    b"507d47af09bdc16c5f0ee4cdceea551539382333226048a026d3a90a0535f4a64236467db8fee22b"
    b"041af986ad0f253bc369137cd8d8cd061925461d7f4d7895ca9a4181ab554dad50360ac31860e971"
    b"483877c9335ac1300c5e78f3e56f3b8e0fc16358fcaceefd5c8d8aaae7b35be116f8832856ca6114"
    b"4fcdd95e071b94d0cf7233740000"
    b"FFFFFFFFFFFFFFFF"  # trailing garbage present in the original sample
)


def _make_client_hello():
    raw = unhexlify(_CLIENT_HELLO_HEX)
    body_len = struct.unpack('!I', b'\x00' + raw[1:4])[0]
    return raw[:4 + body_len]


def _make_certificate():
    cert_blob = unhexlify('30820005' + '00' * 5)
    cert_list = struct.pack('!I', len(cert_blob))[1:] + cert_blob
    return b'\x0b' + struct.pack('!I', len(cert_list))[1:] + cert_list


def _make_server_hello_done():
    return b'\x0e\x00\x00\x00'


def _record(rec_type, payload, version=ssl.TLS12_V):
    return struct.pack('!BHH', rec_type, version, len(payload)) + payload


CLIENT_HELLO = _make_client_hello()
CERTIFICATE = _make_certificate()
SERVER_HELLO_DONE = _make_server_hello_done()


def _build_split_stream():
    """Stream exercising every framing case at once.

    * record 1: first part of ClientHello
    * record 2: rest of ClientHello + full Certificate + start of SHD
    * record 3: rest of SHD
    """
    cut = 37
    stream = _record(22, CLIENT_HELLO[:cut])
    stream += _record(22, CLIENT_HELLO[cut:] + CERTIFICATE +
                      SERVER_HELLO_DONE[:2])
    stream += _record(22, SERVER_HELLO_DONE[2:])
    return stream


SPLIT_STREAM = _build_split_stream()
EXPECTED_MESSAGES = [CLIENT_HELLO, CERTIFICATE, SERVER_HELLO_DONE]
EXPECTED_TYPES = [1, 11, 14]


def _collect(assembler, chunks):
    events = []
    for chunk in chunks:
        events.extend(assembler.feed(chunk))
    return events


def _all_single_splits(data):
    """Every (prefix, suffix) cut of data, including the empty-chunk edges."""
    for cut in range(len(data) + 1):
        yield [data[:cut], data[cut:]]


def _fixed_size_chunks(data, size):
    return [data[i:i + size] for i in range(0, len(data), size)]


# ---------------------------------------------------------------------------
# Exhaustive boundary splitting
# ---------------------------------------------------------------------------
class TestAllBoundarySplits(object):
    """Feed the fixed samples through every short boundary split."""

    def _assert_messages(self, events):
        messages = [e for e in events if isinstance(e, HandshakeMessage)]
        assert [m.type for m in messages] == EXPECTED_TYPES
        assert [m.raw for m in messages] == EXPECTED_MESSAGES
        assert [len(m.body) for m in messages] == [
            len(m) - 4 for m in EXPECTED_MESSAGES]
        assert all(isinstance(m.parsed, ssl.TLSClientHello)
                   for m in messages[:1])
        assert isinstance(messages[1].parsed, ssl.TLSCertificate)
        assert messages[2].parsed is not None
        # order check: byte offsets of messages are strictly increasing
        # is implied by list equality above; also verify event ordering
        assert events == messages

    def test_every_two_feed_split(self):
        for chunks in _all_single_splits(SPLIT_STREAM):
            assembler = TLSHandshakeAssembler()
            events = _collect(assembler, chunks)
            self._assert_messages(events)
            assert assembler.records_seen == 3
            assert assembler.messages_seen == 3
            assert assembler.state == tr.STATE_PLAINTEXT
            assert assembler.finish() == []

    def test_every_fixed_chunk_size(self):
        for size in range(1, 8):
            assembler = TLSHandshakeAssembler()
            events = _collect(
                assembler, _fixed_size_chunks(SPLIT_STREAM, size))
            self._assert_messages(events)
            assert assembler.finish() == []

    def test_byte_by_byte_feeds(self):
        assembler = TLSHandshakeAssembler()
        events = _collect(
            assembler, [SPLIT_STREAM[i:i + 1]
                        for i in range(len(SPLIT_STREAM))])
        self._assert_messages(events)
        assert assembler.records_seen == 3

    def test_empty_and_none_feeds_are_noop(self):
        assembler = TLSHandshakeAssembler()
        assert assembler.feed(b'') == []
        events = _collect(assembler, [SPLIT_STREAM[:10], b'',
                                      SPLIT_STREAM[10:]])
        self._assert_messages(events)


class TestSingleMessageAcrossRecords(object):
    def test_client_hello_split_at_every_byte(self):
        # one record containing the whole CH, then cut at every byte boundary
        stream = _record(22, CLIENT_HELLO)
        for chunks in _all_single_splits(stream):
            assembler = TLSHandshakeAssembler()
            events = _collect(assembler, chunks)
            assert len(events) == 1
            message = events[0]
            assert isinstance(message, HandshakeMessage)
            assert message.type == 1
            assert message.raw == CLIENT_HELLO
            assert isinstance(message.parsed, ssl.TLSClientHello)
            assert assembler.finish() == []

    def test_certificate_split_across_many_records(self):
        # chop the Certificate itself into 3-byte fragments, one record each
        fragments = [CERTIFICATE[i:i + 3]
                     for i in range(0, len(CERTIFICATE), 3)]
        stream = b''.join(_record(22, fragment) for fragment in fragments)
        assembler = TLSHandshakeAssembler()
        events = _collect(assembler, _fixed_size_chunks(stream, 7))
        assert len(events) == 1
        assert events[0].raw == CERTIFICATE
        assert isinstance(events[0].parsed, ssl.TLSCertificate)
        assert len(events[0].parsed.certificates) == 1


class TestMultipleMessagesInOneRecord(object):
    def test_two_messages_one_record_all_splits(self):
        stream = _record(22, CLIENT_HELLO + SERVER_HELLO_DONE)
        for chunks in _all_single_splits(stream):
            assembler = TLSHandshakeAssembler()
            events = _collect(assembler, chunks)
            assert [e.type for e in events] == [1, 14]
            assert [e.raw for e in events] == [
                CLIENT_HELLO, SERVER_HELLO_DONE]
            assert assembler.finish() == []

    def test_three_messages_one_record(self):
        stream = _record(22, CERTIFICATE + SERVER_HELLO_DONE + CERTIFICATE)
        assembler = TLSHandshakeAssembler()
        events = assembler.feed(stream)
        assert [e.type for e in events] == [11, 14, 11]
        assert events[0].raw == CERTIFICATE
        assert events[2].raw == CERTIFICATE


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------
class TestTruncation(object):
    def test_truncated_record_header(self):
        stream = _record(22, CLIENT_HELLO)
        for cut in (1, 2, 3, 4):
            assembler = TLSHandshakeAssembler()
            assembler.feed(stream[:cut])
            with pytest.raises(TruncatedStreamError):
                assembler.finish()
            assert assembler.state == tr.STATE_ERROR

    def test_truncated_record_payload(self):
        stream = _record(22, CLIENT_HELLO)
        assembler = TLSHandshakeAssembler()
        assembler.feed(stream[:-5])
        with pytest.raises(TruncatedStreamError):
            assembler.finish()

    def test_truncated_handshake_header_and_body(self):
        stream = _record(22, CLIENT_HELLO)
        for cut in (5, 6, 8, 9, 50):
            assembler = TLSHandshakeAssembler()
            assembler.feed(stream[:cut])
            with pytest.raises(TruncatedStreamError):
                assembler.finish()

    def test_resume_after_more_bytes_arrives(self):
        # not an error if the missing tail arrives before finish()
        stream = _record(22, CLIENT_HELLO)
        assembler = TLSHandshakeAssembler()
        assert assembler.feed(stream[:20]) == []
        events = assembler.feed(stream[20:])
        assert len(events) == 1 and events[0].raw == CLIENT_HELLO
        assert assembler.finish() == []


# ---------------------------------------------------------------------------
# Malformed framing and bad lengths
# ---------------------------------------------------------------------------
class TestMalformedInput(object):
    def test_bad_record_version(self):
        assembler = TLSHandshakeAssembler()
        with pytest.raises(MalformedRecordError, match='bad record layer version'):
            assembler.feed(_record(22, b'\x00', version=0x0400))
        assert assembler.state == tr.STATE_ERROR
        with pytest.raises(tr.TLSReassemblyError):
            assembler.feed(b'\x00')

    def test_record_payload_over_tls_limit(self):
        header = struct.pack('!BHH', 22, ssl.TLS12_V,
                             tr.MAX_RECORD_PAYLOAD + 1)
        assembler = TLSHandshakeAssembler()
        with pytest.raises(MalformedRecordError, match='exceeds TLS limit'):
            assembler.feed(header)

    def test_unknown_record_type(self):
        assembler = TLSHandshakeAssembler()
        with pytest.raises(MalformedRecordError, match='unknown record content type 99'):
            assembler.feed(_record(99, b'\x01\x02'))

    def test_handshake_declared_length_too_big(self):
        # header claims 1000 bytes but the record ends the stream early
        bogus = b'\x01' + struct.pack('!I', 1000)[1:] + b'\x00' * 10
        assembler = TLSHandshakeAssembler(max_message_size=100,
                                          max_buffer_size=400)
        with pytest.raises(MessageLimitExceeded, match='exceeds limit'):
            assembler.feed(_record(22, bogus))

    def test_encryption_mid_message_is_error(self):
        assembler = TLSHandshakeAssembler()
        partial = _record(22, CLIENT_HELLO[:20])  # whole message not present
        assembler.feed(partial)
        with pytest.raises(MalformedRecordError,
                           match='encryption started in the middle'):
            assembler.feed(_record(20, b'\x01'))

    def test_malformed_inner_body_still_delivered_raw(self):
        # ServerHello (type 2) whose claimed-complete body is garbage.
        body = b'\x00' * 8
        raw = b'\x02' + struct.pack('!I', len(body))[1:] + body
        assembler = TLSHandshakeAssembler()
        events = assembler.feed(_record(22, raw))
        assert len(events) == 1
        assert events[0].type == 2
        assert events[0].raw == raw
        assert events[0].parsed is None
        assert assembler.state == tr.STATE_PLAINTEXT
        assert assembler.finish() == []


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
class TestLimits(object):
    def test_message_limit_by_declared_length(self):
        body = b'\x00' * 20
        bogus = b'\x01' + struct.pack('!I', 500)[1:] + body
        assembler = TLSHandshakeAssembler(max_message_size=100,
                                          max_buffer_size=1024)
        with pytest.raises(MessageLimitExceeded):
            assembler.feed(_record(22, bogus))

    def test_message_limit_while_reassembling(self):
        # declared length is legal but bigger than the configured limit
        big = b'\x01' + struct.pack('!I', 300)[1:] + b'\x00' * 300
        assembler = TLSHandshakeAssembler(max_message_size=100,
                                          max_buffer_size=4096)
        with pytest.raises(MessageLimitExceeded):
            assembler.feed(_record(22, big))

    def test_buffer_limit_on_feed(self):
        assembler = TLSHandshakeAssembler(max_message_size=16,
                                          max_buffer_size=32)
        huge_record = _record(22, b'\x01' + b'\x00' * 100)
        with pytest.raises(BufferLimitExceeded):
            assembler.feed(huge_record)

    def test_invalid_limit_construction(self):
        with pytest.raises(ValueError):
            TLSHandshakeAssembler(max_message_size=0)
        with pytest.raises(ValueError):
            TLSHandshakeAssembler(max_message_size=10, max_buffer_size=5)


# ---------------------------------------------------------------------------
# Encrypted / opaque content handling
# ---------------------------------------------------------------------------
class TestEncryptedContent(object):
    def test_change_cipher_spec_then_app_data(self):
        assembler = TLSHandshakeAssembler()
        events = assembler.feed(_record(20, b'\x01'))
        assert len(events) == 1
        assert isinstance(events[0], ChangeCipherSpecEvent)
        assert assembler.state == tr.STATE_ENCRYPTED

        ciphertext = _record(23, b'\xde\xad\xbe\xef' * 4)
        events = assembler.feed(ciphertext)
        assert len(events) == 1
        assert isinstance(events[0], EncryptedRecordEvent)
        assert events[0].record_type == 23
        assert events[0].length == 16
        assert assembler.encrypted_bytes == len(ciphertext)
        # encrypted stream is allowed to end with pending ciphertext
        assert assembler.finish() == []

    def test_application_data_is_opaque(self):
        assembler = TLSHandshakeAssembler()
        events = assembler.feed(_record(23, b'\x00' * 32))
        assert isinstance(events[0], EncryptedRecordEvent)
        assert assembler.state == tr.STATE_ENCRYPTED
        # further bytes never get parsed as handshakes, even type-22 records
        events = assembler.feed(_record(22, b'\x01\x00\x00\x05abcde'))
        assert isinstance(events[0], EncryptedRecordEvent)
        assert events[0].record_type == 22

    def test_tls13_ciphertext_handshake_record_not_parsed(self):
        # TLS 1.3 encrypted handshake: type 22 record whose first byte is not
        # a valid plaintext handshake type -> must be treated as opaque
        assembler = TLSHandshakeAssembler()
        opaque = b'\x7b\x00\x00\x05' + b'\xaa\xbb\xcc\xdd\xee'
        events = assembler.feed(_record(22, opaque))
        assert len(events) == 1
        assert isinstance(events[0], EncryptedRecordEvent)
        assert assembler.state == tr.STATE_ENCRYPTED

    def test_mark_encrypted_after_plaintext_message(self):
        assembler = TLSHandshakeAssembler()
        assembler.feed(_record(22, SERVER_HELLO_DONE))
        assembler.mark_encrypted()
        assert assembler.state == tr.STATE_ENCRYPTED
        events = assembler.feed(_record(22, b'\x17' * 10))
        assert isinstance(events[0], EncryptedRecordEvent)

    def test_mark_encrypted_with_pending_bytes_rejected(self):
        assembler = TLSHandshakeAssembler()
        assembler.feed(_record(22, CLIENT_HELLO)[:12])
        with pytest.raises(TruncatedStreamError):
            assembler.mark_encrypted()

    def test_plaintext_alert_still_parsed(self):
        assembler = TLSHandshakeAssembler()
        events = assembler.feed(_record(21, b'\x02\x28'))
        assert isinstance(events[0], AlertEvent)
        assert events[0].level == 2
        assert events[0].description == 40
        assert assembler.state == tr.STATE_PLAINTEXT


# ---------------------------------------------------------------------------
# Instance isolation
# ---------------------------------------------------------------------------
class TestInstanceIsolation(object):
    def test_assemblers_do_not_share_state(self):
        a1 = TLSHandshakeAssembler()
        a2 = TLSHandshakeAssembler()
        a1.feed(_record(22, CLIENT_HELLO))
        # a2 must know nothing about a1's message and reassemble its own copy
        events = _collect(a2, _fixed_size_chunks(
            _record(22, CERTIFICATE), 5))
        assert len(events) == 1 and events[0].raw == CERTIFICATE
        assert a1.messages_seen == 1 and a2.messages_seen == 1
        assert a1.records_seen == 1 and a2.records_seen == 1

    def test_error_state_is_per_instance(self):
        good = TLSHandshakeAssembler()
        bad = TLSHandshakeAssembler()
        with pytest.raises(MalformedRecordError):
            bad.feed(_record(22, b'\x00', version=0x0400))
        assert bad.state == tr.STATE_ERROR
        assert good.state == tr.STATE_PLAINTEXT
        events = good.feed(_record(22, SERVER_HELLO_DONE))
        assert events[0].raw == SERVER_HELLO_DONE

    def test_events_from_separate_instances_are_independent(self):
        a1 = TLSHandshakeAssembler()
        a2 = TLSHandshakeAssembler()
        e1 = a1.feed(_record(22, CERTIFICATE))[0]
        e2 = a2.feed(_record(22, CERTIFICATE))[0]
        assert e1 == e2 and e1 is not e2
        assert e1.raw == e2.raw == CERTIFICATE
