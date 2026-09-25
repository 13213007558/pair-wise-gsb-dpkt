# -*- coding: utf-8 -*-
"""TLS 1.3 (RFC 8446) handshake transcript hash builder.

This module is meant for offline analysis: the caller has already obtained
the plaintext handshake records (e.g. by decrypting TLSCiphertext records
with keys from a key log) and feeds their payloads here. This module does
not capture keys and does not decrypt traffic.

The transcript hash is accumulated over complete handshake message
encodings (the 4-byte Handshake header included), never over record
payloads: handshake messages may be split across records and several
messages may be packed into a single record. A record boundary is never
treated as a message boundary; a trailing partial message leaves the
builder in a pending state until the rest of the message arrives.

HelloRetryRequest is handled with the message_hash replacement rule from
RFC 8446 section 4.4.1: ClientHello1 is replaced in the transcript by a
synthetic message_hash handshake message carrying Hash(ClientHello1).

Digest checkpoints are exposed for the points right before each
CertificateVerify and each Finished message, which are the values needed
to verify those messages. Main-handshake and post-handshake
authentication (RFC 8446 section 4.6.2) transcripts are kept distinct:
each post-handshake CertificateRequest starts a fresh transcript rooted
at the end of the main handshake. KeyUpdate and NewSessionTicket are
post-handshake messages that do not enter the handshake context used for
CertificateVerify/Finished (see the Handshake Context table in RFC 8446
section 4.4), so they are consumed but never extend the transcript.
"""
from __future__ import absolute_import

import collections
import hashlib
import struct

from . import dpkt
from .compat import compat_ord

# Handshake message types (RFC 8446 section 4)
HELLO_REQUEST = 0
CLIENT_HELLO = 1
SERVER_HELLO = 2
NEW_SESSION_TICKET = 4
END_OF_EARLY_DATA = 5
ENCRYPTED_EXTENSIONS = 8
CERTIFICATE = 11
CERTIFICATE_REQUEST = 13
CERTIFICATE_VERIFY = 15
FINISHED = 20
KEY_UPDATE = 24
MESSAGE_HASH = 254

# Record content type for handshake (RFC 8446 section 5.1)
RECORD_TYPE_HANDSHAKE = 22

# Transcript phases
PHASE_MAIN = 'main'
PHASE_POST_HANDSHAKE = 'post_handshake'

# Checkpoint message names
CERTIFICATE_VERIFY_NAME = 'certificate_verify'
FINISHED_NAME = 'finished'

# Special ServerHello.random value identifying a HelloRetryRequest
# (RFC 8446 section 4.1.3)
HELLO_RETRY_REQUEST_RANDOM = struct.pack(
    '!16H', 0xcf21, 0xad74, 0xe59a, 0x6111, 0xbe1d, 0x8c02, 0x1e65, 0xb891,
    0xc2a2, 0x1116, 0x7abb, 0x8c5e, 0x079e, 0x09e2, 0xc8a8, 0x339c)

# A digest checkpoint captured right before a CertificateVerify or Finished
# message was folded into the transcript.
Checkpoint = collections.namedtuple('Checkpoint', ['phase', 'message', 'digest'])


class TLS13TranscriptError(dpkt.Error):
    pass


def _message_hash_replacement(hash_name, transcript):
    """Build the synthetic message_hash handshake message (RFC 8446 4.4.1)."""
    digest = hashlib.new(hash_name, bytes(transcript)).digest()
    return struct.pack('!B', MESSAGE_HASH) + struct.pack('!I', len(digest))[1:] + digest


class TLS13Transcript(object):
    """Incrementally builds the TLS 1.3 handshake transcript hash.

    Feed plaintext handshake record payloads with feed() (or whole parsed
    records with feed_record()). Bytes of an incomplete trailing handshake
    message are buffered; pending is True while a message is incomplete.
    """

    def __init__(self, hash_name='sha256'):
        # validate the hash early
        hashlib.new(hash_name)
        self.hash_name = hash_name
        self._pending = bytearray()
        # exact handshake message encodings of the main transcript
        self._main = bytearray()
        # active post-handshake authentication transcript, or None
        self._pha = None
        self._phase = PHASE_MAIN
        self._main_finished = 0
        self._hrr_seen = False
        self.key_updates = 0
        self.session_tickets = 0
        self._checkpoints = []

    @property
    def phase(self):
        """PHASE_MAIN until the client Finished, then PHASE_POST_HANDSHAKE."""
        return self._phase

    @property
    def pending(self):
        """True while bytes of an incomplete handshake message are buffered."""
        return len(self._pending) > 0

    @property
    def pending_bytes(self):
        """Number of buffered bytes of the incomplete trailing message."""
        return len(self._pending)

    @property
    def hello_retry_request(self):
        """True once a HelloRetryRequest has been folded into the transcript."""
        return self._hrr_seen

    @property
    def checkpoints(self):
        """All digest checkpoints, in the order the messages completed."""
        return tuple(self._checkpoints)

    def _latest_checkpoint(self, message, phase=PHASE_MAIN):
        for checkpoint in reversed(self._checkpoints):
            if checkpoint.message == message and checkpoint.phase == phase:
                return checkpoint.digest
        return None

    @property
    def certificate_verify_hash(self):
        """Main-handshake transcript digest right before CertificateVerify."""
        return self._latest_checkpoint(CERTIFICATE_VERIFY_NAME)

    @property
    def finished_hash(self):
        """Main-handshake transcript digest right before the latest Finished."""
        return self._latest_checkpoint(FINISHED_NAME)

    def handshake_hash(self):
        """Digest of the main handshake transcript so far."""
        return hashlib.new(self.hash_name, bytes(self._main)).digest()

    def post_handshake_hash(self):
        """Digest of the active post-handshake auth transcript, or None."""
        if self._pha is None:
            return None
        return hashlib.new(self.hash_name, bytes(self._pha)).digest()

    def feed_record(self, record):
        """Feed a parsed plaintext handshake record (e.g. dpkt.ssl.TLSRecord)."""
        if record.type != RECORD_TYPE_HANDSHAKE:
            raise TLS13TranscriptError(
                'expected a handshake record (type %d), got type %d' %
                (RECORD_TYPE_HANDSHAKE, record.type))
        return self.feed(record.data)

    def feed(self, data):
        """Feed plaintext handshake record payload bytes.

        Returns the list of handshake message types completed by this call.
        Incomplete trailing bytes are buffered until more data is fed.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError('feed() expects bytes, got %s' % type(data).__name__)
        self._pending += data
        completed = []
        while len(self._pending) >= 4:
            header = bytes(self._pending[:4])
            length = struct.unpack('!I', b'\x00' + header[1:])[0]
            if len(self._pending) < 4 + length:
                break
            raw = bytes(self._pending[:4 + length])
            del self._pending[:4 + length]
            msg_type = compat_ord(header[0])
            self._process(msg_type, raw)
            completed.append(msg_type)
        return completed

    def _checkpoint(self, message, context):
        digest = hashlib.new(self.hash_name, bytes(context)).digest()
        self._checkpoints.append(Checkpoint(self._phase, message, digest))

    def _process(self, msg_type, raw):
        if msg_type == KEY_UPDATE:
            # KeyUpdate never enters the transcript (RFC 8446 4.4)
            self.key_updates += 1
            return
        if msg_type == NEW_SESSION_TICKET:
            # NewSessionTicket is not part of any CertificateVerify/Finished
            # handshake context (RFC 8446 4.4)
            self.session_tickets += 1
            return
        if msg_type == SERVER_HELLO and len(raw) >= 38 and \
                raw[6:38] == HELLO_RETRY_REQUEST_RANDOM:
            # RFC 8446 4.4.1: replace ClientHello1 with message_hash
            if self._hrr_seen or self._phase != PHASE_MAIN:
                raise TLS13TranscriptError('unexpected HelloRetryRequest')
            self._main = bytearray(
                _message_hash_replacement(self.hash_name, self._main))
            self._hrr_seen = True
            self._main += raw
            return
        if msg_type in (HELLO_REQUEST, MESSAGE_HASH) or msg_type > KEY_UPDATE:
            raise TLS13TranscriptError(
                'unexpected handshake message type %d' % msg_type)
        if self._phase == PHASE_POST_HANDSHAKE:
            self._process_post_handshake(msg_type, raw)
            return
        if msg_type == CERTIFICATE_VERIFY:
            self._checkpoint(CERTIFICATE_VERIFY_NAME, self._main)
        elif msg_type == FINISHED:
            self._checkpoint(FINISHED_NAME, self._main)
            self._main_finished += 1
        self._main += raw
        if self._main_finished == 2:
            # client Finished ends the main handshake
            self._phase = PHASE_POST_HANDSHAKE

    def _process_post_handshake(self, msg_type, raw):
        if msg_type == CERTIFICATE_REQUEST:
            # RFC 8446 4.4: post-handshake auth context is
            # ClientHello ... client Finished + CertificateRequest
            self._pha = bytearray(self._main)
            self._pha += raw
            return
        if self._pha is None:
            raise TLS13TranscriptError(
                'post-handshake message type %d without CertificateRequest' %
                msg_type)
        if msg_type == CERTIFICATE_VERIFY:
            self._checkpoint(CERTIFICATE_VERIFY_NAME, self._pha)
        elif msg_type == FINISHED:
            self._checkpoint(FINISHED_NAME, self._pha)
        elif msg_type != CERTIFICATE:
            raise TLS13TranscriptError(
                'unexpected post-handshake message type %d' % msg_type)
        self._pha += raw


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _hs(msg_type, body):
    """Encode a handshake message: type || uint24 length || body."""
    return struct.pack('!B', msg_type) + struct.pack('!I', len(body))[1:] + body


def _client_hello(tag):
    body = (b'\x03\x03' + tag * 32 +          # legacy_version, random
            b'\x20' + tag * 32 +               # session_id
            b'\x00\x02\x13\x01' +           # cipher_suites
            b'\x01\x00')                      # compression_methods
    return _hs(CLIENT_HELLO, body)


def _server_hello(tag):
    body = (b'\x03\x03' + tag * 32 +          # legacy_version, random
            b'\x20' + tag * 32 +               # session_id_echo
            b'\x13\x01' +                     # cipher_suite
            b'\x00' +                          # compression_method
            b'\x00\x00')                      # extensions
    return _hs(SERVER_HELLO, body)


def _hello_retry_request():
    body = (b'\x03\x03' + HELLO_RETRY_REQUEST_RANDOM +
            b'\x20' + b'\xaa' * 32 +
            b'\x13\x01' + b'\x00' + b'\x00\x00')
    return _hs(SERVER_HELLO, body)


def _encrypted_extensions():
    return _hs(ENCRYPTED_EXTENSIONS, b'\x00\x00')


def _certificate(tag):
    entry = b'\x00\x00\x02' + tag * 2 + b'\x00\x00'  # cert + extensions
    body = b'\x00' + struct.pack('!I', len(entry))[1:] + entry
    return _hs(CERTIFICATE, body)


def _certificate_verify(tag):
    return _hs(CERTIFICATE_VERIFY, b'\x04\x03\x00\x04' + tag * 4)


def _finished(tag):
    return _hs(FINISHED, tag * 32)


def _certificate_request():
    return _hs(CERTIFICATE_REQUEST, b'\x00\x00\x00')


def _new_session_ticket():
    return _hs(NEW_SESSION_TICKET, b'\x00\x00\x00\x2a\x01\x02')


def _key_update(request=False):
    return _hs(KEY_UPDATE, b'\x01' if request else b'\x00')


def _main_handshake_messages():
    return [
        _client_hello(b'\x01'),
        _server_hello(b'\x02'),
        _encrypted_extensions(),
        _certificate(b'\x03'),
        _certificate_verify(b'\x04'),
        _finished(b'\x05'),
        _finished(b'\x06'),
    ]


def _digest(hash_name, *chunks):
    h = hashlib.new(hash_name)
    for chunk in chunks:
        h.update(chunk)
    return h.digest()


class TestTLS13Transcript(object):
    """Full 1-RTT handshake fed as interleaved client/server records, with
    messages split across records and packed several per record."""

    def test_main_handshake_checkpoints(self):
        ch, sh, ee, cert, cv, fin_s, fin_c = _main_handshake_messages()
        t = TLS13Transcript()

        # split ClientHello across two records
        assert t.feed(ch[:7]) == []
        assert t.pending
        assert t.pending_bytes == 7
        # rest of ClientHello packed together with ServerHello
        assert t.feed(ch[7:] + sh) == [CLIENT_HELLO, SERVER_HELLO]
        assert not t.pending
        # EncryptedExtensions plus the start of Certificate
        assert t.feed(ee + cert[:5]) == [ENCRYPTED_EXTENSIONS]
        assert t.pending
        # rest of Certificate plus CertificateVerify
        assert t.feed(cert[5:] + cv) == [CERTIFICATE, CERTIFICATE_VERIFY]
        assert not t.pending
        # both Finished messages in a single record
        assert t.feed(fin_s + fin_c) == [FINISHED, FINISHED]

        # independently generated digests
        assert t.certificate_verify_hash == _digest('sha256', ch, sh, ee, cert)
        assert t.finished_hash == _digest('sha256', ch, sh, ee, cert, cv, fin_s)
        assert t.handshake_hash() == _digest(
            'sha256', ch, sh, ee, cert, cv, fin_s, fin_c)

        checkpoints = t.checkpoints
        assert len(checkpoints) == 3
        assert checkpoints[0] == Checkpoint(
            PHASE_MAIN, CERTIFICATE_VERIFY_NAME,
            _digest('sha256', ch, sh, ee, cert))
        assert checkpoints[1] == Checkpoint(
            PHASE_MAIN, FINISHED_NAME,
            _digest('sha256', ch, sh, ee, cert, cv))
        assert checkpoints[2] == Checkpoint(
            PHASE_MAIN, FINISHED_NAME,
            _digest('sha256', ch, sh, ee, cert, cv, fin_s))

        assert t.phase == PHASE_POST_HANDSHAKE
        assert not t.hello_retry_request
        assert t.post_handshake_hash() is None

    def test_partial_message_stays_pending(self):
        ch = _client_hello(b'\x01')
        t = TLS13Transcript()
        # incomplete header: not even a message boundary can be found
        assert t.feed(ch[:2]) == []
        assert t.pending
        # complete header, incomplete body: still pending, a record
        # boundary must not be mistaken for the end of the message
        assert t.feed(ch[2:10]) == []
        assert t.pending
        assert t.pending_bytes == 10
        # nothing was folded into the transcript yet
        assert t.handshake_hash() == _digest('sha256')
        assert t.feed(ch[10:]) == [CLIENT_HELLO]
        assert not t.pending
        assert t.handshake_hash() == _digest('sha256', ch)

    def test_feed_record(self):
        from . import ssl
        ch = _client_hello(b'\x01')
        record = ssl.TLSRecord(b'\x16\x03\x03' + struct.pack('!H', len(ch)) + ch)
        t = TLS13Transcript()
        assert t.feed_record(record) == [CLIENT_HELLO]
        assert t.handshake_hash() == _digest('sha256', ch)

    def test_feed_record_rejects_non_handshake(self):
        from . import ssl
        record = ssl.TLSRecord(b'\x17\x03\x03\x00\x01\x00')
        t = TLS13Transcript()
        try:
            t.feed_record(record)
            assert False, 'expected TLS13TranscriptError'
        except TLS13TranscriptError:
            pass


class TestTLS13TranscriptHelloRetryRequest(object):
    """Handshake with HelloRetryRequest: ClientHello1 must be replaced by
    message_hash per RFC 8446 section 4.4.1."""

    def _messages(self):
        return [
            _client_hello(b'\x11'),
            _hello_retry_request(),
            _client_hello(b'\x12'),
            _server_hello(b'\x13'),
            _encrypted_extensions(),
            _certificate(b'\x14'),
            _certificate_verify(b'\x15'),
            _finished(b'\x16'),
            _finished(b'\x17'),
        ]

    def _transcript_prefix(self, hash_name, ch1, hrr):
        mh = _digest(hash_name, ch1)
        return struct.pack('!B', MESSAGE_HASH) + \
            struct.pack('!I', len(mh))[1:] + mh + hrr

    def test_hrr_checkpoints(self):
        ch1, hrr, ch2, sh, ee, cert, cv, fin_s, fin_c = self._messages()
        prefix = self._transcript_prefix('sha256', ch1, hrr)
        t = TLS13Transcript()

        assert t.feed(ch1) == [CLIENT_HELLO]
        # split HelloRetryRequest across records
        assert t.feed(hrr[:9]) == []
        assert t.pending
        assert t.feed(hrr[9:] + ch2) == [SERVER_HELLO, CLIENT_HELLO]
        assert t.hello_retry_request
        # after the replacement the transcript is message_hash || HRR || CH2
        assert t.handshake_hash() == _digest('sha256', prefix, ch2)

        assert t.feed(sh + ee + cert) == [
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, CERTIFICATE]
        assert t.feed(cv) == [CERTIFICATE_VERIFY]
        assert t.feed(fin_s + fin_c) == [FINISHED, FINISHED]

        assert t.certificate_verify_hash == _digest(
            'sha256', prefix, ch2, sh, ee, cert)
        assert t.finished_hash == _digest(
            'sha256', prefix, ch2, sh, ee, cert, cv, fin_s)
        assert t.handshake_hash() == _digest(
            'sha256', prefix, ch2, sh, ee, cert, cv, fin_s, fin_c)
        assert len(t.checkpoints) == 3

    def test_hrr_checkpoints_sha384(self):
        ch1, hrr, ch2, sh, ee, cert, cv, fin_s, fin_c = self._messages()
        prefix = self._transcript_prefix('sha384', ch1, hrr)
        t = TLS13Transcript(hash_name='sha384')
        for message in [ch1, hrr, ch2, sh, ee, cert, cv, fin_s, fin_c]:
            t.feed(message)
        assert t.certificate_verify_hash == _digest(
            'sha384', prefix, ch2, sh, ee, cert)
        assert t.finished_hash == _digest(
            'sha384', prefix, ch2, sh, ee, cert, cv, fin_s)
        assert t.handshake_hash() == _digest(
            'sha384', prefix, ch2, sh, ee, cert, cv, fin_s, fin_c)

    def test_second_hrr_rejected(self):
        t = TLS13Transcript()
        t.feed(_client_hello(b'\x11') + _hello_retry_request())
        try:
            t.feed(_hello_retry_request())
            assert False, 'expected TLS13TranscriptError'
        except TLS13TranscriptError:
            pass


class TestTLS13TranscriptPostHandshake(object):
    """KeyUpdate and NewSessionTicket must not affect the transcript;
    post-handshake authentication gets its own transcript rooted at the
    end of the main handshake."""

    def _established(self):
        t = TLS13Transcript()
        messages = _main_handshake_messages()
        for message in messages:
            t.feed(message)
        assert t.phase == PHASE_POST_HANDSHAKE
        return t, b''.join(messages)

    def test_key_update_and_ticket_do_not_extend_transcript(self):
        t, main = self._established()
        main_hash = t.handshake_hash()

        assert t.feed(_new_session_ticket()) == [NEW_SESSION_TICKET]
        assert t.session_tickets == 1
        assert t.handshake_hash() == main_hash

        assert t.feed(_key_update() + _key_update(request=True)) == \
            [KEY_UPDATE, KEY_UPDATE]
        assert t.key_updates == 2
        assert t.handshake_hash() == main_hash
        assert t.post_handshake_hash() is None
        assert len(t.checkpoints) == 3  # only the main-handshake ones

    def test_post_handshake_authentication(self):
        t, main = self._established()
        main_hash = t.handshake_hash()
        main_cv_hash = t.certificate_verify_hash

        cr = _certificate_request()
        cert = _certificate(b'\x21')
        cv = _certificate_verify(b'\x22')
        fin = _finished(b'\x23')

        # interleave a KeyUpdate between CertificateRequest and Certificate
        assert t.feed(cr + _key_update()) == [CERTIFICATE_REQUEST, KEY_UPDATE]
        assert t.feed(cert[:9]) == []
        assert t.pending
        assert t.feed(cert[9:] + cv + fin) == \
            [CERTIFICATE, CERTIFICATE_VERIFY, FINISHED]

        pha_base = main + cr
        checkpoints = t.checkpoints
        assert len(checkpoints) == 5
        assert checkpoints[3] == Checkpoint(
            PHASE_POST_HANDSHAKE, CERTIFICATE_VERIFY_NAME,
            _digest('sha256', pha_base, cert))
        assert checkpoints[4] == Checkpoint(
            PHASE_POST_HANDSHAKE, FINISHED_NAME,
            _digest('sha256', pha_base, cert, cv))
        assert t.post_handshake_hash() == _digest(
            'sha256', pha_base, cert, cv, fin)

        # the main transcript and its checkpoints are untouched
        assert t.handshake_hash() == main_hash
        assert t.certificate_verify_hash == main_cv_hash

    def test_second_post_handshake_authentication_starts_fresh(self):
        t, main = self._established()
        cr1 = _certificate_request()
        t.feed(cr1 + _certificate(b'\x21') +
               _certificate_verify(b'\x22') + _finished(b'\x23'))
        cr2 = _certificate_request()
        cert2 = _certificate(b'\x31')
        cv2 = _certificate_verify(b'\x32')
        fin2 = _finished(b'\x33')
        t.feed(cr2 + cert2 + cv2 + fin2)
        # RFC 8446 4.4: subsequent post-handshake authentications do not
        # include each other, just the messages through the main handshake
        pha_base = main + cr2
        assert t.post_handshake_hash() == _digest(
            'sha256', pha_base, cert2, cv2, fin2)
        assert t.checkpoints[-1] == Checkpoint(
            PHASE_POST_HANDSHAKE, FINISHED_NAME,
            _digest('sha256', pha_base, cert2, cv2))

    def test_post_handshake_certificate_without_request_rejected(self):
        t, _ = self._established()
        try:
            t.feed(_certificate(b'\x21'))
            assert False, 'expected TLS13TranscriptError'
        except TLS13TranscriptError:
            pass


class TestTLS13TranscriptErrors(object):
    def test_unknown_handshake_type(self):
        t = TLS13Transcript()
        try:
            t.feed(_hs(99, b'\x00'))
            assert False, 'expected TLS13TranscriptError'
        except TLS13TranscriptError:
            pass

    def test_feed_rejects_non_bytes(self):
        t = TLS13Transcript()
        try:
            t.feed('not bytes')
            assert False, 'expected TypeError'
        except TypeError:
            pass

    def test_invalid_hash_name(self):
        try:
            TLS13Transcript(hash_name='md0')
            assert False, 'expected ValueError'
        except ValueError:
            pass
