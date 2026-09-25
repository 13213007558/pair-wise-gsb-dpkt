# -*- coding: utf-8 -*-
"""TLS 1.3 (RFC 8446) handshake transcript hash builder.

This module implements the Transcript-Hash construction of RFC 8446,
Section 4.4.1 for offline analysis. The caller feeds the *plaintext*
payloads of handshake records (content type 22) that it has already
obtained; deriving keys or decrypting traffic is explicitly out of
scope.

Handshake messages may be split across record boundaries and several
messages may be coalesced into a single record. The builder therefore
buffers partial data and only folds a message into the running digest
once its complete handshake encoding (4-byte header + body) is
available; a record boundary is never treated as a message boundary.
"""
from __future__ import absolute_import

import hashlib
import struct

from . import dpkt
from .compat import compat_ord

# Handshake message types (RFC 8446, Appendix B.3)
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

# RFC 8446, Section 4.1.3: special ServerHello.random value that
# identifies a HelloRetryRequest.
HELLO_RETRY_REQUEST_RANDOM = (
    b'\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91'
    b'\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c'
)

HANDSHAKE_HEADER_LEN = 4

# Checkpoint names used in TLSTranscriptBuilder.checkpoints
CHECKPOINT_CERTIFICATE_VERIFY = 'certificate_verify'
CHECKPOINT_SERVER_FINISHED = 'server_finished'
CHECKPOINT_CLIENT_FINISHED = 'client_finished'
CHECKPOINT_POST_HANDSHAKE_CERTIFICATE_VERIFY = 'post_handshake_certificate_verify'
CHECKPOINT_POST_HANDSHAKE_FINISHED = 'post_handshake_finished'


def _u24(n):
    """Encode an integer as a uint24 (3 bytes, big-endian)."""
    return struct.pack('!I', n)[1:]


class TLSTranscriptBuilder(object):
    """Incrementally builds the TLS 1.3 handshake transcript hash.

    Feed plaintext handshake record payloads with feed(); complete
    handshake messages are folded into the running digest in order.
    HelloRetryRequest triggers the message_hash replacement rule of
    RFC 8446, Section 4.4.1. Digests sampled immediately before the
    CertificateVerify and Finished messages are exposed as named
    checkpoints, distinguishing the main handshake from post-handshake
    authentication; KeyUpdate messages extend the transcript but are
    accounted for separately.
    """

    MAIN_HANDSHAKE = 'main_handshake'
    POST_HANDSHAKE = 'post_handshake'

    def __init__(self, hash_name='sha256'):
        self.hash_name = hash_name
        self._hash = hashlib.new(hash_name)
        self._buffer = bytearray()
        self._client_hello1 = None
        self.message_count = 0
        self.finished_count = 0
        self.key_update_count = 0
        self.hello_retry_request = False
        self.post_handshake_auth = False
        self.phase = self.MAIN_HANDSHAKE
        self.checkpoints = {}

    @property
    def pending(self):
        """True if an incomplete handshake message is being buffered."""
        return len(self._buffer) > 0

    @property
    def pending_bytes(self):
        """Number of buffered bytes not yet forming a complete message."""
        return len(self._buffer)

    def digest(self):
        """Current transcript hash value."""
        return self._hash.copy().digest()

    def hexdigest(self):
        """Current transcript hash value as a hex string."""
        return self._hash.copy().hexdigest()

    @property
    def certificate_verify_digest(self):
        """Transcript hash immediately before the main-handshake CertificateVerify."""
        return self.checkpoints.get(CHECKPOINT_CERTIFICATE_VERIFY)

    @property
    def server_finished_digest(self):
        """Transcript hash immediately before the server Finished."""
        return self.checkpoints.get(CHECKPOINT_SERVER_FINISHED)

    @property
    def client_finished_digest(self):
        """Transcript hash immediately before the client Finished."""
        return self.checkpoints.get(CHECKPOINT_CLIENT_FINISHED)

    @property
    def post_handshake_certificate_verify_digest(self):
        """Transcript hash immediately before a post-handshake CertificateVerify."""
        return self.checkpoints.get(CHECKPOINT_POST_HANDSHAKE_CERTIFICATE_VERIFY)

    @property
    def post_handshake_finished_digest(self):
        """Transcript hash immediately before a post-handshake Finished."""
        return self.checkpoints.get(CHECKPOINT_POST_HANDSHAKE_FINISHED)

    def feed(self, data):
        """Feed plaintext handshake record payload bytes.

        Returns the list of handshake message types that were completed
        by this call. Bytes belonging to an incomplete trailing message
        remain buffered and do not affect the transcript yet.
        """
        self._buffer += bytes(data)
        completed = []
        while len(self._buffer) >= HANDSHAKE_HEADER_LEN:
            msg_len = struct.unpack('!I', b'\x00' + bytes(self._buffer[1:4]))[0]
            if len(self._buffer) < HANDSHAKE_HEADER_LEN + msg_len:
                break
            msg = bytes(self._buffer[:HANDSHAKE_HEADER_LEN + msg_len])
            del self._buffer[:HANDSHAKE_HEADER_LEN + msg_len]
            self._process_message(msg)
            completed.append(compat_ord(msg[0]))
        return completed

    def feed_record(self, record):
        """Feed a plaintext dpkt.ssl.TLSRecord (content type 22)."""
        if record.type != 22:
            raise ValueError('expected a handshake record (type 22), got %d' % record.type)
        return self.feed(record.data)

    def _process_message(self, msg):
        msg_type = compat_ord(msg[0])
        if msg_type == SERVER_HELLO and self._is_hello_retry_request(msg):
            self._apply_hello_retry_request(msg)
            return
        if msg_type == CERTIFICATE_VERIFY:
            if self.phase == self.MAIN_HANDSHAKE:
                key = CHECKPOINT_CERTIFICATE_VERIFY
            else:
                key = CHECKPOINT_POST_HANDSHAKE_CERTIFICATE_VERIFY
            self.checkpoints[key] = self.digest()
        elif msg_type == FINISHED:
            if self.phase == self.MAIN_HANDSHAKE:
                if self.finished_count == 0:
                    key = CHECKPOINT_SERVER_FINISHED
                else:
                    key = CHECKPOINT_CLIENT_FINISHED
                self.checkpoints[key] = self.digest()
                self.finished_count += 1
                if self.finished_count == 2:
                    self.phase = self.POST_HANDSHAKE
            else:
                self.checkpoints[CHECKPOINT_POST_HANDSHAKE_FINISHED] = self.digest()
        elif msg_type == KEY_UPDATE:
            # KeyUpdate extends the transcript like any other handshake
            # message but creates no checkpoint; count it separately.
            self.key_update_count += 1
        elif msg_type == CERTIFICATE_REQUEST and self.phase == self.POST_HANDSHAKE:
            self.post_handshake_auth = True
        self._hash.update(msg)
        self.message_count += 1
        if self.message_count == 1 and msg_type == CLIENT_HELLO:
            # Retain ClientHello1 until HelloRetryRequest is ruled out.
            self._client_hello1 = msg
        elif self.message_count >= 2:
            self._client_hello1 = None

    @staticmethod
    def _is_hello_retry_request(msg):
        body = msg[HANDSHAKE_HEADER_LEN:]
        return body[2:34] == HELLO_RETRY_REQUEST_RANDOM

    def _apply_hello_retry_request(self, msg):
        if self._client_hello1 is None or self.message_count != 1:
            raise dpkt.Error(
                'HelloRetryRequest without exactly one prior ClientHello')
        # RFC 8446, Section 4.4.1: replace ClientHello1 with
        # message_hash in the transcript.
        message_hash = hashlib.new(self.hash_name, self._client_hello1).digest()
        self._hash = hashlib.new(self.hash_name)
        self._hash.update(struct.pack('!B', MESSAGE_HASH) + _u24(len(message_hash)) + message_hash)
        self._hash.update(msg)
        self.message_count += 1
        self.hello_retry_request = True
        self._client_hello1 = None


def _hs(msg_type, body):
    """Build a complete handshake message encoding (test helper)."""
    return struct.pack('!B', msg_type) + _u24(len(body)) + body


def _server_hello_body(random):
    return b'\x03\x03' + random + b'\x00' + b'\x13\x01' + b'\x00'


# Deterministic sample messages for a full main handshake. Body contents
# are fixed test patterns; only their encodings matter for the transcript.
CH = _hs(CLIENT_HELLO, b'\x03\x03' + b'\x01' * 32 + b'\x00\x00\x02\x13\x01\x01\x00')
SH = _hs(SERVER_HELLO, _server_hello_body(b'\x02' * 32))
EE = _hs(ENCRYPTED_EXTENSIONS, b'\x00\x00')
CERT = _hs(CERTIFICATE, b'\x00' + b'\x00\x00\x11' + b'\x00\x00\x0d' + b'\xaa' * 13)
CV = _hs(CERTIFICATE_VERIFY, b'\x04\x03' + b'\x00\x40' + b'\xbb' * 64)
FIN_S = _hs(FINISHED, b'\xcc' * 32)
FIN_C = _hs(FINISHED, b'\xdd' * 32)
MAIN_TRANSCRIPT = CH + SH + EE + CERT + CV + FIN_S + FIN_C


def test_hrr_random_constant():
    # RFC 8446, Section 4.1.3: the value is SHA-256 of "HelloRetryRequest".
    assert HELLO_RETRY_REQUEST_RANDOM == hashlib.sha256(b'HelloRetryRequest').digest()


def test_main_handshake_checkpoints():
    # Client and server records interleaved, split and coalesced across
    # arbitrary record boundaries.
    tb = TLSTranscriptBuilder()
    assert tb.feed(CH[:7]) == []
    assert tb.pending
    assert tb.feed(CH[7:] + SH + EE[:1]) == [CLIENT_HELLO, SERVER_HELLO]
    assert tb.feed(EE[1:] + CERT + CV[:20]) == [ENCRYPTED_EXTENSIONS, CERTIFICATE]
    assert tb.feed(CV[20:]) == [CERTIFICATE_VERIFY]
    assert tb.feed(FIN_S + FIN_C[:5]) == [FINISHED]
    assert tb.feed(FIN_C[5:]) == [FINISHED]
    assert not tb.pending

    h = hashlib.sha256
    assert tb.certificate_verify_digest == h(CH + SH + EE + CERT).digest()
    assert tb.server_finished_digest == h(CH + SH + EE + CERT + CV).digest()
    assert tb.client_finished_digest == h(CH + SH + EE + CERT + CV + FIN_S).digest()
    assert tb.digest() == h(MAIN_TRANSCRIPT).digest()
    assert tb.hexdigest() == h(MAIN_TRANSCRIPT).hexdigest()
    assert tb.phase == TLSTranscriptBuilder.POST_HANDSHAKE
    assert tb.finished_count == 2
    assert tb.key_update_count == 0
    assert not tb.hello_retry_request
    assert tb.post_handshake_certificate_verify_digest is None
    assert tb.post_handshake_finished_digest is None


def test_hello_retry_request_transcript():
    ch1 = _hs(CLIENT_HELLO, b'\x03\x03' + b'\x0a' * 32 + b'\x00')
    hrr = _hs(SERVER_HELLO, _server_hello_body(HELLO_RETRY_REQUEST_RANDOM))
    ch2 = _hs(CLIENT_HELLO, b'\x03\x03' + b'\x0b' * 32 + b'\x00')
    sh = _hs(SERVER_HELLO, _server_hello_body(b'\x0c' * 32))

    tb = TLSTranscriptBuilder()
    tb.feed(ch1)
    tb.feed(hrr + ch2[:10])
    tb.feed(ch2[10:] + sh + EE + CERT + CV)
    tb.feed(FIN_S + FIN_C)

    assert tb.hello_retry_request
    # RFC 8446, Section 4.4.1: ClientHello1 is replaced by message_hash.
    h = hashlib.sha256
    message_hash = _hs(MESSAGE_HASH, h(ch1).digest())
    prefix = message_hash + hrr
    transcript = prefix + ch2 + sh + EE + CERT + CV + FIN_S + FIN_C
    assert tb.certificate_verify_digest == h(prefix + ch2 + sh + EE + CERT).digest()
    assert tb.server_finished_digest == h(prefix + ch2 + sh + EE + CERT + CV).digest()
    assert tb.client_finished_digest == h(prefix + ch2 + sh + EE + CERT + CV + FIN_S).digest()
    assert tb.digest() == h(transcript).digest()


def test_hello_retry_request_without_client_hello():
    import pytest
    tb = TLSTranscriptBuilder()
    hrr = _hs(SERVER_HELLO, _server_hello_body(HELLO_RETRY_REQUEST_RANDOM))
    with pytest.raises(dpkt.Error):
        tb.feed(hrr)


def test_post_handshake_auth_and_key_update():
    nst = _hs(NEW_SESSION_TICKET, b'\xee' * 10)
    ku = _hs(KEY_UPDATE, b'\x01')
    cr = _hs(CERTIFICATE_REQUEST, b'\x00\x00')
    cert2 = _hs(CERTIFICATE, b'\x00' + b'\x00\x00\x05' + b'\x00\x00\x01' + b'\x99')
    cv2 = _hs(CERTIFICATE_VERIFY, b'\x08\x04' + b'\x00\x20' + b'\xf1' * 32)
    fin_ph = _hs(FINISHED, b'\xf2' * 32)

    tb = TLSTranscriptBuilder()
    tb.feed(MAIN_TRANSCRIPT)
    assert tb.phase == TLSTranscriptBuilder.POST_HANDSHAKE
    digest_before_nst = tb.digest()

    tb.feed(nst + ku[:2])
    assert tb.pending  # KeyUpdate split across records
    tb.feed(ku[2:] + cr)
    assert tb.key_update_count == 1
    assert tb.post_handshake_auth
    # KeyUpdate extends the transcript like any other handshake message.
    h = hashlib.sha256
    assert tb.digest() == h(MAIN_TRANSCRIPT + nst + ku + cr).digest()
    assert tb.digest() != digest_before_nst

    tb.feed(cert2)
    tb.feed(cv2[:15])
    tb.feed(cv2[15:] + fin_ph)

    base = MAIN_TRANSCRIPT + nst + ku + cr
    assert tb.post_handshake_certificate_verify_digest == h(base + cert2).digest()
    assert tb.post_handshake_finished_digest == h(base + cert2 + cv2).digest()
    assert tb.digest() == h(base + cert2 + cv2 + fin_ph).digest()
    # Main-handshake checkpoints are untouched by post-handshake auth.
    assert tb.certificate_verify_digest == h(CH + SH + EE + CERT).digest()
    assert tb.client_finished_digest == h(CH + SH + EE + CERT + CV + FIN_S).digest()


def test_partial_message_stays_pending():
    tb = TLSTranscriptBuilder()
    # Feed a record that ends in the middle of the Certificate header.
    first = CH + SH + EE + CERT[:2]
    assert tb.feed(first) == [CLIENT_HELLO, SERVER_HELLO, ENCRYPTED_EXTENSIONS]
    assert tb.pending
    assert tb.pending_bytes == 2
    # The incomplete message must not affect the transcript.
    assert tb.digest() == hashlib.sha256(CH + SH + EE).digest()
    assert tb.certificate_verify_digest is None

    # Feed the rest of the header plus part of the body: still pending.
    assert tb.feed(CERT[2:10]) == []
    assert tb.pending
    assert tb.digest() == hashlib.sha256(CH + SH + EE).digest()

    # Completing the message folds exactly its full encoding into the hash.
    assert tb.feed(CERT[10:]) == [CERTIFICATE]
    assert not tb.pending
    assert tb.digest() == hashlib.sha256(CH + SH + EE + CERT).digest()


def test_sha384_hash_name():
    tb = TLSTranscriptBuilder(hash_name='sha384')
    tb.feed(MAIN_TRANSCRIPT)
    h = hashlib.sha384
    assert tb.certificate_verify_digest == h(CH + SH + EE + CERT).digest()
    assert tb.digest() == h(MAIN_TRANSCRIPT).digest()


def test_feed_record():
    import pytest
    from . import ssl

    tb = TLSTranscriptBuilder()
    record = ssl.TLSRecord(type=22, version=0x0303, data=CH)
    assert tb.feed_record(record) == [CLIENT_HELLO]
    assert tb.digest() == hashlib.sha256(CH).digest()

    alert = ssl.TLSRecord(type=21, version=0x0303, data=b'\x02\x28')
    with pytest.raises(ValueError):
        tb.feed_record(alert)
