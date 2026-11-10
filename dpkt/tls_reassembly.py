# -*- coding: utf-8 -*-
"""Incremental reassembly of TLS records and handshake messages from a byte stream.

The :class:`TLSHandshakeAssembler` in this module solves the two-layer framing
problem that a passive analyzer hits when feeding it raw TLS bytes one chunk at
a time:

* a TLS record (5-byte header + payload) may arrive split across several feeds;
* a handshake message (4-byte header + body) may be spread across several
  records;
* a single record may contain several handshake messages.

Scope and non-goals
-------------------
The input is assumed to be the bytes of **one direction** of one connection,
already reassembled and in order by the transport layer.  This module
intentionally does **not** handle:

* TCP retransmission (duplicate bytes) or TCP-level segmentation bookkeeping;
* out-of-order delivery;
* concatenating the two directions of a connection -- instantiate one
  assembler per direction;
* decryption.  Once the stream becomes opaque (ChangeCipherSpec, application
  data, an explicit :meth:`TLSHandshakeAssembler.mark_encrypted` call, or a
  record whose payload cannot be a plaintext handshake), the assembler stops
  interpreting bytes and reports the encrypted state instead of guessing.
  In particular, TLS 1.3 post-ServerHello handshake records are encrypted and
  are never parsed as plaintext handshakes.
"""
from __future__ import absolute_import

import struct

from . import dpkt
from . import ssl as _ssl

# Record content types (RFC 5246 6.2.1 / RFC 8446 5.1)
RECORD_CHANGE_CIPHER_SPEC = 20
RECORD_ALERT = 21
RECORD_HANDSHAKE = 22
RECORD_APPLICATION_DATA = 23

RECORD_HEADER_LEN = 5
HANDSHAKE_HEADER_LEN = 4

# RFC 5246 6.2.1: record-layer payloads MUST NOT exceed 2^14 bytes.
MAX_RECORD_PAYLOAD = 2 ** 14

# Legal record-layer "legacy_version" values on the wire.
_RECORD_VERSIONS = set((
    _ssl.SSL3_V, _ssl.TLS1_V, _ssl.TLS11_V, _ssl.TLS12_V,
))

# Assembler states
STATE_PLAINTEXT = 'plaintext'
STATE_ENCRYPTED = 'encrypted'
STATE_ERROR = 'error'

# Default safety limits.  A handshake body is a 24-bit length, so the hard
# protocol ceiling is 2^24 - 1; these defaults fail long before that.
DEFAULT_MAX_MESSAGE_SIZE = 2 ** 20      # 1 MiB per handshake message
DEFAULT_MAX_BUFFER_SIZE = 4 * 2 ** 20   # 4 MiB of retained bytes overall


class TLSReassemblyError(Exception):
    """Base class for every error raised by this module."""


class MalformedRecordError(TLSReassemblyError):
    """A record header violates the TLS framing rules."""


class MessageLimitExceeded(TLSReassemblyError):
    """A handshake message declares or reaches a body larger than the limit."""


class BufferLimitExceeded(TLSReassemblyError):
    """The assembler was asked to retain more bytes than the buffer limit."""


class TruncatedStreamError(TLSReassemblyError):
    """The stream ended in the middle of a record or handshake message."""


class HandshakeMessage(object):
    """One fully reassembled TLS handshake message.

    Attributes:
        type (int): handshake type byte (RFC 5246 7.4, e.g. 1 ClientHello,
            11 Certificate).
        raw (bytes): the complete on-the-wire message, including the 4-byte
            handshake header.
        body (bytes): the message body without its 4-byte header.
        parsed: the corresponding dpkt object from
            :data:`dpkt.ssl.HANDSHAKE_TYPES` (e.g. :class:`dpkt.ssl.TLSClientHello`)
            when the type is known, otherwise ``None``.
    """

    __slots__ = ('type', 'raw', 'body', 'parsed')

    def __init__(self, msg_type, raw, body, parsed):
        self.type = msg_type
        self.raw = raw
        self.body = body
        self.parsed = parsed

    @property
    def type_name(self):
        """Human-readable handshake type name, or ``'Unknown'``."""
        entry = _ssl.HANDSHAKE_TYPES.get(self.type)
        return entry[0] if entry is not None else 'Unknown'

    def __repr__(self):
        return 'HandshakeMessage(type=%d %s, %d bytes)' % (
            self.type, self.type_name, len(self.raw))

    def __eq__(self, other):
        if not isinstance(other, HandshakeMessage):
            return NotImplemented
        return self.raw == other.raw

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.type, self.raw))


class AlertEvent(object):
    """A plaintext TLS alert record (RFC 5246 7.2)."""

    __slots__ = ('level', 'description', 'raw')

    def __init__(self, raw):
        self.raw = raw
        if len(raw) >= 2:
            self.level = raw[0]
            self.description = raw[1]
        else:
            self.level = None
            self.description = None

    def __repr__(self):
        return 'AlertEvent(level=%r, description=%r)' % (
            self.level, self.description)


class ChangeCipherSpecEvent(object):
    """A ChangeCipherSpec record; everything after it is encrypted."""

    __slots__ = ('raw',)

    def __init__(self, raw):
        self.raw = raw

    def __repr__(self):
        return 'ChangeCipherSpecEvent()'


class EncryptedRecordEvent(object):
    """An opaque record that the assembler deliberately does not decrypt.

    Attributes:
        record_type (int): the record content type seen on the wire.  TLS 1.3
            sends most encrypted traffic as application-data records (23),
            while middlebox-compatible handshakes may still use type 22.
    """

    __slots__ = ('record_type', 'length')

    def __init__(self, record_type, length):
        self.record_type = record_type
        self.length = length

    def __repr__(self):
        return 'EncryptedRecordEvent(record_type=%d, length=%d)' % (
            self.record_type, self.length)


class TLSHandshakeAssembler(object):
    """Incrementally reassemble TLS records and handshake messages.

    Construct one assembler per direction of a connection and call
    :meth:`feed` with each ordered chunk of TCP payload.  Every call returns
    the list of events that the chunk completed, possibly empty.  Events are
    emitted in stream order across calls.

    Args:
        max_message_size (int): maximum accepted handshake body in bytes.
            A message whose 24-bit length exceeds this, or whose reassembly
            reaches it, raises :class:`MessageLimitExceeded`.
        max_buffer_size (int): maximum total bytes the assembler may retain
            across an incomplete record and an incomplete handshake message.
            Exceeding it raises :class:`BufferLimitExceeded`.

    Once :attr:`state` becomes :data:`STATE_ENCRYPTED`, further plaintext
    parsing stops; later feeds only count encrypted bytes and return
    :class:`EncryptedRecordEvent` objects.  After :data:`STATE_ERROR` the
    assembler is unusable and every feed raises.
    """

    def __init__(self, max_message_size=DEFAULT_MAX_MESSAGE_SIZE,
                 max_buffer_size=DEFAULT_MAX_BUFFER_SIZE):
        if max_message_size <= 0 or max_buffer_size <= 0:
            raise ValueError('limits must be positive integers')
        if max_message_size > max_buffer_size:
            raise ValueError(
                'max_message_size (%d) cannot exceed max_buffer_size (%d)'
                % (max_message_size, max_buffer_size))
        self.max_message_size = max_message_size
        self.max_buffer_size = max_buffer_size

        self.state = STATE_PLAINTEXT
        self._record_buf = bytearray()   # bytes waiting for record framing
        self._handshake_buf = bytearray()  # handshake bytes across records
        self.encrypted_bytes = 0         # opaque bytes observed post-encryption
        self.records_seen = 0
        self.messages_seen = 0

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def feed(self, data):
        """Consume one ordered chunk of TLS bytes.

        Args:
            data (bytes): the next chunk of the reassembled stream.

        Returns:
            list: zero or more of :class:`HandshakeMessage`,
            :class:`AlertEvent`, :class:`ChangeCipherSpecEvent` and
            :class:`EncryptedRecordEvent`, in stream order.

        Raises:
            MalformedRecordError, MessageLimitExceeded,
            BufferLimitExceeded, TruncatedStreamError on protocol or limit
            violations.  After any exception the assembler state is
            :data:`STATE_ERROR`.
        """
        if self.state == STATE_ERROR:
            raise TLSReassemblyError('assembler is in an error state')
        if not data:
            return []
        try:
            if self.state == STATE_ENCRYPTED:
                return self._feed_encrypted(data)
            return self._feed_plaintext(data)
        except TLSReassemblyError:
            self.state = STATE_ERROR
            raise

    def finish(self):
        """Signal end of stream and check for an unfinished frame.

        Returns:
            list: always empty; retained for symmetry / future use.

        Raises:
            TruncatedStreamError if bytes of a record or handshake message are
            still pending when the plaintext stream ends.  An encrypted stream
            may simply stop, so pending ciphertext is not an error.
        """
        if self.state == STATE_ERROR:
            raise TLSReassemblyError('assembler is in an error state')
        if self.state == STATE_ENCRYPTED:
            return []
        if self._record_buf or self._handshake_buf:
            self.state = STATE_ERROR
            raise TruncatedStreamError(
                'stream ended with %d record and %d handshake bytes pending'
                % (len(self._record_buf), len(self._handshake_buf)))
        return []

    def mark_encrypted(self):
        """Manually mark the stream as encrypted.

        A passive analyzer that tracks the TLS 1.3 ServerHello can use this to
        tell the assembler that subsequent handshake-type records carry
        ciphertext, so they are never misread as plaintext handshakes.
        Pending plaintext buffers must be empty (call :meth:`finish` logic via
        normal feeds first); retained bytes are discarded.
        """
        if self.state == STATE_ERROR:
            raise TLSReassemblyError('assembler is in an error state')
        if self.state == STATE_ENCRYPTED:
            return
        if self._record_buf or self._handshake_buf:
            self.state = STATE_ERROR
            raise TruncatedStreamError(
                'cannot enter encrypted state with %d record and %d handshake '
                'bytes pending'
                % (len(self._record_buf), len(self._handshake_buf)))
        self.state = STATE_ENCRYPTED

    # ------------------------------------------------------------------ #
    # Internal: record framing
    # ------------------------------------------------------------------ #
    def _retain(self, extra):
        if len(self._record_buf) + len(self._handshake_buf) + extra \
                > self.max_buffer_size:
            raise BufferLimitExceeded(
                'buffer limit of %d bytes exceeded' % self.max_buffer_size)

    def _feed_encrypted(self, data):
        # Opaque bytes are never retained or interpreted; just count them and
        # report whole records when their framing happens to be available.
        self.encrypted_bytes += len(data)
        self._record_buf += data
        events = []
        buf = self._record_buf
        while len(buf) >= RECORD_HEADER_LEN:
            length = struct.unpack('!H', bytes(buf[3:5]))[0]
            if len(buf) < RECORD_HEADER_LEN + length:
                break
            rec_type = buf[0]
            del buf[:RECORD_HEADER_LEN + length]
            self.records_seen += 1
            events.append(EncryptedRecordEvent(rec_type, length))
        # Ciphertext pending at a feed boundary is normal; cap it anyway so a
        # dead peer cannot grow the buffer without limit.
        if len(buf) > self.max_buffer_size:
            self.state = STATE_ERROR
            raise BufferLimitExceeded(
                'buffer limit of %d bytes exceeded' % self.max_buffer_size)
        return events

    def _feed_plaintext(self, data):
        self._retain(len(data))
        self._record_buf += data
        events = []
        buf = self._record_buf
        while len(buf) >= RECORD_HEADER_LEN:
            rec_type = buf[0]
            version = struct.unpack('!H', bytes(buf[1:3]))[0]
            length = struct.unpack('!H', bytes(buf[3:5]))[0]
            if version not in _RECORD_VERSIONS:
                raise MalformedRecordError(
                    'bad record layer version 0x%04x' % version)
            if length > MAX_RECORD_PAYLOAD:
                raise MalformedRecordError(
                    'record payload %d exceeds TLS limit of %d'
                    % (length, MAX_RECORD_PAYLOAD))
            if len(buf) < RECORD_HEADER_LEN + length:
                break  # rest of the record arrives in a later feed
            payload = bytes(buf[RECORD_HEADER_LEN:
                                RECORD_HEADER_LEN + length])
            del buf[:RECORD_HEADER_LEN + length]
            self.records_seen += 1
            events.extend(self._handle_record(rec_type, payload))
            if self.state != STATE_PLAINTEXT:
                # Anything already buffered after the encryption boundary is
                # ciphertext: stop framing it as plaintext.
                if buf:
                    self.encrypted_bytes += len(buf)
                    del buf[:]
                break
        return events

    # ------------------------------------------------------------------ #
    # Internal: per-record content handling
    # ------------------------------------------------------------------ #
    def _handle_record(self, rec_type, payload):
        if rec_type == RECORD_HANDSHAKE:
            return self._handle_handshake_payload(payload)
        if rec_type == RECORD_CHANGE_CIPHER_SPEC:
            events = [ChangeCipherSpecEvent(payload)]
            self._enter_encrypted()
            return events
        if rec_type == RECORD_APPLICATION_DATA:
            events = [EncryptedRecordEvent(rec_type, len(payload))]
            self._enter_encrypted()
            return events
        if rec_type == RECORD_ALERT:
            return [AlertEvent(payload)]
        raise MalformedRecordError('unknown record content type %d' % rec_type)

    def _enter_encrypted(self):
        # A handshake message must not straddle the encryption boundary.
        if self._handshake_buf:
            raise MalformedRecordError(
                'encryption started in the middle of a handshake message')
        self.state = STATE_ENCRYPTED

    # ------------------------------------------------------------------ #
    # Internal: handshake message framing across records
    # ------------------------------------------------------------------ #
    def _handle_handshake_payload(self, payload):
        self._retain(len(payload))
        self._handshake_buf += payload
        events = []
        buf = self._handshake_buf
        while len(buf) >= HANDSHAKE_HEADER_LEN:
            msg_type = buf[0]
            body_len = struct.unpack('!I', b'\x00' + bytes(buf[1:4]))[0]
            if body_len > self.max_message_size:
                raise MessageLimitExceeded(
                    'handshake message length %d exceeds limit of %d'
                    % (body_len, self.max_message_size))
            total_len = HANDSHAKE_HEADER_LEN + body_len
            if len(buf) < total_len:
                if len(buf) > self.max_buffer_size:
                    raise BufferLimitExceeded(
                        'buffer limit of %d bytes exceeded'
                        % self.max_buffer_size)
                break
            raw = bytes(buf[:total_len])
            del buf[:total_len]
            if msg_type not in _ssl.HANDSHAKE_TYPES:
                # Every plaintext handshake type is assigned in the RFCs.
                # An unknown type byte means these bytes are not a plaintext
                # handshake at all: treat them as opaque rather than guessing.
                self.encrypted_bytes += len(raw)
                self.state = STATE_ENCRYPTED
                events.append(EncryptedRecordEvent(RECORD_HANDSHAKE, len(raw)))
                # Any remaining bytes in this record are ciphertext too.
                if buf:
                    self.encrypted_bytes += len(buf)
                    del buf[:]
                return events
            parsed = None
            try:
                parsed = _ssl.HANDSHAKE_TYPES[msg_type][1](raw[HANDSHAKE_HEADER_LEN:])
            except (dpkt.NeedData, _ssl.SSL3Exception, struct.error):
                # Framing said the body was complete, so a failure here is a
                # malformed inner encoding.  The raw message is still emitted.
                parsed = None
            self.messages_seen += 1
            events.append(HandshakeMessage(
                msg_type, raw, raw[HANDSHAKE_HEADER_LEN:], parsed))
        return events
