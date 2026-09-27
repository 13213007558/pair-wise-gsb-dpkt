# -*- coding: utf-8 -*-
"""Incremental IPv4 fragment reassembly.

Feed captured IPv4 packets one at a time to IPv4Defragmenter.  Fragments
sharing the same (src, dst, protocol, id) tuple are kept in a per-datagram
buffer until all pieces have arrived, at which point the reassembled
datagram is returned with its transport header (e.g. UDP) decoded.

The reassembler is purely passive: expiration is driven by timestamps passed
in by the caller ('now'), there are no background threads, and incomplete
datagrams are never zero-padded and handed to the application.
"""
from __future__ import absolute_import

import time

from .ip import IP, IP_LEN_MAX

# Status values carried by ReassemblyResult.
COMPLETE = 'complete'      # fully reassembled; 'datagram' is an IP object
INCOMPLETE = 'incomplete'  # still missing pieces; see 'holes'/'reason'
CONFLICT = 'conflict'      # overlapping fragments disagree; datagram dropped
INVALID = 'invalid'        # fragment violates IPv4 fragmentation rules
EXPIRED = 'expired'        # incomplete datagram reaped by expire()


class ReassemblyResult(object):
    """Outcome of feeding a single fragment (or of an expiration sweep).

    Attributes:
        status: One of COMPLETE, INCOMPLETE, CONFLICT, INVALID or EXPIRED.
        key: The (src, dst, protocol, id) tuple the fragments belong to.
        datagram: The reassembled dpkt.ip.IP when status is COMPLETE,
            otherwise None.  Incomplete data is never zero-filled.
        reason: Human readable explanation of a non-complete status.
        holes: Sorted list of (start, end) byte ranges that have not been
            received yet.
        conflicts: Sorted list of (start, end) byte ranges where overlapping
            fragments carried different data.
    """

    def __init__(self, status, key=None, datagram=None, reason='',
                 holes=None, conflicts=None):
        self.status = status
        self.key = key
        self.datagram = datagram
        self.reason = reason
        self.holes = holes if holes is not None else []
        self.conflicts = conflicts if conflicts is not None else []

    def __bool__(self):
        return self.status == COMPLETE

    __nonzero__ = __bool__

    def __repr__(self):
        return ('ReassemblyResult(%s, key=%r, reason=%r, holes=%r, '
                'conflicts=%r)' % (self.status, self.key, self.reason,
                                   self.holes, self.conflicts))


class _PendingDatagram(object):
    """Fragments collected for a single (src, dst, p, id) tuple."""

    __slots__ = ('key', 'created', 'updated', 'first', 'total_len',
                 'segments', 'conflicts')

    def __init__(self, key, now):
        self.key = key
        self.created = now
        self.updated = now
        self.first = None       # offset-0 fragment, owns header and options
        self.total_len = None   # payload length once the last fragment is seen
        # Non-overlapping, sorted list of (start, end, bytes).
        self.segments = []
        self.conflicts = []

    def holes(self):
        out = []
        cursor = 0
        for seg_start, seg_end, _ in self.segments:
            if seg_start > cursor:
                out.append((cursor, seg_start))
            cursor = max(cursor, seg_end)
        if self.total_len is None:
            # The terminal fragment (and hence the true total length) has not
            # arrived; the open-ended tail is (cursor, None).
            out.append((cursor, None))
            return out
        if cursor < self.total_len:
            out.append((cursor, self.total_len))
        return out

    def is_complete(self):
        if self.first is None or self.total_len is None:
            return False
        return not self.holes()

    def describe(self):
        parts = []
        if self.first is None:
            parts.append('first fragment not received')
        holes = self.holes()
        if holes:
            rendered = ['%d..%s' % (s, '?' if e is None else e) for s, e in holes]
            parts.append('missing byte range(s) %s' % rendered)
        if self.total_len is None:
            parts.append('last fragment not received')
        return '; '.join(parts) if parts else 'complete'


class IPv4Defragmenter(object):
    """Incremental, caller-time-driven IPv4 fragment reassembler.

    Args:
        timeout: Seconds since the first fragment after which an incomplete
            datagram is eligible for expiration.
        overlap_policy: How to handle overlapping fragments whose shared
            bytes differ.  Identical retransmissions always merge silently.

            * OVERLAP_REJECT (default): drop the whole datagram and report
              CONFLICT.
            * OVERLAP_FIRST: keep the bytes that arrived first.
            * OVERLAP_LAST: let the newly received bytes win.
    """

    OVERLAP_REJECT = 'reject'
    OVERLAP_FIRST = 'first'
    OVERLAP_LAST = 'last'
    _COMPLETED_CACHE_MAX = 64

    def __init__(self, timeout=30.0, overlap_policy=OVERLAP_REJECT):
        if overlap_policy not in (self.OVERLAP_REJECT, self.OVERLAP_FIRST,
                                  self.OVERLAP_LAST):
            raise ValueError('unknown overlap policy: %r' % (overlap_policy,))
        if timeout < 0:
            raise ValueError('timeout must be non-negative')
        self.timeout = timeout
        self.overlap_policy = overlap_policy
        self._pending = {}
        # key -> recently reassembled datagram, used to recognize late
        # retransmissions of an already completed datagram.
        self._completed = {}

    def __len__(self):
        """Number of partially reassembled datagrams currently buffered."""
        return len(self._pending)

    @property
    def pending(self):
        """Keys of the datagrams for which fragments are still buffered."""
        return list(self._pending.keys())

    def feed(self, pkt, now=None):
        """Feed one captured IPv4 packet.

        Args:
            pkt: A dpkt.ip.IP object.
            now: Caller supplied capture timestamp in seconds.  When given,
                stale datagrams are reaped first, just like an explicit
                expire() call.

        Returns:
            ReassemblyResult
        """
        if not isinstance(pkt, IP):
            raise TypeError('expected dpkt.ip.IP, got %r' % (type(pkt),))
        if now is None:
            now = time.time()
        self.expire(now)

        mf = bool(pkt.mf)
        offset = pkt.offset
        start = offset << 3
        payload = bytes(pkt.data)
        end = start + len(payload)

        # An unfragmented datagram is complete by itself and is not buffered.
        if not mf and offset == 0:
            return ReassemblyResult(
                COMPLETE, key=(pkt.src, pkt.dst, pkt.p, pkt.id),
                datagram=pkt)

        key = (pkt.src, pkt.dst, pkt.p, pkt.id)
        cached = self._completed.get(key)
        if cached is not None:
            return self._feed_completed(cached, key, start, end, payload, mf)
        invalid = self._validate(pkt, start, end, len(payload), mf)
        if invalid is not None:
            return ReassemblyResult(INVALID, key=key, reason=invalid)

        dgram = self._pending.get(key)
        if dgram is None:
            dgram = _PendingDatagram(key, now)
            self._pending[key] = dgram
        dgram.updated = now

        if not mf:
            # The terminal fragment fixes the total payload length.
            if dgram.total_len is not None and dgram.total_len != end:
                reason = ('last fragment declares total payload length %d, '
                          'expected %d' % (end, dgram.total_len))
                conflicts = sorted(set(dgram.conflicts))
                del self._pending[key]
                return ReassemblyResult(CONFLICT, key=key, reason=reason,
                                        conflicts=conflicts)
            dgram.total_len = end

        if offset == 0 and dgram.first is None:
            dgram.first = pkt

        if not self._merge(dgram, start, end, payload):
            conflicts = sorted(set(dgram.conflicts))
            del self._pending[key]
            return ReassemblyResult(
                CONFLICT, key=key,
                reason='overlapping fragments disagree on byte range(s) %s'
                       % conflicts,
                conflicts=conflicts)

        if dgram.is_complete():
            datagram = self._assemble(dgram)
            self._remember_completed(dgram, datagram, now)
            conflicts = sorted(set(dgram.conflicts))
            del self._pending[key]
            return ReassemblyResult(COMPLETE, key=key, datagram=datagram,
                                    conflicts=conflicts)

        return ReassemblyResult(
            INCOMPLETE, key=key, reason=dgram.describe(),
            holes=dgram.holes(), conflicts=sorted(set(dgram.conflicts)))

    def expire(self, now=None):
        """Reap incomplete datagrams older than 'timeout' at time 'now'.

        Returns a list of ReassemblyResult instances with status EXPIRED and
        a description of what was still missing.
        """
        if now is None:
            now = time.time()
        expired = []
        for key in list(self._pending.keys()):
            dgram = self._pending[key]
            if now - dgram.created >= self.timeout:
                expired.append(ReassemblyResult(
                    EXPIRED, key=key,
                    reason='timed out after %ss; %s'
                           % (self.timeout, dgram.describe()),
                    holes=dgram.holes(),
                    conflicts=sorted(set(dgram.conflicts))))
                del self._pending[key]
        for key in list(self._completed.keys()):
            if self._completed[key]['expires'] <= now:
                del self._completed[key]
        return expired

    def _remember_completed(self, dgram, datagram, now):
        self._completed[dgram.key] = {
            'expires': now + self.timeout,
            'total_len': dgram.total_len,
            'payload': bytes(datagram.data),
            'datagram': datagram}
        if len(self._completed) > self._COMPLETED_CACHE_MAX:
            oldest = min(self._completed,
                         key=lambda k: self._completed[k]['expires'])
            del self._completed[oldest]

    def _feed_completed(self, cached, key, start, end, payload, mf):
        total_len = cached['total_len']
        if (not mf and end != total_len) or end > total_len:
            return ReassemblyResult(
                CONFLICT, key=key,
                reason='fragment of completed datagram contradicts total '
                       'length %d' % total_len)
        if payload == cached['payload'][start:end]:
            # Identical late retransmission; surface the same datagram once.
            return ReassemblyResult(COMPLETE, key=key,
                                    datagram=cached['datagram'])
        conflicts = []
        old = cached['payload'][start:end]
        for idx, (a, b) in enumerate(zip(payload, old)):
            if a != b:
                pos = start + idx
                if conflicts and conflicts[-1][1] == pos:
                    conflicts[-1] = (conflicts[-1][0], pos + 1)
                else:
                    conflicts.append((pos, pos + 1))
        return ReassemblyResult(
            CONFLICT, key=key,
            reason='retransmitted fragment disagrees with reassembled '
                   'datagram over byte range(s) %s' % conflicts,
            conflicts=conflicts)

    @staticmethod
    def _validate(pkt, start, end, payload_len, mf):
        # RFC 791: every fragment but the last must carry a non-zero,
        # 8-byte-aligned payload.
        if mf and payload_len == 0:
            return 'non-final fragment has empty payload'
        if mf and payload_len & 0x7:
            return ('non-final fragment payload length %d is not a multiple '
                    'of 8 bytes' % payload_len)
        if end > IP_LEN_MAX:
            return ('fragment ends at %d, past IPv4 total length limit %d'
                    % (end, IP_LEN_MAX))
        hdr_len = pkt.hl << 2
        if hdr_len < 20 or hdr_len > 60:
            return 'invalid IPv4 header length %d' % hdr_len
        if len(pkt.opts) != hdr_len - 20:
            return ('option length %d disagrees with IHL %d'
                    % (len(pkt.opts), hdr_len))
        return None

    def _merge(self, dgram, start, end, payload):
        """Merge (start, end, payload) into dgram.segments.

        Returns False when a disagreeing overlap must reject the datagram.
        Byte-identical overlaps (plain retransmissions) merge silently.
        """
        policy = self.overlap_policy
        out = []
        cur_start, cur_end, cur_data = start, end, payload
        placed = False
        for seg_start, seg_end, seg_data in dgram.segments:
            if seg_end <= cur_start:
                out.append((seg_start, seg_end, seg_data))
            elif cur_end <= seg_start:
                if not placed:
                    out.append((cur_start, cur_end, cur_data))
                    placed = True
                out.append((seg_start, seg_end, seg_data))
            else:
                ov_start = max(seg_start, cur_start)
                ov_end = min(seg_end, cur_end)
                old = seg_data[ov_start - seg_start:ov_end - seg_start]
                new = cur_data[ov_start - cur_start:ov_end - cur_start]
                if old != new:
                    dgram.conflicts.append((ov_start, ov_end))
                    if policy == self.OVERLAP_REJECT:
                        return False
                merged_start = min(seg_start, cur_start)
                merged_end = max(seg_end, cur_end)
                merged = bytearray(merged_end - merged_start)
                merged[seg_start - merged_start:
                       seg_end - merged_start] = seg_data
                if policy == self.OVERLAP_LAST:
                    merged[cur_start - merged_start:
                           cur_end - merged_start] = cur_data
                else:
                    # OVERLAP_FIRST: overwrite only previously uncovered bytes.
                    if cur_start < seg_start:
                        merged[cur_start - merged_start:
                               seg_start - merged_start] = \
                            cur_data[:seg_start - cur_start]
                    if cur_end > seg_end:
                        merged[seg_end - merged_start:
                               cur_end - merged_start] = \
                            cur_data[seg_end - cur_start:]
                cur_start, cur_end, cur_data = (
                    merged_start, merged_end, bytes(merged))
        if not placed:
            out.append((cur_start, cur_end, cur_data))
        dgram.segments = out
        return True

    def _assemble(self, dgram):
        """Rebuild a full datagram; the first fragment owns header/options."""
        first = dgram.first
        payload = bytearray(dgram.total_len)
        for seg_start, seg_end, seg_data in dgram.segments:
            payload[seg_start:seg_end] = seg_data

        rebuilt = IP(
            src=first.src, dst=first.dst, p=first.p, id=first.id,
            tos=first.tos, ttl=first.ttl, data=bytes(payload))
        rebuilt.hl = first.hl
        rebuilt.opts = bytes(first.opts)
        rebuilt.rf = first.rf
        rebuilt.df = first.df
        rebuilt.mf = 0
        rebuilt.offset = 0
        raw = bytes(rebuilt)  # fixes total length and header checksum
        # Re-parse so the transport header in the first fragment is decoded
        # (e.g. result.udp / result.udp.data).
        return IP(raw)


import pytest

SRC = b'\x0a\x00\x00\x01'
DST = b'\x0a\x00\x00\x02'


def _udp_wire(payload, sport, dport):
    from .udp import UDP
    udp = UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = udp.__hdr_len__ + len(payload)
    return bytes(udp)


def _make_fragment(ident, offset_bytes, data, mf, src=SRC, dst=DST, proto=17,
                   opts=b''):
    frag = IP(src=src, dst=dst, p=proto, id=ident, data=data)
    frag.opts = opts
    frag.hl = (20 + len(opts)) >> 2
    frag.mf = 1 if mf else 0
    frag.offset = offset_bytes >> 3
    return IP(bytes(frag))


def _fragment_datagram(ident, payload, frag_size, **kwargs):
    frags = []
    offset = 0
    while offset < len(payload):
        chunk = payload[offset:offset + frag_size]
        mf = offset + len(chunk) < len(payload)
        frags.append(_make_fragment(ident, offset, chunk, mf, **kwargs))
        offset += len(chunk)
    return frags


def test_unfragmented_passthrough():
    from .udp import UDP
    reassembler = IPv4Defragmenter()
    pkt = IP(src=SRC, dst=DST, p=17, id=7,
             data=UDP(sport=1234, dport=53, data=b'hello'))
    wire = IP(bytes(pkt))
    result = reassembler.feed(wire, now=1.0)
    assert result.status == COMPLETE
    assert result.datagram is wire
    assert len(reassembler) == 0


def test_interleaved_datagrams_reassemble():
    reassembler = IPv4Defragmenter()
    payloads = {1: b'A' * 64 + b'first', 2: b'B' * 64 + b'second'}
    udp1 = _udp_wire(payloads[1], 1001, 2001)
    udp2 = _udp_wire(payloads[2], 1002, 2002)
    frags1 = _fragment_datagram(1, udp1, 24)
    frags2 = _fragment_datagram(2, udp2, 24)
    assert len(frags1) == 4 and len(frags2) == 4

    # Interleave both streams; the last fragment of stream 1 arrives first.
    order = ([frags1[-1], frags2[0], frags1[0], frags2[1], frags1[1],
              frags2[-1]] + frags1[2:-1] + frags2[2:-1])
    results = [reassembler.feed(f, now=10.0 + i)
               for i, f in enumerate(order)]

    completes = [r for r in results if r.status == COMPLETE]
    assert len(completes) == 2
    for result in completes:
        datagram = result.datagram
        ident = datagram.id
        assert datagram.mf == 0
        assert datagram.offset == 0
        assert datagram.udp.sport == 1000 + ident
        assert datagram.udp.dport == 2000 + ident
        assert datagram.udp.data == payloads[ident]
    # Nothing was zero-filled or left behind.
    assert len(reassembler) == 0
    assert all(r.datagram is None for r in results if r.status == INCOMPLETE)


def test_missing_fragment_stays_incomplete():
    reassembler = IPv4Defragmenter()
    udp = _udp_wire(b'x' * 60, 1, 2)  # 68 bytes -> 24, 24, 20
    frags = _fragment_datagram(9, udp, 24)
    r0 = reassembler.feed(frags[0], now=1.0)
    r2 = reassembler.feed(frags[2], now=2.0)
    assert r0.status == INCOMPLETE
    assert r2.status == INCOMPLETE
    assert r2.datagram is None
    assert r2.holes == [(24, 48)]
    assert 'missing byte range' in r2.reason
    assert len(reassembler) == 1


def test_duplicate_retransmission_merges():
    reassembler = IPv4Defragmenter()
    udp = _udp_wire(b'y' * 40, 1, 2)  # 48 bytes -> 3 x 16
    frags = _fragment_datagram(3, udp, 16)
    results = [reassembler.feed(f, now=5.0) for f in frags + frags]
    completes = [r for r in results if r.status == COMPLETE]
    # One assembly on first pass; each identical retransmission is recognized
    # and returns the same reassembled datagram instead of re-buffering.
    assert len(completes) == 4
    assert {id(r.datagram) for r in completes} == {id(completes[0].datagram)}
    assert all(r.conflicts == [] for r in completes)
    assert completes[0].datagram.udp.data == b'y' * 40
    assert len(reassembler) == 0


def test_overlap_identical_merges():
    reassembler = IPv4Defragmenter()
    payload = _udp_wire(b'z' * 32, 1, 2)  # 40 bytes
    f1 = _make_fragment(5, 0, payload[:24], True)
    f2 = _make_fragment(5, 16, payload[16:], False)  # [16, 24) overlaps
    assert reassembler.feed(f1, now=1.0).status == INCOMPLETE
    result = reassembler.feed(f2, now=2.0)
    assert result.status == COMPLETE
    assert result.conflicts == []
    assert result.datagram.udp.data == b'z' * 32


def test_overlap_conflict_reject():
    reassembler = IPv4Defragmenter()  # default policy: reject
    payload = _udp_wire(b'z' * 32, 1, 2)
    evil = bytearray(payload[16:])
    evil[0] ^= 0xff
    reassembler.feed(_make_fragment(5, 0, payload[:24], True), now=1.0)
    result = reassembler.feed(_make_fragment(5, 16, bytes(evil), False),
                              now=2.0)
    assert result.status == CONFLICT
    assert result.conflicts == [(16, 24)]
    assert result.datagram is None
    assert len(reassembler) == 0


def test_overlap_first_and_last_policies():
    payload = _udp_wire(b'z' * 32, 1, 2)
    evil = bytearray(payload[16:])
    evil[0] ^= 0xff
    cases = ((IPv4Defragmenter.OVERLAP_FIRST, payload[16]),
             (IPv4Defragmenter.OVERLAP_LAST, payload[16] ^ 0xff))
    for policy, expected_byte in cases:
        reassembler = IPv4Defragmenter(overlap_policy=policy)
        reassembler.feed(_make_fragment(5, 0, payload[:24], True), now=1.0)
        result = reassembler.feed(_make_fragment(5, 16, bytes(evil), False),
                                  now=2.0)
        assert result.status == COMPLETE
        assert result.conflicts == [(16, 24)]
        assert bytes(result.datagram.data)[16] == expected_byte


def test_invalid_nonfinal_fragment_length():
    reassembler = IPv4Defragmenter()
    frag = _make_fragment(6, 0, b'1234567890', True)  # 10 % 8 != 0
    result = reassembler.feed(frag, now=1.0)
    assert result.status == INVALID
    assert 'multiple of 8' in result.reason
    assert len(reassembler) == 0


def test_conflicting_total_length():
    reassembler = IPv4Defragmenter()
    reassembler.feed(_make_fragment(4, 0, b'12345678', True), now=1.0)
    result = reassembler.feed(_make_fragment(4, 16, b'12345678', False),
                              now=2.0)
    assert result.status == INCOMPLETE
    assert result.holes == [(8, 16)]
    # A second, contradictory terminal fragment is a conflict.
    result = reassembler.feed(_make_fragment(4, 16, b'12345678' * 2, False),
                              now=3.0)
    assert result.status == CONFLICT
    assert 'total payload length' in result.reason
    assert len(reassembler) == 0


def test_expire_reports_incomplete():
    reassembler = IPv4Defragmenter(timeout=30.0)
    udp = _udp_wire(b'q' * 40, 1, 2)  # 48 bytes -> 3 x 16
    frags = _fragment_datagram(8, udp, 16)
    reassembler.feed(frags[0], now=100.0)
    assert reassembler.expire(now=129.0) == []
    expired = reassembler.expire(now=131.0)
    assert len(expired) == 1
    assert expired[0].status == EXPIRED
    assert expired[0].datagram is None
    # Only the first fragment was seen; the tail is an open-ended gap.
    assert expired[0].holes == [(16, None)]
    assert 'timed out' in expired[0].reason
    assert len(reassembler) == 0


def test_completed_cache_expires_and_duplicate_conflicts():
    reassembler = IPv4Defragmenter(timeout=10.0)
    udp = _udp_wire(b'q' * 40, 1, 2)
    frags = _fragment_datagram(8, udp, 16)
    for frag in frags:
        reassembler.feed(frag, now=0.0)
    assert len(reassembler) == 0
    # A duplicate right after completion is merged via the cache.
    assert reassembler.feed(frags[1], now=1.0).status == COMPLETE
    # A retransmission carrying different bytes is reported as a conflict.
    evil = bytearray(frags[1].data)
    evil[0] ^= 0xff
    bad = _make_fragment(8, 16, bytes(evil), True)
    result = reassembler.feed(bad, now=2.0)
    assert result.status == CONFLICT
    assert result.conflicts == [(16, 17)]
    # Once the cache entry times out, a late fragment is merely incomplete.
    result = reassembler.feed(frags[0], now=20.0)
    assert result.status == INCOMPLETE
    assert len(reassembler) == 1


def test_feed_reaps_expired_datagrams():
    reassembler = IPv4Defragmenter(timeout=10.0)
    udp = _udp_wire(b'q' * 40, 1, 2)
    frags = _fragment_datagram(8, udp, 16)
    reassembler.feed(frags[0], now=0.0)
    # A later packet arrives after the timeout; the stale entry is reaped.
    reassembler.feed(_make_fragment(9, 0, b'12345678', True), now=20.0)
    assert reassembler.pending == [(SRC, DST, 17, 9)]


def test_first_fragment_supplies_options():
    reassembler = IPv4Defragmenter()
    opts = b'\x01\x01\x01\x00'  # NOP, NOP, NOP, EOL
    udp = _udp_wire(b'w' * 24, 1, 2)  # 32 bytes
    reassembler.feed(_make_fragment(2, 0, udp[:16], True, opts=opts), now=1.0)
    result = reassembler.feed(_make_fragment(2, 16, udp[16:], False), now=2.0)
    assert result.status == COMPLETE
    assert result.datagram.opts == opts
    assert result.datagram.hl == 6
    assert result.datagram.udp.data == b'w' * 24


def test_feed_rejects_non_ip():
    reassembler = IPv4Defragmenter()
    with pytest.raises(TypeError):
        reassembler.feed(b'not a packet', now=1.0)


def test_result_truthiness_and_repr():
    result = ReassemblyResult(INCOMPLETE, reason='x')
    assert not result
    assert 'incomplete' in repr(result)
    assert ReassemblyResult(COMPLETE)
