# -*- coding: utf-8 -*-
"""Incremental IPv4 fragment reassembly.

This module provides :class:IPv4Defragmenter, a small, thread-free state
machine that accepts the fragments of one or many IPv4 datagrams in arbitrary
order and emits a fully reassembled :class:dpkt.ip.IP packet as soon as all
fragments of a datagram have been seen.

Reassembly candidates are keyed by (src, dst, protocol, identification),
so fragments belonging to different datagrams may be interleaved freely.
Identical retransmissions of an already seen fragment (byte for byte) are
simply merged.  When fragments overlap and the overlapping bytes differ, the
behaviour is selected explicitly with the overlap_policy argument and every
conflict is recorded on the returned :class:ReassemblyResult.

Time is always supplied by the caller; no background thread or timer is
started.  Datagrams that never complete are reported by :meth:expire once
they are older than the configured timeout.  A datagram with holes is never
zero-padded and never handed to the application.

Example:

    >>> from dpkt.ipdefrag import IPv4Defragmenter
    >>> df = IPv4Defragmenter(timeout=30.0)
    >>> for fragment in capture:
    ...     result = df.feed(fragment, ts=capture_time)
    ...     if result.complete:
    ...         handle(result.datagram)
    >>> for result in df.expire(now):
    ...     log_stale(result)
"""
from __future__ import absolute_import
from __future__ import print_function

import struct
from collections import namedtuple

from .dpkt import in_cksum
from .ip import IP, IP_DF, IP_HDR_LEN, IP_LEN_MAX
from .utils import inet_to_str


# Result statuses -------------------------------------------------------------

STATUS_COMPLETE = 'complete'
STATUS_INCOMPLETE = 'incomplete'
STATUS_INVALID = 'invalid'


# Overlap policies ------------------------------------------------------------

#: Reject a datagram as soon as two fragments overlap with different bytes.
OVERLAP_REJECT = 'reject'
#: Keep the bytes of the first fragment seen in a conflicting overlap.
OVERLAP_FIRST = 'first'
#: Let the bytes of the later fragment win a conflicting overlap.
OVERLAP_LAST = 'last'

_OVERLAP_POLICIES = (OVERLAP_REJECT, OVERLAP_FIRST, OVERLAP_LAST)


#: Identity of an in-progress reassembly: source, destination, protocol and
#: IP identification field, exactly as required by RFC 791.
FragKey = namedtuple('FragKey', 'src dst proto id')


#: A byte range [start, end) where two fragments disagreed.  existing holds
#: the bytes already buffered and incoming the bytes of the new fragment.
Conflict = namedtuple('Conflict', 'start end existing incoming')


class ReassemblyResult(object):
    """Outcome of a single IPv4Defragmenter.feed call.

    Attributes:
        key (FragKey): identity of the datagram.
        status (str): one of STATUS_COMPLETE, STATUS_INCOMPLETE or
            STATUS_INVALID.
        datagram (dpkt.ip.IP or None): the reassembled, fully parsed IP
            datagram; only present when status is STATUS_COMPLETE.
        missing (list): list of (start, end) byte ranges that have not
            been received yet.
        conflicts (list): list of Conflict objects recorded while
            reassembling this datagram.
        reason (str or None): human readable explanation for an invalid
            datagram.
        received (int): number of payload bytes currently covered.
        total (int or None): total payload length advertised by the final
            fragment (MF == 0); None until that fragment arrives.
    """

    __slots__ = ('key', 'status', 'datagram', 'missing', 'conflicts',
                 'reason', 'received', 'total')

    def __init__(self, key, status, datagram=None, missing=None,
                 conflicts=None, reason=None, received=0, total=None):
        self.key = key
        self.status = status
        self.datagram = datagram
        self.missing = list(missing or ())
        self.conflicts = list(conflicts or ())
        self.reason = reason
        self.received = received
        self.total = total

    @property
    def complete(self):
        """True when datagram holds a reassembled IP datagram."""
        return self.status == STATUS_COMPLETE

    @property
    def last_fragment_seen(self):
        """True once a fragment with MF == 0 fixed the total length."""
        return self.total is not None

    def __repr__(self):
        parts = ['status=%r' % self.status,
                 'src=%s' % inet_to_str(self.key.src),
                 'dst=%s' % inet_to_str(self.key.dst),
                 'proto=%d' % self.key.proto,
                 'id=%d' % self.key.id,
                 'received=%d' % self.received]
        if self.total is not None:
            parts.append('total=%d' % self.total)
        if self.missing:
            parts.append('missing=%r' % self.missing)
        if self.conflicts:
            parts.append('conflicts=%d' % len(self.conflicts))
        if self.reason:
            parts.append('reason=%r' % self.reason)
        return 'ReassemblyResult(%s)' % ', '.join(parts)


#: Maximum number of payload bytes a reassembled IPv4 datagram may contain
#: (65535 byte total length minus the 20 byte minimum header).
_MAX_PAYLOAD = IP_LEN_MAX - IP_HDR_LEN


class _Entry(object):
    __slots__ = ('first_hdr', 'total', 'buf', 'ranges', 'conflicts',
                 'invalid', 'updated')

    def __init__(self):
        # Raw header (fixed header + options) taken from the offset 0
        # fragment; that fragment owns the protocol header and options.
        self.first_hdr = None
        # Total reassembled payload length, fixed by the MF == 0 fragment.
        self.total = None
        self.buf = bytearray()
        # Sorted, disjoint list of covered (start, end) payload ranges.
        self.ranges = []
        self.conflicts = []
        self.invalid = None
        self.updated = None


class IPv4Defragmenter(object):
    """Incrementally reassemble IPv4 fragments.

    Args:
        timeout (float): time an unfinished datagram is kept before
            expire() reports it.  Time values are whatever the caller
            passes to feed() and expire() (seconds since the epoch,
            monotonic clocks, ...).
        overlap_policy (str): one of OVERLAP_REJECT, OVERLAP_FIRST or
            OVERLAP_LAST.
        max_datagrams (int): maximum number of unfinished datagrams kept;
            the oldest one is evicted when the limit is exceeded.
    """

    def __init__(self, timeout=60.0, overlap_policy=OVERLAP_REJECT,
                 max_datagrams=1024):
        if overlap_policy not in _OVERLAP_POLICIES:
            raise ValueError('unknown overlap_policy %r, expected one of %r'
                             % (overlap_policy, _OVERLAP_POLICIES))
        if timeout < 0:
            raise ValueError('timeout must be non-negative')
        self.timeout = timeout
        self.overlap_policy = overlap_policy
        self.max_datagrams = max_datagrams
        self._entries = {}

    def __len__(self):
        return len(self._entries)

    def __contains__(self, key):
        return key in self._entries

    def keys(self):
        """Identifiers of all datagrams currently being reassembled."""
        return list(self._entries)

    def drop(self, key):
        """Discard an unfinished datagram; return True if one was removed."""
        return self._entries.pop(key, None) is not None

    def feed(self, pkt, ts=None):
        """Feed one IPv4 packet (a dpkt.ip.IP or raw IP bytes).

        Returns a ReassemblyResult describing the state of the datagram
        after inserting the packet.  Packets that are not fragmented at
        all (offset 0, MF == 0) are returned complete immediately and are
        not tracked.
        """
        if not isinstance(pkt, IP):
            pkt = IP(pkt)
        if pkt.v != 4:
            raise ValueError('expected an IPv4 packet, got IP version %r'
                             % (pkt.v,))

        key = FragKey(pkt.src, pkt.dst, pkt.p, pkt.id)
        payload = bytes(pkt.data)
        start = pkt.offset * 8
        end = start + len(payload)
        more = bool(pkt.mf)

        if start == 0 and not more:
            # A complete, unfragmented datagram; nothing to reassemble.
            return ReassemblyResult(key, STATUS_COMPLETE, datagram=pkt,
                                    received=len(payload), total=len(payload))

        entry = self._entries.get(key)
        if entry is None:
            if len(self._entries) >= self.max_datagrams:
                self._evict_oldest()
            entry = _Entry()
            self._entries[key] = entry
        if ts is not None:
            entry.updated = ts

        # A datagram that already failed validation stays invalid; further
        # fragments cannot repair it.
        if entry.invalid is not None:
            return self._result(entry, key)

        self._validate(entry, start, end, len(payload), more)
        if entry.invalid is None and start == 0 and entry.first_hdr is None:
            entry.first_hdr = pkt.pack_hdr() + bytes(pkt.opts)
        if entry.invalid is None and end > start:
            self._merge(entry, start, end, payload)

        return self._result(entry, key)

    def expire(self, now):
        """Drop unfinished datagrams older than timeout at time now.

        Returns a list of ReassemblyResult objects, one per expired
        datagram.  Entries that never received an explicit timestamp are
        stamped with now and expire only after a further timeout.
        No background work happens between calls.
        """
        expired = []
        for key in list(self._entries):
            entry = self._entries[key]
            if entry.updated is None:
                entry.updated = now
            elif now - entry.updated >= self.timeout:
                expired.append(self._result(entry, key))
                del self._entries[key]
        return expired

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _validate(entry, start, end, length, more):
        if more and length % 8 != 0:
            # RFC 791: every fragment except the last must carry data whose
            # length is a multiple of 8 bytes.
            entry.invalid = ('non-final fragment payload length %d is not a '
                             'multiple of 8' % length)
            return
        if end > _MAX_PAYLOAD:
            entry.invalid = ('fragment end offset %d exceeds the maximum '
                             'IPv4 payload length %d' % (end, _MAX_PAYLOAD))
            return
        if not more:
            if entry.total is not None and entry.total != end:
                entry.invalid = ('conflicting total datagram lengths: final '
                                 'fragment ends at %d but %d was previously '
                                 'observed' % (end, entry.total))
                return
            entry.total = end
        if entry.total is not None and end > entry.total:
            entry.invalid = ('fragment end offset %d exceeds the reassembled '
                             'datagram length %d' % (end, entry.total))

    def _merge(self, entry, start, end, data):
        if end > len(entry.buf):
            entry.buf.extend(b'\x00' * (end - len(entry.buf)))

        conflicts = []
        for range_start, range_end in entry.ranges:
            if range_start >= end:
                break
            if range_end <= start:
                continue
            overlap_start = max(start, range_start)
            overlap_end = min(end, range_end)
            existing = bytes(entry.buf[overlap_start:overlap_end])
            incoming = data[overlap_start - start:overlap_end - start]
            if existing != incoming:
                conflicts.append(Conflict(overlap_start, overlap_end,
                                          existing, incoming))

        if conflicts:
            entry.conflicts.extend(conflicts)
            if self.overlap_policy == OVERLAP_REJECT:
                entry.invalid = ('overlapping fragments with different '
                                 'content at byte ranges %s'
                                 % [(c.start, c.end) for c in conflicts])
                return

        if self.overlap_policy == OVERLAP_FIRST:
            # Preserve previously buffered bytes; fill only uncovered gaps.
            for write_start, write_end in _subtract(entry.ranges, start, end):
                entry.buf[write_start:write_end] = \
                    data[write_start - start:write_end - start]
        else:
            # OVERLAP_LAST, or an identical overlap under OVERLAP_REJECT.
            entry.buf[start:end] = data

        _insert_range(entry.ranges, start, end)

    def _result(self, entry, key):
        if (entry.invalid is None and entry.first_hdr is not None
                and entry.total is not None
                and entry.ranges == [(0, entry.total)]):
            datagram = self._build_datagram(entry)
            del self._entries[key]
            return ReassemblyResult(key, STATUS_COMPLETE, datagram=datagram,
                                    conflicts=entry.conflicts,
                                    received=entry.total, total=entry.total)

        received = sum(end - start for start, end in entry.ranges)
        if entry.invalid is not None:
            status = STATUS_INVALID
        else:
            status = STATUS_INCOMPLETE
        return ReassemblyResult(key, status,
                                missing=_holes(entry),
                                conflicts=entry.conflicts,
                                reason=entry.invalid,
                                received=received,
                                total=entry.total)

    @staticmethod
    def _build_datagram(entry):
        header = bytearray(entry.first_hdr)
        total_length = len(header) + entry.total
        struct.pack_into('>H', header, 2, total_length)
        # Clear MF and the fragment offset, keep DF.
        flags_offset = struct.unpack_from('>H', header, 6)[0]
        struct.pack_into('>H', header, 6, flags_offset & IP_DF)
        struct.pack_into('>H', header, 10, 0)
        struct.pack_into('>H', header, 10, in_cksum(bytes(header)))
        return IP(bytes(header) + bytes(entry.buf[:entry.total]))

    def _evict_oldest(self):
        def staleness(item):
            updated = item[1].updated
            # Entries without a timestamp are evicted first.
            return (updated is not None, updated)

        oldest = min(self._entries.items(), key=staleness)[0]
        del self._entries[oldest]


def _insert_range(ranges, start, end):
    ranges.append((start, end))
    ranges.sort()
    merged = []
    for range_start, range_end in ranges:
        if merged and range_start <= merged[-1][1]:
            if range_end > merged[-1][1]:
                merged[-1] = (merged[-1][0], range_end)
        else:
            merged.append((range_start, range_end))
    ranges[:] = merged


def _subtract(ranges, start, end):
    """Parts of [start, end) not covered by sorted disjoint ranges."""
    uncovered = []
    cursor = start
    for range_start, range_end in ranges:
        if range_end <= cursor:
            continue
        if range_start >= end:
            break
        if range_start > cursor:
            uncovered.append((cursor, min(range_start, end)))
        cursor = max(cursor, range_end)
        if cursor >= end:
            break
    if cursor < end:
        uncovered.append((cursor, end))
    return uncovered


def _holes(entry):
    limit = entry.total
    if limit is None:
        limit = max((range_end for _, range_end in entry.ranges), default=0)
    holes = []
    cursor = 0
    for range_start, range_end in entry.ranges:
        if range_start > cursor:
            holes.append((cursor, range_start))
        cursor = max(cursor, range_end)
    if cursor < limit:
        holes.append((cursor, limit))
    return holes


# -- tests -------------------------------------------------------------------

def _udp_payload(payload, sport=1234, dport=5678):
    from . import udp
    u = udp.UDP(sport=sport, dport=dport, data=payload)
    u.ulen = udp.UDP_HDR_LEN + len(payload)
    return bytes(u)


def _fragment(ident, payload, offset, more, src=b'\x0a\x00\x00\x01',
              dst=b'\x0a\x00\x00\x02', proto=17):
    pkt = IP(src=src, dst=dst, p=proto, id=ident, data=payload)
    pkt.offset = offset // 8
    pkt.mf = 1 if more else 0
    return pkt


def _fragmented(ident, payload, chunk, **kwargs):
    frags = []
    offset = 0
    while offset < len(payload):
        piece = payload[offset:offset + chunk]
        frags.append(_fragment(ident, piece, offset,
                               offset + len(piece) < len(payload), **kwargs))
        offset += len(piece)
    return frags


def test_interleaved_udp_reassembly():
    payload_a = _udp_payload(b'alpha-' * 20)   # 128 bytes, 4 fragments
    payload_b = _udp_payload(b'beta!' * 30)    # 158 bytes, 5 fragments
    frags_a = _fragmented(0x1111, payload_a, 32)
    frags_b = _fragmented(0x2222, payload_b, 32, src=b'\x0a\x00\x00\x03')

    df = IPv4Defragmenter()
    completed = []
    # Reverse both groups: fragments arrive out of order, last one first.
    frags_a.reverse()
    frags_b.reverse()
    for i in range(max(len(frags_a), len(frags_b))):
        for frag in (frags_a[i:i + 1], frags_b[i:i + 1]):
            if not frag:
                continue
            result = df.feed(frag[0], ts=1000.0)
            if result.complete:
                completed.append(result)
            else:
                assert result.status == STATUS_INCOMPLETE

    assert len(completed) == 2
    assert len(df) == 0
    by_ident = dict((r.key.id, r) for r in completed)
    assert by_ident[0x1111].datagram.udp.data == b'alpha-' * 20
    assert by_ident[0x2222].datagram.udp.data == b'beta!' * 30
    assert by_ident[0x1111].datagram.udp.sport == 1234
    assert by_ident[0x1111].datagram.udp.dport == 5678
    assert by_ident[0x1111].datagram.mf == 0
    assert by_ident[0x1111].datagram.offset == 0
    assert by_ident[0x1111].datagram.len == 20 + 128
    assert not by_ident[0x1111].conflicts


def test_feed_accepts_raw_bytes():
    payload = _udp_payload(b'raw' * 16)
    frags = _fragmented(9, payload, 24)
    df = IPv4Defragmenter()
    result = None
    for frag in frags:
        result = df.feed(bytes(frag), ts=0.0)
    assert result.complete
    assert result.datagram.udp.data == b'raw' * 16


def test_missing_fragment_is_incomplete():
    payload = _udp_payload(b'x' * 64)  # 72 bytes -> 5 fragments of 16
    frags = _fragmented(7, payload, 16)
    df = IPv4Defragmenter()
    result = None
    for i, frag in enumerate(frags):
        if i == 2:
            continue  # drop the fragment covering [32, 48)
        result = df.feed(frag, ts=1.0)
    assert result.status == STATUS_INCOMPLETE
    assert not result.complete
    # The hole is reported, never zero-padded into a datagram.
    assert result.datagram is None
    assert result.missing == [(32, 48)]
    assert result.total == 72
    assert result.received == 56
    assert result.last_fragment_seen
    assert 'incomplete' in repr(result)

    # Feeding the missing piece finishes the datagram.
    result = df.feed(frags[2], ts=2.0)
    assert result.complete
    assert result.datagram.udp.data == b'x' * 64


def test_duplicate_retransmission_merges():
    payload = _udp_payload(b'dup' * 16)
    frags = _fragmented(3, payload, 16)
    df = IPv4Defragmenter()
    result = None
    for frag in frags:
        result = df.feed(frag, ts=1.0)
        df.feed(frag, ts=2.0)  # identical retransmission
    assert result.complete
    assert not result.conflicts
    assert result.datagram.udp.data == b'dup' * 16


def _overlap_pair():
    first = _fragment(1, b'A' * 16, 0, True, proto=0)
    second = _fragment(1, b'B' * 16, 8, False, proto=0)
    return first, second


def test_overlap_reject():
    df = IPv4Defragmenter(overlap_policy=OVERLAP_REJECT)
    first, second = _overlap_pair()
    df.feed(first)
    result = df.feed(second)
    assert result.status == STATUS_INVALID
    assert 'overlap' in result.reason
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert (conflict.start, conflict.end) == (8, 16)
    assert conflict.existing == b'A' * 8
    assert conflict.incoming == b'B' * 8
    # The datagram stays invalid; later fragments cannot repair it.
    assert df.feed(first).status == STATUS_INVALID


def test_overlap_first_wins():
    df = IPv4Defragmenter(overlap_policy=OVERLAP_FIRST)
    first, second = _overlap_pair()
    df.feed(first)
    result = df.feed(second)
    assert result.complete
    assert len(result.conflicts) == 1
    assert bytes(result.datagram.data) == b'A' * 16 + b'B' * 8


def test_overlap_last_wins():
    df = IPv4Defragmenter(overlap_policy=OVERLAP_LAST)
    first, second = _overlap_pair()
    df.feed(first)
    result = df.feed(second)
    assert result.complete
    assert len(result.conflicts) == 1
    assert bytes(result.datagram.data) == b'A' * 8 + b'B' * 16


def test_invalid_overlap_policy():
    import pytest
    with pytest.raises(ValueError):
        IPv4Defragmenter(overlap_policy='bogus')


def test_nonfinal_fragment_length_must_be_multiple_of_8():
    df = IPv4Defragmenter()
    result = df.feed(_fragment(1, b'123456789', 0, True, proto=0))
    assert result.status == STATUS_INVALID
    assert 'multiple of 8' in result.reason


def test_fragment_beyond_total_length():
    df = IPv4Defragmenter()
    df.feed(_fragment(1, b'A' * 16, 0, True, proto=0))
    df.feed(_fragment(1, b'B' * 8, 24, False, proto=0))  # total = 32
    result = df.feed(_fragment(1, b'C' * 8, 32, True, proto=0))
    assert result.status == STATUS_INVALID
    assert 'exceeds the reassembled' in result.reason


def test_conflicting_total_lengths():
    df = IPv4Defragmenter()
    df.feed(_fragment(1, b'A' * 16, 0, True, proto=0))
    df.feed(_fragment(1, b'B' * 8, 24, False, proto=0))  # total = 32
    result = df.feed(_fragment(1, b'C' * 8, 40, False, proto=0))
    assert result.status == STATUS_INVALID
    assert 'conflicting total' in result.reason


def test_expire_uses_caller_supplied_time():
    df = IPv4Defragmenter(timeout=30.0)
    frag = _fragment(5, b'A' * 16, 0, True, proto=0)
    df.feed(frag, ts=100.0)
    assert df.expire(129.9) == []
    assert len(df) == 1
    expired = df.expire(130.0)
    assert len(expired) == 1
    assert expired[0].status == STATUS_INCOMPLETE
    assert expired[0].key.id == 5
    # [0, 16) is covered; the final fragment never arrived, so the total
    # length (and therefore the tail of the datagram) is still unknown.
    assert expired[0].missing == []
    assert expired[0].total is None
    assert len(df) == 0


def test_expire_stamps_untimed_entries():
    df = IPv4Defragmenter(timeout=10.0)
    df.feed(_fragment(6, b'A' * 16, 0, True, proto=0))  # no timestamp
    assert df.expire(50.0) == []   # stamped at 50.0
    assert len(df.expire(61.0)) == 1


def test_unfragmented_packet_passes_through():
    df = IPv4Defragmenter()
    pkt = IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=17, id=5,
             data=_udp_payload(b'hi'))
    result = df.feed(bytes(pkt), ts=1.0)
    assert result.complete
    assert result.datagram.udp.data == b'hi'
    assert len(df) == 0


def test_max_datagrams_evicts_oldest():
    df = IPv4Defragmenter(max_datagrams=1)
    df.feed(_fragment(1, b'A' * 16, 0, True, proto=0), ts=1.0)
    df.feed(_fragment(2, b'B' * 16, 0, True, proto=0), ts=2.0)
    assert len(df) == 1
    assert df.keys()[0].id == 2
    assert df.drop(df.keys()[0])
    assert len(df) == 0
