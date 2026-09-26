# -*- coding: utf-8 -*-
"""Header rewriting with incremental checksum adjustment.

Anonymization services often work with truncated captures where only the
first few dozen bytes of each packet were recorded.  Rewriting an address
or port and then recomputing checksums from the captured bytes would
produce values that no longer correspond to the original full packet.
This module instead rewrites header fields in place and adjusts the IPv4
header checksum and the TCP/UDP pseudo-header checksums incrementally
(RFC 1624), without ever reading the (possibly missing) payload.

The entry point is :func:'rewrite'.  It returns a per-field report so the
caller knows exactly which fields were rewritten and which could not be
processed:

- REWRITTEN    - the field was rewritten
- ADJUSTED     - the checksum was incrementally adjusted and stays valid
- UNCHANGED    - no new value was requested for the field
- NO_CHECKSUM  - the original packet carried no UDP checksum (0x0000);
  it is left untouched per RFC 768 rather than being fabricated
- NOT_PRESENT  - the field is not present in this packet (trailing
  fragment, or the protocol carries no such field)
- INSUFFICIENT - the capture is too short to rewrite or adjust the field
"""
from __future__ import absolute_import

import socket
import struct

from . import ip
from . import ip6
from . import tcp
from . import udp

REWRITTEN = 'rewritten'
ADJUSTED = 'adjusted'
UNCHANGED = 'unchanged'
NO_CHECKSUM = 'no-checksum'
NOT_PRESENT = 'not-present'
INSUFFICIENT = 'insufficient'

# checksum field offset within the transport header, per IP protocol number
_PROTO_SUM_OFFSET = {
    ip.IP_PROTO_TCP: 16,
    ip.IP_PROTO_UDP: 6,
}


def _cksum_update(sum_, segments):
    """Return Internet checksum 'sum_' incrementally updated for 'segments'.

    Each segment is an (old_buf, new_buf) pair of equal, even length
    holding the 16-bit words that were replaced.  The arithmetic is done in
    one's complement, so the two zero representations (0x0000 and 0xffff)
    of a stored checksum are both folded correctly.
    """
    s = (~sum_) & 0xffff
    for old_buf, new_buf in segments:
        for off in range(0, len(old_buf), 2):
            old_word, = struct.unpack('>H', old_buf[off:off + 2])
            new_word, = struct.unpack('>H', new_buf[off:off + 2])
            s += (~old_word) & 0xffff
            s += new_word
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _coerce_addr(addr, family):
    if isinstance(addr, bytes):
        expected = 4 if family == socket.AF_INET else 16
        if len(addr) != expected:
            raise ValueError('expected a %d-byte address, got %d bytes' % (expected, len(addr)))
        return addr
    return socket.inet_pton(family, addr)


def _port_segments(l4, sport, dport):
    segments = []
    if sport is not None:
        segments.append((struct.pack('>H', l4.sport), struct.pack('>H', sport)))
    if dport is not None:
        segments.append((struct.pack('>H', l4.dport), struct.pack('>H', dport)))
    return segments


def _normalize_sum(sum_, is_udp):
    # RFC 768: a computed zero UDP checksum is transmitted as all ones; an
    # all-zero transmitted value means the sender generated no checksum.
    if is_udp and sum_ == 0:
        return 0xffff
    return sum_


def rewrite(pkt, src=None, dst=None, sport=None, dport=None):
    """Rewrite addresses/ports of a parsed IP or IP6 packet in place.

    Checksums are fixed up incrementally from their captured values, so the
    payload is never needed and truncated datagrams are handled gracefully.
    Returns a dict mapping field names ('src', 'dst', 'ip_sum', 'sport',
    'dport', 'transport_sum') to one of the status constants defined in
    this module.
    """
    if isinstance(pkt, ip.IP):
        return _rewrite_ip(pkt, src, dst, sport, dport)
    if isinstance(pkt, ip6.IP6):
        return _rewrite_ip6(pkt, src, dst, sport, dport)
    raise TypeError('expected an ip.IP or ip6.IP6 packet, got %r' % (type(pkt),))


def _rewrite_ip(pkt, src, dst, sport, dport):
    report = {}
    old_addrs = pkt.src + pkt.dst
    new_src = _coerce_addr(src, socket.AF_INET) if src is not None else pkt.src
    new_dst = _coerce_addr(dst, socket.AF_INET) if dst is not None else pkt.dst
    new_addrs = new_src + new_dst

    pkt.src = new_src
    pkt.dst = new_dst
    report['src'] = REWRITTEN if src is not None else UNCHANGED
    report['dst'] = REWRITTEN if dst is not None else UNCHANGED
    if new_addrs != old_addrs:
        pkt.sum = _cksum_update(pkt.sum, [(old_addrs, new_addrs)])
        report['ip_sum'] = ADJUSTED
    else:
        report['ip_sum'] = UNCHANGED

    if pkt.offset != 0:
        # trailing fragment: the transport header lives in the first fragment
        report['sport'] = NOT_PRESENT
        report['dport'] = NOT_PRESENT
        report['transport_sum'] = NOT_PRESENT
        return report
    _rewrite_transport(pkt, pkt.p, report, old_addrs, new_addrs, sport, dport)
    return report


def _rewrite_ip6(pkt, src, dst, sport, dport):
    report = {}
    old_addrs = pkt.src + pkt.dst
    new_src = _coerce_addr(src, socket.AF_INET6) if src is not None else pkt.src
    new_dst = _coerce_addr(dst, socket.AF_INET6) if dst is not None else pkt.dst
    new_addrs = new_src + new_dst

    pkt.src = new_src
    pkt.dst = new_dst
    report['src'] = REWRITTEN if src is not None else UNCHANGED
    report['dst'] = REWRITTEN if dst is not None else UNCHANGED
    report['ip_sum'] = NOT_PRESENT  # IPv6 has no header checksum

    fragment = None
    for ext in getattr(pkt, 'all_extension_headers', ()):
        if isinstance(ext, ip6.IP6FragmentHeader):
            fragment = ext
            break
    if fragment is not None and fragment.frag_off != 0:
        # trailing fragment: the transport header lives in the first fragment
        report['sport'] = NOT_PRESENT
        report['dport'] = NOT_PRESENT
        report['transport_sum'] = NOT_PRESENT
        return report
    _rewrite_transport(pkt, getattr(pkt, 'p', pkt.nxt), report, old_addrs, new_addrs, sport, dport)
    return report


def _rewrite_transport(pkt, proto, report, old_addrs, new_addrs, sport, dport):
    if proto not in _PROTO_SUM_OFFSET:
        report['sport'] = NOT_PRESENT
        report['dport'] = NOT_PRESENT
        report['transport_sum'] = NOT_PRESENT
        return

    is_udp = proto == ip.IP_PROTO_UDP
    l4 = pkt.data
    addr_segments = [(old_addrs, new_addrs)] if old_addrs != new_addrs else []

    if isinstance(l4, (tcp.TCP, udp.UDP)):
        segments = addr_segments + _port_segments(l4, sport, dport)
        report['transport_sum'] = _adjust_sum(l4, is_udp, segments)
        if sport is not None:
            l4.sport = sport
        if dport is not None:
            l4.dport = dport
        report['sport'] = REWRITTEN if sport is not None else UNCHANGED
        report['dport'] = REWRITTEN if dport is not None else UNCHANGED
    elif isinstance(l4, bytes):
        _rewrite_transport_raw(pkt, proto, report, addr_segments, sport, dport)
    else:
        report['sport'] = NOT_PRESENT
        report['dport'] = NOT_PRESENT
        report['transport_sum'] = NOT_PRESENT


def _adjust_sum(l4, is_udp, segments):
    if is_udp and l4.sum == 0:
        # RFC 768: a zero UDP checksum means the transmitter generated none
        return NO_CHECKSUM
    if segments:
        l4.sum = _normalize_sum(_cksum_update(l4.sum, segments), is_udp)
        return ADJUSTED
    return UNCHANGED


def _rewrite_transport_raw(pkt, proto, report, addr_segments, sport, dport):
    """Rewrite whatever a truncated transport header still allows.

    Used when the capture cut off part of the TCP/UDP header itself, so the
    packet data never parsed into a TCP/UDP instance.
    """
    is_udp = proto == ip.IP_PROTO_UDP
    buf = pkt.data
    sum_off = _PROTO_SUM_OFFSET[proto]

    segments = list(addr_segments)
    new_ports = None
    if len(buf) >= 4:
        # ports are the first 4 bytes of both the TCP and UDP headers
        old_sport, old_dport = struct.unpack('>HH', buf[:4])
        new_ports = struct.pack('>HH',
                                sport if sport is not None else old_sport,
                                dport if dport is not None else old_dport)
        if new_ports != buf[:4]:
            segments.append((buf[:4], new_ports))

    out = bytearray(buf)
    if len(buf) >= sum_off + 2:
        old_sum, = struct.unpack('>H', buf[sum_off:sum_off + 2])
        if is_udp and old_sum == 0:
            report['transport_sum'] = NO_CHECKSUM
        elif segments:
            new_sum = _normalize_sum(_cksum_update(old_sum, segments), is_udp)
            struct.pack_into('>H', out, sum_off, new_sum)
            report['transport_sum'] = ADJUSTED
        else:
            report['transport_sum'] = UNCHANGED
    else:
        report['transport_sum'] = INSUFFICIENT

    if len(buf) >= 4:
        if new_ports != buf[:4]:
            out[0:4] = new_ports
        report['sport'] = REWRITTEN if sport is not None else UNCHANGED
        report['dport'] = REWRITTEN if dport is not None else UNCHANGED
    else:
        report['sport'] = (INSUFFICIENT if sport is not None else UNCHANGED)
        report['dport'] = (INSUFFICIENT if dport is not None else UNCHANGED)
    pkt.data = bytes(out)


# Unit tests


def _build_tcp4(payload=b'x' * 100):
    t = tcp.TCP(sport=12345, dport=80, seq=1000, win=8192)
    t.flags = tcp.TH_PUSH | tcp.TH_ACK
    t.data = payload
    pkt = ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=ip.IP_PROTO_TCP, data=t)
    return bytes(pkt)


def _build_udp4(payload=b'u' * 60, sport=111, dport=222):
    u = udp.UDP(sport=sport, dport=dport)
    u.data = payload
    u.ulen += len(u.data)
    pkt = ip.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', p=ip.IP_PROTO_UDP, data=u)
    return bytes(pkt)


def _build_tcp6(payload=b'y' * 64):
    t = tcp.TCP(sport=443, dport=55555, seq=7, win=4096)
    t.flags = tcp.TH_PUSH | tcp.TH_ACK
    t.data = payload
    pkt = ip6.IP6(src=socket.inet_pton(socket.AF_INET6, '2001:db8::1'),
                  dst=socket.inet_pton(socket.AF_INET6, '2001:db8::2'),
                  nxt=ip.IP_PROTO_TCP, data=t)
    pkt.plen = len(t)
    return bytes(pkt)


def _full_recompute_reference(raw, src=None, dst=None, sport=None, dport=None):
    """Apply the same edits to a full packet and recompute all checksums
    from scratch, as the reference for the incremental results."""
    from . import dpkt

    ref = ip6.IP6(raw) if raw[0] >> 4 == 6 else ip.IP(raw)
    if src is not None:
        ref.src = _coerce_addr(src, socket.AF_INET6 if isinstance(ref, ip6.IP6) else socket.AF_INET)
    if dst is not None:
        ref.dst = _coerce_addr(dst, socket.AF_INET6 if isinstance(ref, ip6.IP6) else socket.AF_INET)
    l4 = ref.data
    if isinstance(l4, (tcp.TCP, udp.UDP)):
        if sport is not None:
            l4.sport = sport
        if dport is not None:
            l4.dport = dport
        l4.sum = 0
        # full recompute over pseudo-header + transport header + payload
        p = bytes(l4)
        if isinstance(ref, ip6.IP6):
            s = struct.pack('>16s16sxBH', ref.src, ref.dst,
                            getattr(ref, 'p', ref.nxt), len(p))
        else:
            s = struct.pack('>4s4sxBH', ref.src, ref.dst, ref.p, len(p))
        s = dpkt.in_cksum_add(0, s)
        s = dpkt.in_cksum_add(s, p)
        l4.sum = _normalize_sum(dpkt.in_cksum_done(s), isinstance(l4, udp.UDP))
    if isinstance(ref, ip.IP):
        ref.sum = 0
    bytes(ref)
    return ref


def test_cksum_update_matches_full_recompute():
    from . import dpkt

    hdr = bytes(bytearray(range(20)))
    old_sum = dpkt.in_cksum(hdr)
    new_hdr = hdr[:12] + b'\x0a\x00\x00\x63' + hdr[16:]
    segments = [(hdr[12:16], new_hdr[12:16])]
    assert _cksum_update(old_sum, segments) == dpkt.in_cksum(new_hdr)


def test_cksum_update_zero_representations():
    # 0x0000 and 0xffff both represent zero in one's complement arithmetic
    seg = [(b'\x12\x34', b'\x12\x34')]  # no-op change
    assert _cksum_update(0x0000, seg) == 0x0000
    assert _cksum_update(0xffff, seg) == 0x0000
    seg = [(b'\x12\x34', b'\x12\x35')]
    assert _cksum_update(0x0000, seg) == _cksum_update(0xffff, seg)


def test_rewrite_ipv4_tcp():
    raw = _build_tcp4()
    pkt = ip.IP(raw)
    report = rewrite(pkt, src=b'\x0a\x00\x00\x63', dst=b'\x0a\x00\x00\x64',
                     sport=1111, dport=2222)
    assert report == {'src': REWRITTEN, 'dst': REWRITTEN, 'ip_sum': ADJUSTED,
                      'sport': REWRITTEN, 'dport': REWRITTEN, 'transport_sum': ADJUSTED}
    ref = _full_recompute_reference(raw, src=b'\x0a\x00\x00\x63', dst=b'\x0a\x00\x00\x64',
                                    sport=1111, dport=2222)
    assert pkt.sum == ref.sum
    assert pkt.tcp.sum == ref.tcp.sum


def test_rewrite_ipv4_tcp_truncated():
    raw = _build_tcp4()
    full = ip.IP(raw)
    rewrite(full, src=b'\x0a\x00\x00\x63', sport=1111)

    # keep only the IP and TCP headers, drop the whole payload
    trunc = ip.IP(raw[:40])
    assert isinstance(trunc.data, tcp.TCP)
    assert trunc.tcp.data == b''
    report = rewrite(trunc, src=b'\x0a\x00\x00\x63', sport=1111)
    assert report['transport_sum'] == ADJUSTED
    # the incrementally adjusted checksums match the full-packet results
    assert trunc.sum == full.sum
    assert trunc.tcp.sum == full.tcp.sum


def test_rewrite_ipv4_udp_truncated():
    raw = _build_udp4()
    full = ip.IP(raw)
    rewrite(full, dst=b'\x0a\x00\x00\x64', dport=53)

    # keep only the IP and UDP headers
    trunc = ip.IP(raw[:28])
    assert isinstance(trunc.data, udp.UDP)
    report = rewrite(trunc, dst=b'\x0a\x00\x00\x64', dport=53)
    assert report['transport_sum'] == ADJUSTED
    assert trunc.sum == full.sum
    assert trunc.udp.sum == full.udp.sum


def test_rewrite_truncated_transport_header():
    raw = _build_tcp4()

    # cut inside the TCP header: only the ports are still captured
    pkt = ip.IP(raw[:24])
    assert isinstance(pkt.data, bytes)
    report = rewrite(pkt, src=b'\x0a\x00\x00\x63', sport=1111)
    assert report['ip_sum'] == ADJUSTED
    assert report['sport'] == REWRITTEN
    assert report['dport'] == UNCHANGED
    assert report['transport_sum'] == INSUFFICIENT
    assert pkt.data[:2] == struct.pack('>H', 1111)

    # cut inside the TCP header but keep the checksum field
    full = ip.IP(raw)
    rewrite(full, dport=2222)
    pkt = ip.IP(raw[:38])
    assert isinstance(pkt.data, bytes)
    report = rewrite(pkt, dport=2222)
    assert report['dport'] == REWRITTEN
    assert report['transport_sum'] == ADJUSTED
    assert struct.unpack('>H', pkt.data[16:18])[0] == full.tcp.sum


def test_rewrite_truncated_udp_header():
    raw = _build_udp4()

    # 6 bytes of the UDP header captured: ports yes, checksum no
    pkt = ip.IP(raw[:26])
    assert isinstance(pkt.data, bytes)
    report = rewrite(pkt, sport=9999)
    assert report['sport'] == REWRITTEN
    assert report['transport_sum'] == INSUFFICIENT


def test_rewrite_udp_no_checksum():
    # UDP datagram captured with a zero checksum (sender generated none)
    udp_raw = udp.UDP(sport=53, dport=5353, ulen=13, sum=0).pack_hdr() + b'hello'
    pkt = ip.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08',
                p=ip.IP_PROTO_UDP, data=udp_raw)
    raw = bytes(pkt)
    parsed = ip.IP(raw)
    assert parsed.udp.sum == 0
    report = rewrite(parsed, src=b'\x0a\x00\x00\x01', sport=9999)
    assert report['transport_sum'] == NO_CHECKSUM
    assert report['sport'] == REWRITTEN
    assert report['ip_sum'] == ADJUSTED
    # the zero checksum is left untouched, not recomputed or zeroed out
    assert parsed.udp.sum == 0
    assert parsed.udp.sport == 9999


def test_rewrite_udp_negative_zero():
    # a UDP checksum that computes to zero is transmitted as 0xffff (RFC 768)
    u = udp.UDP(sport=1, dport=0xffdb)
    pkt = ip.IP(src=b'\x00\x00\x00\x01', dst=b'\x00\x00\x00\x01',
                p=ip.IP_PROTO_UDP, data=u)
    raw = bytes(pkt)
    parsed = ip.IP(raw)
    assert parsed.udp.sum == 0xffff
    report = rewrite(parsed, sport=2)
    assert report['transport_sum'] == ADJUSTED
    ref = _full_recompute_reference(raw, sport=2)
    assert parsed.udp.sum == ref.udp.sum
    assert parsed.sum == ref.sum


def test_rewrite_ipv4_trailing_fragment():
    pkt = ip.IP(_build_tcp4())
    pkt.offset = 185
    pkt.mf = 1
    pkt.sum = 0
    raw = bytes(pkt)

    frag = ip.IP(raw)
    assert frag.offset == 185
    report = rewrite(frag, src=b'\x0a\x00\x00\x63', sport=1111)
    assert report['src'] == REWRITTEN
    assert report['ip_sum'] == ADJUSTED
    assert report['sport'] == NOT_PRESENT
    assert report['dport'] == NOT_PRESENT
    assert report['transport_sum'] == NOT_PRESENT

    ref = ip.IP(raw)
    ref.src = b'\x0a\x00\x00\x63'
    ref.sum = 0
    bytes(ref)
    assert frag.sum == ref.sum


def test_rewrite_ipv4_first_fragment():
    pkt = ip.IP(_build_tcp4())
    pkt.mf = 1  # offset stays 0: the transport header is present
    pkt.sum = 0
    raw = bytes(pkt)

    frag = ip.IP(raw)
    assert frag.mf == 1 and frag.offset == 0
    report = rewrite(frag, dst=b'\x0a\x00\x00\x64', dport=8080)
    assert report['transport_sum'] == ADJUSTED
    ref = _full_recompute_reference(raw, dst=b'\x0a\x00\x00\x64', dport=8080)
    assert frag.sum == ref.sum
    assert frag.tcp.sum == ref.tcp.sum


def test_rewrite_ipv6_tcp():
    raw = _build_tcp6()
    pkt = ip6.IP6(raw)
    report = rewrite(pkt, src='2001:db8::dead', dport=443)
    assert report == {'src': REWRITTEN, 'dst': UNCHANGED, 'ip_sum': NOT_PRESENT,
                      'sport': UNCHANGED, 'dport': REWRITTEN, 'transport_sum': ADJUSTED}
    ref = _full_recompute_reference(raw, src='2001:db8::dead', dport=443)
    assert pkt.tcp.sum == ref.tcp.sum


def test_rewrite_ipv6_tcp_truncated():
    raw = _build_tcp6()
    full = ip6.IP6(raw)
    rewrite(full, dst='2001:db8::beef', sport=1024)

    trunc = ip6.IP6(raw[:60])  # IPv6 + TCP headers only
    assert isinstance(trunc.data, tcp.TCP)
    report = rewrite(trunc, dst='2001:db8::beef', sport=1024)
    assert report['transport_sum'] == ADJUSTED
    assert trunc.tcp.sum == full.tcp.sum


def test_rewrite_ipv6_fragments():
    raw = _build_tcp6()
    pkt = ip6.IP6(raw)
    payload = raw[40:]

    # first fragment: fragment header with offset 0, transport header present
    frag_hdr = ip6.IP6FragmentHeader(nxt=ip.IP_PROTO_TCP, id=0x1234)
    frag_hdr.m_flag = 1
    first = ip6.IP6(src=pkt.src, dst=pkt.dst, nxt=ip.IP_PROTO_FRAGMENT,
                    data=bytes(frag_hdr) + payload)
    first.plen = len(first.data)
    first_raw = bytes(first)
    f1 = ip6.IP6(first_raw)
    assert f1.all_extension_headers[0].frag_off == 0
    report = rewrite(f1, sport=999)
    assert report['transport_sum'] == ADJUSTED
    assert report['sport'] == REWRITTEN
    ref = _full_recompute_reference(first_raw, sport=999)
    assert f1.tcp.sum == ref.tcp.sum

    # trailing fragment: no transport header in this packet
    frag_hdr = ip6.IP6FragmentHeader(nxt=ip.IP_PROTO_TCP, id=0x1234)
    frag_hdr.frag_off = 8
    frag_hdr.m_flag = 1
    rest = ip6.IP6(src=pkt.src, dst=pkt.dst, nxt=ip.IP_PROTO_FRAGMENT,
                   data=bytes(frag_hdr) + payload[64:])
    rest.plen = len(rest.data)
    f2 = ip6.IP6(bytes(rest))
    report = rewrite(f2, src='2001:db8::dead', sport=999)
    assert report['src'] == REWRITTEN
    assert report['sport'] == NOT_PRESENT
    assert report['dport'] == NOT_PRESENT
    assert report['transport_sum'] == NOT_PRESENT


def test_rewrite_non_tcp_udp():
    pkt = ip.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08',
                p=ip.IP_PROTO_ICMP, data=b'\x08\x00\xf7\xff' + b'\x00' * 8)
    raw = bytes(pkt)
    parsed = ip.IP(raw)
    report = rewrite(parsed, src=b'\x0a\x00\x00\x01', sport=1)
    assert report['ip_sum'] == ADJUSTED
    assert report['sport'] == NOT_PRESENT
    assert report['dport'] == NOT_PRESENT
    assert report['transport_sum'] == NOT_PRESENT


def test_rewrite_noop_request():
    raw = _build_tcp4()
    pkt = ip.IP(raw)
    report = rewrite(pkt)
    assert report == {'src': UNCHANGED, 'dst': UNCHANGED, 'ip_sum': UNCHANGED,
                      'sport': UNCHANGED, 'dport': UNCHANGED, 'transport_sum': UNCHANGED}
    assert bytes(pkt) == raw


def test_rewrite_bad_input():
    from . import ethernet

    try:
        rewrite(ethernet.Ethernet())
    except TypeError:
        pass
    else:
        raise AssertionError('expected TypeError')

    pkt = ip.IP(_build_tcp4())
    try:
        rewrite(pkt, src=b'\x01\x02')  # wrong address length
    except ValueError:
        pass
    else:
        raise AssertionError('expected ValueError')
