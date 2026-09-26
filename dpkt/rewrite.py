# -*- coding: utf-8 -*-
"""Incremental rewriting of IP/TCP/UDP header fields.

Captures are often truncated to the first few dozen bytes, so the payload
needed to recompute a transport checksum from scratch is not always
available.  This module rewrites IPv4/IPv6 addresses and TCP/UDP ports in
place and adjusts the affected checksums *incrementally* (RFC 1624), using
only the original checksum and the words that changed, so a missing payload
never has to be read.

Each call to rewrite_packet() returns a RewriteResult telling the caller
which fields were actually rewritten, how every affected checksum was
handled, and which requested changes were skipped because the capture does
not contain enough information to apply them.
"""
from __future__ import absolute_import

import struct

from . import ip
from . import ip6
from . import tcp
from . import udp

# Checksum handling outcomes, as reported in RewriteResult.checksums:
CKSUM_ADJUSTED = 'adjusted'  # checksum updated incrementally and remains valid
CKSUM_ABSENT = 'absent'  # the original packet carried no checksum (UDP sum == 0); left untouched
CKSUM_INSUFFICIENT = 'insufficient'  # the capture lacks the data needed to adjust; left untouched

_PORT_MAX = 65535


class RewriteResult(object):
    """Outcome of a rewrite_packet() call.

    Attributes:
        rewritten (dict): {field name: (old value, new value)} for every
            field that was actually rewritten ('src', 'dst', 'sport', 'dport').
        checksums (dict): {checksum name: CKSUM_*} describing how each
            affected checksum ('ip', 'tcp', 'udp') was handled.
        skipped (dict): {field name: reason} for requested changes that were
            not applied because the capture lacks the required bytes.
    """

    def __init__(self):
        self.rewritten = {}
        self.checksums = {}
        self.skipped = {}

    def __repr__(self):
        return '%s(rewritten=%r, checksums=%r, skipped=%r)' % (
            self.__class__.__name__, self.rewritten, self.checksums, self.skipped)


def _cksum_adjust(sum_, old, new):
    """Incrementally update a 16-bit one's-complement checksum (RFC 1624).

    Args:
        sum_: the original checksum as a 16-bit integer in network byte order.
        old: bytes covered by sum_ that are being replaced.
        new: the replacement bytes; must be the same (even) length as old.

    Returns:
        The adjusted checksum.  Both 0x0000 and 0xffff may represent a zero
        one's-complement sum; callers normalize as the protocol requires.
    """
    if len(old) != len(new) or len(old) % 2:
        raise ValueError('old and new must have the same, even, length')
    s = ~sum_ & 0xffff
    for i in range(0, len(old), 2):
        s += 0xffff - struct.unpack('>H', old[i:i + 2])[0]
        s += struct.unpack('>H', new[i:i + 2])[0]
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def _skip_ports(sport, dport, result, reason):
    if sport is not None:
        result.skipped['sport'] = reason
    if dport is not None:
        result.skipped['dport'] = reason


def _adjust_transport(tpkt, name, addr_old, addr_new, sport, dport, result):
    """Rewrite ports on a parsed TCP/UDP header and fix its checksum."""
    old = addr_old
    new = addr_new
    if sport is not None:
        result.rewritten['sport'] = (tpkt.sport, sport)
        old += struct.pack('>H', tpkt.sport)
        new += struct.pack('>H', sport)
        tpkt.sport = sport
    if dport is not None:
        result.rewritten['dport'] = (tpkt.dport, dport)
        old += struct.pack('>H', tpkt.dport)
        new += struct.pack('>H', dport)
        tpkt.dport = dport
    if not old:
        return
    if isinstance(tpkt, udp.UDP) and tpkt.sum == 0:
        # RFC 768: a zero UDP checksum means the sender computed none; there
        # is nothing to adjust and it must not be replaced with a computed
        # value.
        result.checksums[name] = CKSUM_ABSENT
        return
    sum_ = _cksum_adjust(tpkt.sum, old, new)
    if isinstance(tpkt, udp.UDP) and sum_ == 0:
        # RFC 768: a computed zero checksum is transmitted as all ones (the
        # negative zero of one's-complement arithmetic).
        sum_ = 0xffff
    tpkt.sum = sum_
    result.checksums[name] = CKSUM_ADJUSTED


def _transport_name(p):
    if p == ip.IP_PROTO_TCP:
        return 'tcp'
    if p == ip.IP_PROTO_UDP:
        return 'udp'
    return None


def _rewrite_ipv4(pkt, src, dst, sport, dport, result):
    addr_old = b''
    addr_new = b''
    if src is not None:
        result.rewritten['src'] = (pkt.src, src)
        addr_old += pkt.src
        addr_new += src
        pkt.src = src
    if dst is not None:
        result.rewritten['dst'] = (pkt.dst, dst)
        addr_old += pkt.dst
        addr_new += dst
        pkt.dst = dst
    if addr_old:
        pkt.sum = _cksum_adjust(pkt.sum, addr_old, addr_new)
        result.checksums['ip'] = CKSUM_ADJUSTED

    name = _transport_name(pkt.p)
    if name is None:
        _skip_ports(sport, dport, result, 'not a TCP/UDP packet')
        return
    if pkt._flags_offset & ip.IP_OFFMASK:
        # Non-first fragment: the transport header (and its checksum) lives
        # in the first fragment, which this capture does not contain.
        if addr_old or sport is not None or dport is not None:
            result.checksums[name] = CKSUM_INSUFFICIENT
        _skip_ports(sport, dport, result, 'transport header is in another fragment')
        return
    if not isinstance(pkt.data, (tcp.TCP, udp.UDP)):
        # Capture was truncated before the transport header was complete.
        if addr_old or sport is not None or dport is not None:
            result.checksums[name] = CKSUM_INSUFFICIENT
        _skip_ports(sport, dport, result, 'transport header not captured')
        return
    _adjust_transport(pkt.data, name, addr_old, addr_new, sport, dport, result)


def _rewrite_ipv6(pkt, src, dst, sport, dport, result):
    addr_old = b''
    addr_new = b''
    if src is not None:
        result.rewritten['src'] = (pkt.src, src)
        addr_old += pkt.src
        addr_new += src
        pkt.src = src
    if dst is not None:
        result.rewritten['dst'] = (pkt.dst, dst)
        addr_old += pkt.dst
        addr_new += dst
        pkt.dst = dst
    # IPv6 has no header checksum; only the transport pseudo-header is
    # affected by an address change.

    name = _transport_name(getattr(pkt, 'p', None))
    if name is None:
        _skip_ports(sport, dport, result, 'not a TCP/UDP packet')
        return
    exts = getattr(pkt, 'all_extension_headers', None)
    if exts is None:
        exts = getattr(pkt, 'extension_hdrs', {}).values()
    frag = None
    for ext in exts:
        if isinstance(ext, ip6.IP6FragmentHeader):
            frag = ext
            break
    if frag is not None and frag.frag_off > 0:
        # Non-first fragment: the transport header is in the first fragment.
        if addr_old or sport is not None or dport is not None:
            result.checksums[name] = CKSUM_INSUFFICIENT
        _skip_ports(sport, dport, result, 'transport header is in another fragment')
        return
    if not isinstance(pkt.data, (tcp.TCP, udp.UDP)):
        # Capture was truncated before the transport header was complete.
        if addr_old or sport is not None or dport is not None:
            result.checksums[name] = CKSUM_INSUFFICIENT
        _skip_ports(sport, dport, result, 'transport header not captured')
        return
    _adjust_transport(pkt.data, name, addr_old, addr_new, sport, dport, result)


def rewrite_packet(pkt, src=None, dst=None, sport=None, dport=None):
    """Rewrite addresses and/or ports of an IP or IP6 packet in place.

    Checksums affected by the rewrite are adjusted incrementally (RFC 1624)
    from their original values, so this works on truncated captures whose
    payload is partially or wholly missing.  Checksums are never blindly
    zeroed: a checksum that cannot be adjusted is left untouched and
    reported as CKSUM_INSUFFICIENT, and an absent UDP checksum (sum == 0)
    is preserved and reported as CKSUM_ABSENT.

    Args:
        pkt: an ip.IP or ip6.IP6 packet (modified in place).
        src: new source address (4 bytes for IPv4, 16 for IPv6), or None.
        dst: new destination address, or None.
        sport: new TCP/UDP source port, or None.
        dport: new TCP/UDP destination port, or None.

    Returns:
        A RewriteResult describing the fields rewritten, the checksum
        outcomes, and the requested changes skipped for lack of data.
    """
    if isinstance(pkt, ip.IP):
        addr_len = 4
    elif isinstance(pkt, ip6.IP6):
        addr_len = 16
    else:
        raise TypeError('expected an IP or IP6 packet, got %r' % (type(pkt),))
    for addr in (src, dst):
        if addr is not None and len(addr) != addr_len:
            raise ValueError('address must be %d bytes, got %d' % (addr_len, len(addr)))
    for port in (sport, dport):
        if port is not None and not 0 <= port <= _PORT_MAX:
            raise ValueError('invalid port %r' % (port,))

    result = RewriteResult()
    if addr_len == 4:
        _rewrite_ipv4(pkt, src, dst, sport, dport, result)
    else:
        _rewrite_ipv6(pkt, src, dst, sport, dport, result)
    return result


# Unit tests

_SRC4 = b'\x0a\x00\x00\x01'
_DST4 = b'\x0a\x00\x00\x02'
_NEW_SRC4 = b'\xc0\xa8\x00\x01'
_NEW_DST4 = b'\xc0\xa8\x00\x02'
_SRC6 = b'\x20\x01\x0d\xb8' + b'\x00' * 10 + b'\x00\x01'
_DST6 = b'\x20\x01\x0d\xb8' + b'\x00' * 10 + b'\x00\x02'
_NEW_SRC6 = b'\x20\x01\x0d\xb8' + b'\x00' * 10 + b'\x00\x11'
_NEW_DST6 = b'\x20\x01\x0d\xb8' + b'\x00' * 10 + b'\x00\x12'
_PAYLOAD = b'anonymize this payload!'


def _mk_tcp4():
    t = tcp.TCP(sport=1234, dport=80, seq=100, ack=200, flags=tcp.TH_ACK | tcp.TH_PUSH)
    t.data = _PAYLOAD
    pkt = ip.IP(src=_SRC4, dst=_DST4, p=ip.IP_PROTO_TCP, data=t)
    pkt.sum = 0
    t.sum = 0
    return bytes(pkt)


def _mk_udp4():
    u = udp.UDP(sport=53, dport=5353)
    u.data = _PAYLOAD
    u.ulen += len(u.data)
    pkt = ip.IP(src=_SRC4, dst=_DST4, p=ip.IP_PROTO_UDP, data=u)
    pkt.sum = 0
    u.sum = 0
    return bytes(pkt)


def _mk_tcp6():
    t = tcp.TCP(sport=1234, dport=80, seq=100, ack=200, flags=tcp.TH_ACK | tcp.TH_PUSH)
    t.data = _PAYLOAD
    pkt = ip6.IP6(src=_SRC6, dst=_DST6, nxt=ip.IP_PROTO_TCP, data=t)
    pkt.plen = len(t)
    t.sum = 0
    return bytes(pkt)


def _mk_udp6():
    u = udp.UDP(sport=53, dport=5353)
    u.data = _PAYLOAD
    u.ulen += len(u.data)
    pkt = ip6.IP6(src=_SRC6, dst=_DST6, nxt=ip.IP_PROTO_UDP, data=u)
    pkt.plen = len(u)
    u.sum = 0
    return bytes(pkt)


def _mk_tcp6_frag(frag_off=0):
    t = tcp.TCP(sport=1234, dport=80, seq=100, ack=200, flags=tcp.TH_ACK | tcp.TH_PUSH)
    t.data = _PAYLOAD
    fh = ip6.IP6FragmentHeader(nxt=ip.IP_PROTO_TCP, id=0x1234)
    fh.frag_off = frag_off
    fh.m_flag = 1
    pkt = ip6.IP6(src=_SRC6, dst=_DST6, nxt=ip.IP_PROTO_FRAGMENT, data=t)
    pkt.extension_hdrs = {ip.IP_PROTO_FRAGMENT: fh}
    pkt.plen = len(fh) + len(t)
    t.sum = 0
    return bytes(pkt)


def _reference4(buf, src=None, dst=None, sport=None, dport=None):
    # full checksum recomputation over the complete packet, as a reference
    pkt = ip.IP(buf)
    if src is not None:
        pkt.src = src
    if dst is not None:
        pkt.dst = dst
    if sport is not None:
        pkt.data.sport = sport
    if dport is not None:
        pkt.data.dport = dport
    pkt.sum = 0
    pkt.data.sum = 0
    out = ip.IP(bytes(pkt))
    return out.sum, out.data.sum


def _reference6(buf, src=None, dst=None, sport=None, dport=None):
    pkt = ip6.IP6(buf)
    if src is not None:
        pkt.src = src
    if dst is not None:
        pkt.dst = dst
    if sport is not None:
        pkt.data.sport = sport
    if dport is not None:
        pkt.data.dport = dport
    pkt.data.sum = 0
    out = ip6.IP6(bytes(pkt))
    return out.data.sum


def test_cksum_adjust_matches_full_recompute():
    from . import dpkt

    base = bytes(bytearray(range(32)))
    mod = base[:4] + b'\xde\xad' + base[6:20] + b'\xbe\xef' + base[22:]
    s1 = dpkt.in_cksum(base)
    s2 = dpkt.in_cksum(mod)
    adj = _cksum_adjust(s1, base[4:6] + base[20:22], b'\xde\xad\xbe\xef')
    assert adj == s2 or (adj in (0, 0xffff) and s2 in (0, 0xffff))

    # negative zero input (0xffff) is equivalent to positive zero; a zero
    # result may be represented as either 0x0000 or 0xffff
    assert _cksum_adjust(0xffff, b'\x00\x01', b'\x00\x01') in (0, 0xffff)

    import pytest
    with pytest.raises(ValueError):
        _cksum_adjust(0, b'\x00', b'\x00')


def test_rewrite_ipv4_tcp():
    buf = _mk_tcp4()
    ref_sum, ref_tsum = _reference4(buf, src=_NEW_SRC4, dst=_NEW_DST4, sport=4444, dport=8080)

    pkt = ip.IP(buf)
    res = rewrite_packet(pkt, src=_NEW_SRC4, dst=_NEW_DST4, sport=4444, dport=8080)
    assert pkt.src == _NEW_SRC4
    assert pkt.dst == _NEW_DST4
    assert pkt.tcp.sport == 4444
    assert pkt.tcp.dport == 8080
    assert pkt.sum == ref_sum
    assert pkt.tcp.sum == ref_tsum
    assert res.checksums == {'ip': CKSUM_ADJUSTED, 'tcp': CKSUM_ADJUSTED}
    assert set(res.rewritten) == {'src', 'dst', 'sport', 'dport'}
    assert res.rewritten['src'] == (_SRC4, _NEW_SRC4)
    assert res.rewritten['dport'] == (80, 8080)
    assert not res.skipped

    # the same packet truncated to the IP + TCP headers must produce
    # identical checksum fields without reading the missing payload
    tpkt = ip.IP(buf[:40])
    res = rewrite_packet(tpkt, src=_NEW_SRC4, dst=_NEW_DST4, sport=4444, dport=8080)
    assert tpkt.sum == ref_sum
    assert tpkt.tcp.sum == ref_tsum
    assert res.checksums == {'ip': CKSUM_ADJUSTED, 'tcp': CKSUM_ADJUSTED}


def test_rewrite_ipv4_udp():
    buf = _mk_udp4()
    ref_sum, ref_usum = _reference4(buf, src=_NEW_SRC4, dport=53)

    pkt = ip.IP(buf)
    res = rewrite_packet(pkt, src=_NEW_SRC4, dport=53)
    assert pkt.sum == ref_sum
    assert pkt.udp.sum == ref_usum
    assert res.checksums == {'ip': CKSUM_ADJUSTED, 'udp': CKSUM_ADJUSTED}

    # truncated capture: identical checksum fields
    tpkt = ip.IP(buf[:28])
    res = rewrite_packet(tpkt, src=_NEW_SRC4, dport=53)
    assert tpkt.sum == ref_sum
    assert tpkt.udp.sum == ref_usum


def test_rewrite_ipv4_udp_no_checksum():
    # a zero UDP checksum means the sender computed none; it must be preserved
    buf = bytearray(_mk_udp4())
    buf[26:28] = b'\x00\x00'  # UDP sum field
    pkt = ip.IP(bytes(buf))
    assert pkt.udp.sum == 0

    res = rewrite_packet(pkt, src=_NEW_SRC4, sport=9999)
    assert pkt.udp.sum == 0
    assert pkt.udp.sport == 9999
    assert res.checksums['ip'] == CKSUM_ADJUSTED
    assert res.checksums['udp'] == CKSUM_ABSENT
    assert set(res.rewritten) == {'src', 'sport'}
    assert not res.skipped


def test_rewrite_udp_negative_zero():
    # a computed UDP checksum of zero is transmitted as 0xffff (RFC 768)
    u = udp.UDP(sport=2, dport=0xffdb)
    pkt = ip.IP(src=b'\x00\x00\x00\x01', dst=b'\x00\x00\x00\x01', p=ip.IP_PROTO_UDP, data=u)
    pkt.sum = 0
    u.sum = 0
    buf = bytes(pkt)

    parsed = ip.IP(buf)
    assert parsed.udp.sum != 0
    res = rewrite_packet(parsed, sport=1)
    # with sport=1 the checksum evaluates to zero and must become 0xffff
    assert parsed.udp.sum == 0xffff
    assert res.checksums['udp'] == CKSUM_ADJUSTED


def test_rewrite_ipv4_first_fragment():
    buf = _mk_tcp4()
    pkt = ip.IP(buf)
    pkt.mf = 1
    pkt.sum = 0
    fbuf = bytes(pkt)  # ip sum recomputed; tcp sum kept (MF set)

    fpkt = ip.IP(fbuf)
    assert fpkt.mf == 1 and fpkt.offset == 0
    res = rewrite_packet(fpkt, src=_NEW_SRC4, dport=8080)
    # the transport checksum matches the unfragmented full-recompute reference
    _, ref_tsum = _reference4(buf, src=_NEW_SRC4, dport=8080)
    assert fpkt.tcp.sum == ref_tsum
    assert res.checksums == {'ip': CKSUM_ADJUSTED, 'tcp': CKSUM_ADJUSTED}
    assert not res.skipped

    # truncated first fragment: identical checksum fields
    tpkt = ip.IP(fbuf[:40])
    res = rewrite_packet(tpkt, src=_NEW_SRC4, dport=8080)
    assert tpkt.sum == fpkt.sum
    assert tpkt.tcp.sum == ref_tsum


def test_rewrite_ipv4_nonfirst_fragment():
    buf = _mk_tcp4()
    pkt = ip.IP(buf)
    pkt.offset = 1480
    pkt.mf = 1
    pkt.sum = 0
    fbuf = bytes(pkt)

    fpkt = ip.IP(fbuf)
    assert fpkt.offset == 1480
    assert isinstance(fpkt.data, bytes)

    res = rewrite_packet(fpkt, src=_NEW_SRC4, sport=1)
    # the IPv4 header checksum is adjusted, but the transport header (and its
    # checksum) is in the first fragment and cannot be handled here
    assert res.checksums['ip'] == CKSUM_ADJUSTED
    assert res.checksums['tcp'] == CKSUM_INSUFFICIENT
    assert 'sport' in res.skipped
    assert set(res.rewritten) == {'src'}

    # the adjusted ip checksum matches a full header recomputation
    ref = ip.IP(fbuf)
    ref.src = _NEW_SRC4
    ref.sum = 0
    assert fpkt.sum == ip.IP(bytes(ref)).sum


def test_rewrite_ipv4_truncated_transport_header():
    buf = _mk_tcp4()
    pkt = ip.IP(buf[:30])  # IP header + 10 bytes of TCP header
    assert isinstance(pkt.data, bytes)

    res = rewrite_packet(pkt, src=_NEW_SRC4, sport=1)
    assert res.checksums['ip'] == CKSUM_ADJUSTED
    assert res.checksums['tcp'] == CKSUM_INSUFFICIENT
    assert 'sport' in res.skipped
    assert set(res.rewritten) == {'src'}

    # the ip checksum still matches the full-packet reference
    ref_sum, _ = _reference4(buf, src=_NEW_SRC4)
    assert pkt.sum == ref_sum


def test_rewrite_ipv6_tcp():
    buf = _mk_tcp6()
    ref_tsum = _reference6(buf, src=_NEW_SRC6, dst=_NEW_DST6, sport=4444, dport=8080)

    pkt = ip6.IP6(buf)
    res = rewrite_packet(pkt, src=_NEW_SRC6, dst=_NEW_DST6, sport=4444, dport=8080)
    assert pkt.src == _NEW_SRC6
    assert pkt.tcp.sum == ref_tsum
    assert res.checksums == {'tcp': CKSUM_ADJUSTED}  # no IPv6 header checksum
    assert set(res.rewritten) == {'src', 'dst', 'sport', 'dport'}
    assert not res.skipped

    # truncated capture (IPv6 + TCP headers only): identical checksum field
    tpkt = ip6.IP6(buf[:60])
    res = rewrite_packet(tpkt, src=_NEW_SRC6, dst=_NEW_DST6, sport=4444, dport=8080)
    assert tpkt.tcp.sum == ref_tsum


def test_rewrite_ipv6_udp():
    buf = _mk_udp6()
    ref_usum = _reference6(buf, dst=_NEW_DST6)

    pkt = ip6.IP6(buf)
    res = rewrite_packet(pkt, dst=_NEW_DST6)
    assert pkt.udp.sum == ref_usum
    assert res.checksums == {'udp': CKSUM_ADJUSTED}

    tpkt = ip6.IP6(buf[:48])
    res = rewrite_packet(tpkt, dst=_NEW_DST6)
    assert tpkt.udp.sum == ref_usum


def test_rewrite_ipv6_first_fragment():
    buf = _mk_tcp6_frag(frag_off=0)
    pkt = ip6.IP6(buf)
    assert pkt.p == ip.IP_PROTO_TCP
    assert isinstance(pkt.data, tcp.TCP)

    res = rewrite_packet(pkt, src=_NEW_SRC6)
    ref_tsum = _reference6(_mk_tcp6(), src=_NEW_SRC6)
    assert pkt.tcp.sum == ref_tsum
    assert res.checksums == {'tcp': CKSUM_ADJUSTED}
    assert not res.skipped


def test_rewrite_ipv6_nonfirst_fragment():
    buf = _mk_tcp6_frag(frag_off=185)
    pkt = ip6.IP6(buf)
    assert isinstance(pkt.data, bytes)

    res = rewrite_packet(pkt, src=_NEW_SRC6, dport=1)
    assert res.checksums['tcp'] == CKSUM_INSUFFICIENT
    assert 'dport' in res.skipped
    assert set(res.rewritten) == {'src'}
    assert 'ip' not in res.checksums  # IPv6 has no header checksum


def test_rewrite_not_tcp_udp():
    from . import icmp

    pkt = ip.IP(src=_SRC4, dst=_DST4, p=ip.IP_PROTO_ICMP, data=icmp.ICMP())
    pkt.sum = 0
    buf = bytes(pkt)
    parsed = ip.IP(buf)
    res = rewrite_packet(parsed, src=_NEW_SRC4, sport=1)
    assert res.checksums == {'ip': CKSUM_ADJUSTED}
    assert 'sport' in res.skipped
    assert set(res.rewritten) == {'src'}


def test_rewrite_errors():
    import pytest

    pkt = ip.IP(_mk_tcp4())
    with pytest.raises(ValueError):
        rewrite_packet(pkt, src=b'\x01\x02\x03')
    with pytest.raises(ValueError):
        rewrite_packet(pkt, sport=70000)
    with pytest.raises(TypeError):
        rewrite_packet(object(), src=_NEW_SRC4)

    pkt6 = ip6.IP6(_mk_tcp6())
    with pytest.raises(ValueError):
        rewrite_packet(pkt6, dst=b'\x01\x02\x03\x04')


def test_rewrite_result_repr():
    res = RewriteResult()
    assert 'rewritten={}' in repr(res)
