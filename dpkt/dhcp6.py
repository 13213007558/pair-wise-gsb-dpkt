# -*- coding: utf-8 -*-
"""Dynamic Host Configuration Protocol for IPv6 (DHCPv6, RFC 8415)."""
from __future__ import absolute_import
from __future__ import print_function

import struct

from . import dpkt
from .compat import compat_ord

# DHCPv6 message types
DHCP6_SOLICIT = 1
DHCP6_ADVERTISE = 2
DHCP6_REQUEST = 3
DHCP6_CONFIRM = 4
DHCP6_RENEW = 5
DHCP6_REBIND = 6
DHCP6_REPLY = 7
DHCP6_RELEASE = 8
DHCP6_DECLINE = 9
DHCP6_RECONFIGURE = 10
DHCP6_INFORMATION_REQUEST = 11
DHCP6_RELAY_FORW = 12
DHCP6_RELAY_REPL = 13

# DHCPv6 option codes
DHCP6_OPT_CLIENTID = 1
DHCP6_OPT_SERVERID = 2
DHCP6_OPT_IA_NA = 3
DHCP6_OPT_IA_TA = 4
DHCP6_OPT_IAADDR = 5
DHCP6_OPT_ORO = 6
DHCP6_OPT_PREFERENCE = 7
DHCP6_OPT_ELAPSED_TIME = 8
DHCP6_OPT_RELAY_MSG = 9
DHCP6_OPT_AUTH = 11
DHCP6_OPT_UNICAST = 12
DHCP6_OPT_STATUS_CODE = 13
DHCP6_OPT_RAPID_COMMIT = 14
DHCP6_OPT_USER_CLASS = 15
DHCP6_OPT_VENDOR_CLASS = 16
DHCP6_OPT_VENDOR_OPTS = 17
DHCP6_OPT_INTERFACE_ID = 18
DHCP6_OPT_RECONF_MSG = 19
DHCP6_OPT_RECONF_ACCEPT = 20
DHCP6_OPT_IA_PD = 25
DHCP6_OPT_IAPREFIX = 26

# DUID types
DHCP6_DUID_LLT = 1  # link-layer address plus time
DHCP6_DUID_EN = 2  # vendor-assigned unique ID based on enterprise number
DHCP6_DUID_LL = 3  # link-layer address
DHCP6_DUID_UUID = 4  # universally unique identifier


class DHCP6SemanticError(dpkt.Error):
    """Semantic anomaly detected in a DHCPv6 message.

    Parsing never rewrites suspicious values (e.g. a preferred lifetime
    greater than the valid lifetime); they are kept as-is for inspection
    and reported through validate() instead.
    """


class DUID(dpkt.Packet):
    """DHCP Unique Identifier (DUID).

    Attributes:
        __hdr__: Header fields of DUID.
            type: (int): DUID type, one of DHCP6_DUID_*. (2 bytes)
        data: (bytes): Type-dependent identifier body (hardware type,
            time, enterprise number, link-layer address, UUID, ...).
    """

    __hdr__ = (
        ('type', 'H', DHCP6_DUID_LLT),
    )


class DHCP6Option(dpkt.Packet):
    """DHCPv6 option.

    Attributes:
        __hdr__: Header fields of DHCP6Option.
            code: (int): Option code. (2 bytes)
            len: (int): Length of the option value in bytes, recomputed
                from the actual payload when packing. (2 bytes)
        value: (bytes): Raw option payload. Structured subclasses parse
            it into dedicated attributes; unknown options keep the raw
            bytes here so they round-trip unchanged.
    """

    __hdr__ = (
        ('code', 'H', 0),
        ('len', 'H', 0),
    )
    value = b''

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if len(self.data) < self.len:
            raise dpkt.NeedData(
                'DHCPv6 option %d: got %d bytes, %d expected' % (self.code, len(self.data), self.len))
        # the declared length strictly bounds the sub-parsing scope
        self.value = self.data[:self.len]
        self.data = self.data[self.len:]
        self.unpack_value(self.value)

    def unpack_value(self, value):
        """Hook for structured options to parse their payload."""

    def pack_value(self):
        return self.value

    def validate(self):
        """Return a list of DHCP6SemanticError anomalies (empty if sane)."""
        return []

    def __len__(self):
        return self.__hdr_len__ + len(self.pack_value())

    def __bytes__(self):
        value = self.pack_value()
        self.len = len(value)
        return self.pack_hdr() + value


class DHCP6DUIDOption(DHCP6Option):
    """Base for Client ID / Server ID options carrying a DUID."""

    duid = None

    def unpack_value(self, value):
        self.duid = DUID(value)

    def pack_value(self):
        if self.duid is not None:
            return bytes(self.duid)
        return self.value


class DHCP6ClientIdOption(DHCP6DUIDOption):
    __hdr__ = (
        ('code', 'H', DHCP6_OPT_CLIENTID),
        ('len', 'H', 0),
    )


class DHCP6ServerIdOption(DHCP6DUIDOption):
    __hdr__ = (
        ('code', 'H', DHCP6_OPT_SERVERID),
        ('len', 'H', 0),
    )


class DHCP6IAOption(DHCP6Option):
    """Base for identity association options (IA_NA / IA_PD).

    Attributes:
        iaid: (int): Identity association identifier. (4 bytes)
        t1: (int): Time until the client contacts the server to extend
            lifetimes, in seconds. (4 bytes)
        t2: (int): Time until the client contacts any server to extend
            lifetimes, in seconds. (4 bytes)
        opts: (list): Sub-options (IAADDR / IAPREFIX / unknown), kept in
            wire order, duplicates included.
    """

    iaid = 0
    t1 = 0
    t2 = 0
    opts = ()

    def unpack_value(self, value):
        if len(value) < 12:
            raise dpkt.NeedData('DHCPv6 IA option: got %d bytes, 12 needed at least' % len(value))
        self.iaid, self.t1, self.t2 = struct.unpack('>III', value[:12])
        self.opts = _parse_options(value[12:])

    def pack_value(self):
        return struct.pack('>III', self.iaid, self.t1, self.t2) + _pack_options(self.opts)

    def validate(self):
        return _validate_options(self.opts)


class DHCP6IANAOption(DHCP6IAOption):
    """Identity Association for Non-temporary Addresses (IA_NA)."""

    __hdr__ = (
        ('code', 'H', DHCP6_OPT_IA_NA),
        ('len', 'H', 0),
    )


class DHCP6IAPDOption(DHCP6IAOption):
    """Identity Association for Prefix Delegation (IA_PD)."""

    __hdr__ = (
        ('code', 'H', DHCP6_OPT_IA_PD),
        ('len', 'H', 0),
    )


class DHCP6IAAddrOption(DHCP6Option):
    """IA Address option: an IPv6 address with its lifetimes.

    Attributes:
        addr: (bytes): IPv6 address. (16 bytes)
        preferred_lifetime: (int): Preferred lifetime in seconds. (4 bytes)
        valid_lifetime: (int): Valid lifetime in seconds. (4 bytes)
        opts: (list): Sub-options, kept in wire order.
    """

    __hdr__ = (
        ('code', 'H', DHCP6_OPT_IAADDR),
        ('len', 'H', 0),
    )
    addr = b'\x00' * 16
    preferred_lifetime = 0
    valid_lifetime = 0
    opts = ()

    def unpack_value(self, value):
        if len(value) < 24:
            raise dpkt.NeedData('DHCPv6 IAADDR option: got %d bytes, 24 needed at least' % len(value))
        self.addr = value[:16]
        self.preferred_lifetime, self.valid_lifetime = struct.unpack('>II', value[16:24])
        self.opts = _parse_options(value[24:])

    def pack_value(self):
        return self.addr + struct.pack('>II', self.preferred_lifetime, self.valid_lifetime) + \
            _pack_options(self.opts)

    def validate(self):
        errors = _validate_options(self.opts)
        if self.preferred_lifetime > self.valid_lifetime:
            errors.append(DHCP6SemanticError(
                'IAADDR %r: preferred lifetime %d exceeds valid lifetime %d' % (
                    self.addr, self.preferred_lifetime, self.valid_lifetime)))
        return errors


class DHCP6IAPrefixOption(DHCP6Option):
    """IA Prefix option: a delegated IPv6 prefix with its lifetimes.

    Attributes:
        preferred_lifetime: (int): Preferred lifetime in seconds. (4 bytes)
        valid_lifetime: (int): Valid lifetime in seconds. (4 bytes)
        prefix_len: (int): Prefix length in bits. (1 byte)
        prefix: (bytes): IPv6 prefix. (16 bytes)
        opts: (list): Sub-options, kept in wire order.
    """

    __hdr__ = (
        ('code', 'H', DHCP6_OPT_IAPREFIX),
        ('len', 'H', 0),
    )
    preferred_lifetime = 0
    valid_lifetime = 0
    prefix_len = 0
    prefix = b'\x00' * 16
    opts = ()

    def unpack_value(self, value):
        if len(value) < 25:
            raise dpkt.NeedData('DHCPv6 IAPREFIX option: got %d bytes, 25 needed at least' % len(value))
        self.preferred_lifetime, self.valid_lifetime = struct.unpack('>II', value[:8])
        self.prefix_len = compat_ord(value[8])
        self.prefix = value[9:25]
        self.opts = _parse_options(value[25:])

    def pack_value(self):
        return struct.pack('>IIB', self.preferred_lifetime, self.valid_lifetime, self.prefix_len) + \
            self.prefix + _pack_options(self.opts)

    def validate(self):
        errors = _validate_options(self.opts)
        if self.preferred_lifetime > self.valid_lifetime:
            errors.append(DHCP6SemanticError(
                'IAPREFIX %r/%d: preferred lifetime %d exceeds valid lifetime %d' % (
                    self.prefix, self.prefix_len, self.preferred_lifetime, self.valid_lifetime)))
        return errors


class DHCP6RelayMsgOption(DHCP6Option):
    """Relay Message option: a full DHCPv6 message, parsed recursively."""

    __hdr__ = (
        ('code', 'H', DHCP6_OPT_RELAY_MSG),
        ('len', 'H', 0),
    )
    message = None

    def unpack_value(self, value):
        self.message = parse(value)

    def pack_value(self):
        if self.message is not None:
            return bytes(self.message)
        return self.value

    def validate(self):
        if self.message is not None:
            return self.message.validate()
        return []


_option_classes = {
    DHCP6_OPT_CLIENTID: DHCP6ClientIdOption,
    DHCP6_OPT_SERVERID: DHCP6ServerIdOption,
    DHCP6_OPT_IA_NA: DHCP6IANAOption,
    DHCP6_OPT_IAADDR: DHCP6IAAddrOption,
    DHCP6_OPT_RELAY_MSG: DHCP6RelayMsgOption,
    DHCP6_OPT_IA_PD: DHCP6IAPDOption,
    DHCP6_OPT_IAPREFIX: DHCP6IAPrefixOption,
}


def _parse_options(buf):
    """Parse a buffer into a list of DHCP6Option, preserving order and duplicates."""
    opts = []
    while buf:
        if len(buf) < 4:
            raise dpkt.NeedData('truncated DHCPv6 option header: %r' % (buf,))
        code = struct.unpack('>H', buf[:2])[0]
        opt = _option_classes.get(code, DHCP6Option)(buf)
        opts.append(opt)
        buf = opt.data
    return opts


def _pack_options(opts):
    return b''.join(bytes(opt) for opt in opts)


def _validate_options(opts):
    errors = []
    for opt in opts:
        errors.extend(opt.validate())
    return errors


class DHCP6Base(dpkt.Packet):
    """Shared option handling for DHCPv6 messages.

    Attributes:
        opts: (list): DHCP6Option objects in wire order; unknown and
            repeated options are preserved as-is.
    """

    opts = ()

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.opts = _parse_options(self.data)
        self.data = b''

    def pack_opts(self):
        """Return packed options string."""
        return _pack_options(self.opts)

    def validate(self):
        """Return a list of DHCP6SemanticError anomalies (empty if sane)."""
        return _validate_options(self.opts)

    def __len__(self):
        return self.__hdr_len__ + sum(len(opt) for opt in self.opts)

    def __bytes__(self):
        return self.pack_hdr() + self.pack_opts()


class DHCP6(DHCP6Base):
    """DHCPv6 client/server message.

    Attributes:
        __hdr__: Header fields of DHCP6.
            msg_type: (int): DHCPv6 message type, e.g. DHCP6_SOLICIT. (1 byte)
            xid: (bytes): Transaction ID. (3 bytes)
        opts: (list): Message options in wire order.
    """

    __hdr__ = (
        ('msg_type', 'B', DHCP6_SOLICIT),
        ('xid', '3s', b'\x00' * 3),
    )


class DHCP6Relay(DHCP6Base):
    """DHCPv6 relay agent message (Relay-forward / Relay-reply).

    Attributes:
        __hdr__: Header fields of DHCP6Relay.
            msg_type: (int): DHCP6_RELAY_FORW or DHCP6_RELAY_REPL. (1 byte)
            hop_count: (int): Number of relay agents that have relayed
                this message. (1 byte)
            link_address: (bytes): Global or site-local address of the
                link on which the client is located. (16 bytes)
            peer_address: (bytes): Address of the client or relay agent
                from which the message was received. (16 bytes)
        opts: (list): Message options in wire order; the Relay Message
            option carries the encapsulated message, recursively.
    """

    __hdr__ = (
        ('msg_type', 'B', DHCP6_RELAY_FORW),
        ('hop_count', 'B', 0),
        ('link_address', '16s', b'\x00' * 16),
        ('peer_address', '16s', b'\x00' * 16),
    )


def parse(buf):
    """Parse a DHCPv6 message, returning DHCP6Relay for Relay-forward /
    Relay-reply messages and DHCP6 for all other message types."""
    if not buf:
        raise dpkt.NeedData('empty DHCPv6 message')
    msg_type = compat_ord(buf[0])
    if msg_type in (DHCP6_RELAY_FORW, DHCP6_RELAY_REPL):
        return DHCP6Relay(buf)
    return DHCP6(buf)



def _opt(code, value):
    return struct.pack('>HH', code, len(value)) + value


def _addr(last):
    return b'\x20\x01\x0d\xb8' + b'\x00' * 11 + struct.pack('B', last)


def _prefix():
    return b'\x20\x01\x0d\xb8\xab\xcd' + b'\x00' * 10


def _duid_llt():
    return struct.pack('>HHI', DHCP6_DUID_LLT, 1, 0x12345678) + b'\x00\x11\x22\x33\x44\x55'


def _relay_fixture():
    """A Relay-forward chain of two relays around a Request carrying
    IA_NA (two IAADDR), IA_PD (one IAPREFIX) and repeated unknown options."""
    clientid = _opt(DHCP6_OPT_CLIENTID, _duid_llt())

    iaaddr1 = _opt(DHCP6_OPT_IAADDR, _addr(1) + struct.pack('>II', 300, 600))
    iaaddr2 = _opt(DHCP6_OPT_IAADDR, _addr(2) + struct.pack('>II', 400, 800))
    ia_na = _opt(DHCP6_OPT_IA_NA, struct.pack('>III', 0x01020304, 100, 200) + iaaddr1 + iaaddr2)

    iaprefix = _opt(DHCP6_OPT_IAPREFIX, struct.pack('>II', 100, 200) + b'\x38' + _prefix())
    ia_pd = _opt(DHCP6_OPT_IA_PD, struct.pack('>III', 0x0a0b0c0d, 50, 80) + iaprefix)

    unknown1 = _opt(0x00fa, b'mystery')
    unknown2 = _opt(0x00fa, b'x')

    inner = struct.pack('>B3s', DHCP6_REQUEST, b'\xab\xcd\xef') + \
        clientid + ia_na + ia_pd + unknown1 + unknown2

    link2 = b'\x20\x01\x0d\xb8\x00\x01' + b'\x00' * 9 + b'\x01'
    peer2 = b'\xfe\x80' + b'\x00' * 13 + b'\x02'
    relay2 = struct.pack('>BB', DHCP6_RELAY_FORW, 1) + link2 + peer2 + \
        _opt(DHCP6_OPT_INTERFACE_ID, b'iface-7') + _opt(DHCP6_OPT_RELAY_MSG, inner)

    link1 = b'\x20\x01\x0d\xb8\x00\x02' + b'\x00' * 9 + b'\x01'
    relay1 = struct.pack('>BB', DHCP6_RELAY_FORW, 2) + link1 + link2 + \
        _opt(DHCP6_OPT_RELAY_MSG, relay2)
    return relay1


def test_dhcp6_basic():
    # parse a plain client/server message
    elapsed = _opt(DHCP6_OPT_ELAPSED_TIME, b'\x00\x64')
    oro = _opt(DHCP6_OPT_ORO, struct.pack('>HH', DHCP6_OPT_STATUS_CODE, DHCP6_OPT_IAPREFIX))
    buf = struct.pack('>B3s', DHCP6_INFORMATION_REQUEST, b'\xde\xad\xbe') + elapsed + oro

    msg = DHCP6(buf)
    assert msg.msg_type == DHCP6_INFORMATION_REQUEST
    assert msg.xid == b'\xde\xad\xbe'
    assert [opt.code for opt in msg.opts] == [DHCP6_OPT_ELAPSED_TIME, DHCP6_OPT_ORO]
    assert msg.opts[0].value == b'\x00\x64'
    assert bytes(msg) == buf
    assert len(msg) == len(buf)

    # build one from scratch
    msg = DHCP6(msg_type=DHCP6_SOLICIT, xid=b'\x00\x00\x2a')
    msg.opts = [
        DHCP6ClientIdOption(duid=DUID(type=DHCP6_DUID_LL, data=b'\x00\x01' + b'\xaa' * 6)),
        DHCP6Option(code=DHCP6_OPT_RAPID_COMMIT, value=b''),
    ]
    out = bytes(msg)
    again = parse(out)
    assert isinstance(again, DHCP6)
    assert again.xid == b'\x00\x00\x2a'
    assert again.opts[0].duid.type == DHCP6_DUID_LL
    assert again.opts[0].duid.data == b'\x00\x01' + b'\xaa' * 6
    assert again.opts[1].code == DHCP6_OPT_RAPID_COMMIT
    assert bytes(again) == out

    # relay-reply dispatches to the relay message model
    buf = struct.pack('>BB', DHCP6_RELAY_REPL, 0) + b'\x00' * 32
    repl = parse(buf)
    assert isinstance(repl, DHCP6Relay)
    assert repl.msg_type == DHCP6_RELAY_REPL
    assert repl.hop_count == 0
    assert repl.link_address == b'\x00' * 16
    assert repl.peer_address == b'\x00' * 16
    assert bytes(repl) == buf


def test_dhcp6_option_length_scope():
    # the declared option length strictly bounds sub-parsing
    opt = DHCP6Option(struct.pack('>HH', 0x00fa, 3) + b'abcdef')
    assert opt.value == b'abc'
    assert opt.data == b'def'
    assert bytes(opt) == struct.pack('>HH', 0x00fa, 3) + b'abc'


def test_dhcp6_relay_roundtrip():
    buf = _relay_fixture()

    msg = parse(buf)
    assert isinstance(msg, DHCP6Relay)
    assert msg.msg_type == DHCP6_RELAY_FORW
    assert msg.hop_count == 2
    assert msg.link_address == b'\x20\x01\x0d\xb8\x00\x02' + b'\x00' * 9 + b'\x01'
    assert msg.peer_address == b'\x20\x01\x0d\xb8\x00\x01' + b'\x00' * 9 + b'\x01'
    assert len(msg.opts) == 1

    relay_opt = msg.opts[0]
    assert isinstance(relay_opt, DHCP6RelayMsgOption)

    msg2 = relay_opt.message
    assert isinstance(msg2, DHCP6Relay)
    assert msg2.hop_count == 1
    assert msg2.peer_address == b'\xfe\x80' + b'\x00' * 13 + b'\x02'
    iface_opt = msg2.opts[0]
    assert iface_opt.code == DHCP6_OPT_INTERFACE_ID
    assert iface_opt.value == b'iface-7'

    inner = msg2.opts[1].message
    assert isinstance(inner, DHCP6)
    assert inner.msg_type == DHCP6_REQUEST
    assert inner.xid == b'\xab\xcd\xef'

    # unknown and repeated options are preserved in wire order
    codes = [opt.code for opt in inner.opts]
    assert codes == [DHCP6_OPT_CLIENTID, DHCP6_OPT_IA_NA, DHCP6_OPT_IA_PD, 0x00fa, 0x00fa]
    assert inner.opts[3].value == b'mystery'
    assert inner.opts[4].value == b'x'

    clientid = inner.opts[0]
    assert isinstance(clientid, DHCP6ClientIdOption)
    assert clientid.duid.type == DHCP6_DUID_LLT
    assert clientid.duid.data == struct.pack('>HI', 1, 0x12345678) + b'\x00\x11\x22\x33\x44\x55'

    ia_na = inner.opts[1]
    assert isinstance(ia_na, DHCP6IANAOption)
    assert (ia_na.iaid, ia_na.t1, ia_na.t2) == (0x01020304, 100, 200)
    assert len(ia_na.opts) == 2
    assert ia_na.opts[0].addr == _addr(1)
    assert (ia_na.opts[0].preferred_lifetime, ia_na.opts[0].valid_lifetime) == (300, 600)
    assert ia_na.opts[1].addr == _addr(2)
    assert (ia_na.opts[1].preferred_lifetime, ia_na.opts[1].valid_lifetime) == (400, 800)

    ia_pd = inner.opts[2]
    assert isinstance(ia_pd, DHCP6IAPDOption)
    assert (ia_pd.iaid, ia_pd.t1, ia_pd.t2) == (0x0a0b0c0d, 50, 80)
    iaprefix = ia_pd.opts[0]
    assert isinstance(iaprefix, DHCP6IAPrefixOption)
    assert iaprefix.prefix_len == 0x38
    assert iaprefix.prefix == _prefix()
    assert (iaprefix.preferred_lifetime, iaprefix.valid_lifetime) == (100, 200)

    assert bytes(msg) == buf
    assert len(msg) == len(buf)
    assert msg.validate() == []


def test_dhcp6_nested_length_update():
    buf = _relay_fixture()
    msg = parse(buf)
    inner = msg.opts[0].message.opts[1].message
    ia_na = inner.opts[1]

    # modify the innermost address; enclosing Relay Message lengths stay in sync
    new_addr = _addr(0x42)
    ia_na.opts[0].addr = new_addr
    out = bytes(msg)
    assert len(out) == len(buf)
    again = parse(out)
    assert again.opts[0].message.opts[1].message.opts[1].opts[0].addr == new_addr

    # grow the innermost IA_NA; every enclosing option length follows
    ia_na.opts.append(DHCP6IAAddrOption(addr=_addr(3), preferred_lifetime=10, valid_lifetime=20))
    out = bytes(msg)
    assert len(out) == len(buf) + 28  # 4-byte option header + 24-byte IAADDR

    relay_opt = msg.opts[0]
    assert relay_opt.len == len(bytes(relay_opt.message))
    relay_opt2 = relay_opt.message.opts[1]
    assert relay_opt2.len == len(bytes(relay_opt2.message))

    again = parse(out)
    ia_na2 = again.opts[0].message.opts[1].message.opts[1]
    assert len(ia_na2.opts) == 3
    assert ia_na2.opts[2].addr == _addr(3)
    assert (ia_na2.opts[2].preferred_lifetime, ia_na2.opts[2].valid_lifetime) == (10, 20)
    assert len(again) == len(out)


def test_dhcp6_lifetime_anomaly():
    bad_iaaddr = _opt(DHCP6_OPT_IAADDR, _addr(9) + struct.pack('>II', 7200, 3600))
    bad_iaprefix = _opt(DHCP6_OPT_IAPREFIX, struct.pack('>II', 10, 5) + b'\x40' + _prefix())
    ia_na = _opt(DHCP6_OPT_IA_NA, struct.pack('>III', 7, 0, 0) + bad_iaaddr)
    ia_pd = _opt(DHCP6_OPT_IA_PD, struct.pack('>III', 8, 0, 0) + bad_iaprefix)
    solicit = struct.pack('>B3s', DHCP6_SOLICIT, b'\x01\x02\x03') + ia_na + ia_pd
    buf = struct.pack('>BB', DHCP6_RELAY_REPL, 1) + _addr(0) + _addr(1) + \
        _opt(DHCP6_OPT_RELAY_MSG, solicit)

    msg = parse(buf)
    assert isinstance(msg, DHCP6Relay)
    assert msg.msg_type == DHCP6_RELAY_REPL

    inner = msg.opts[0].message
    iaaddr = inner.opts[0].opts[0]
    # anomalous lifetimes are kept inspectable, never rewritten by the parser
    assert iaaddr.preferred_lifetime == 7200
    assert iaaddr.valid_lifetime == 3600
    iaprefix = inner.opts[1].opts[0]
    assert iaprefix.preferred_lifetime == 10
    assert iaprefix.valid_lifetime == 5

    # ... but they are reported, recursively from the innermost message
    errors = msg.validate()
    assert len(errors) == 2
    assert all(isinstance(err, DHCP6SemanticError) for err in errors)
    assert 'preferred lifetime 7200 exceeds valid lifetime 3600' in str(errors[0])
    assert 'preferred lifetime 10 exceeds valid lifetime 5' in str(errors[1])

    # the anomalous message still round-trips byte for byte
    assert bytes(msg) == buf


def test_dhcp6_truncated():
    import pytest

    # option declares more bytes than available
    buf = struct.pack('>B3s', DHCP6_SOLICIT, b'\x01\x02\x03') + \
        struct.pack('>HH', DHCP6_OPT_CLIENTID, 10) + b'\x00\x01'
    with pytest.raises(dpkt.NeedData):
        DHCP6(buf)

    # trailing partial option header
    buf = struct.pack('>B3s', DHCP6_SOLICIT, b'\x01\x02\x03') + b'\x00'
    with pytest.raises(dpkt.NeedData):
        DHCP6(buf)

    # empty buffer
    with pytest.raises(dpkt.NeedData):
        parse(b'')

