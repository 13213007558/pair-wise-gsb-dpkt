# $Id: netflow.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Cisco Netflow."""
from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from .compat import compat_izip


class NetflowBase(dpkt.Packet):
    """Base class for Cisco Netflow packets.

    NetFlow is a feature that was introduced on Cisco routers around 1996 that provides the ability to collect IP
    network traffic as it enters or exits an interface. By analyzing the data provided by NetFlow, a network
    administrator can determine things such as the source and destination of traffic, class of service, and the causes
    of congestion.

    https://www.ciscopress.com/articles/article.asp?p=2812391&seqNum=3

    Attributes:
        __hdr__: Header fields of NetflowBase.
    """

    __hdr__ = (
        ('version', 'H', 1),
        ('count', 'H', 0),
        ('sys_uptime', 'I', 0),
        ('unix_sec', 'I', 0),
        ('unix_nsec', 'I', 0)
    )

    def __len__(self):
        return self.__hdr_len__ + (len(self.data[0]) * self.count)

    def __bytes__(self):
        # for now, don't try to enforce any size limits
        self.count = len(self.data)
        return self.pack_hdr() + b''.join(map(bytes, self.data))

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        buf = self.data
        l_ = []
        while buf:
            flow = self.NetflowRecord(buf)
            l_.append(flow)
            buf = buf[len(flow):]
        self.data = l_

    class NetflowRecordBase(dpkt.Packet):
        """Base class for netflow v1-v7 netflow records.

        TODO: Longer class information....

        Attributes:
            __hdr__: Header fields of NetflowRecordBase.
            TODO.
        """

        # performance optimizations
        def __len__(self):
            # don't bother with data
            return self.__hdr_len__

        def __bytes__(self):
            # don't bother with data
            return self.pack_hdr()

        def unpack(self, buf):
            # don't bother with data
            for k, v in compat_izip(self.__hdr_fields__,
                                    struct.unpack(self.__hdr_fmt__, buf[:self.__hdr_len__])):
                setattr(self, k, v)
            self.data = b""


class Netflow1(NetflowBase):
    """Netflow Version 1.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Netflow Version 1.
        TODO.
    """

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v1 flow record.

        TODO: Longer class information....

        Attributes:
            __hdr__: Header fields of Netflow Version 1 flow record.
            TODO.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'H', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('pad2', 'B', 0),
            ('pad3', 'H', 0),
            ('reserved', 'I', 0)
        )


# FYI, versions 2-4 don't appear to have ever seen the light of day.

class Netflow5(NetflowBase):
    """Netflow Version 5.

    Popular NetFlow version on many routers from different vendors. Limited to IPv4 flows.

    Attributes:
        __hdr__: Header fields of Netflow Version 5.
    """

    __hdr__ = NetflowBase.__hdr__ + (
        ('flow_sequence', 'I', 0),
        ('engine_type', 'B', 0),
        ('engine_id', 'B', 0),
        ('reserved', 'H', 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v5 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 5 flow record.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('pad2', 'H', 0),
        )


class Netflow6(NetflowBase):
    """Netflow Version 6.

    (Obsolete.) No longer supported by Cisco, but may be found in the field.

    Attributes:
        __hdr__: Header fields of Netflow Version 6.
    """

    __hdr__ = Netflow5.__hdr__

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('in_encaps', 'B', 0),
            ('out_encaps', 'B', 0),
            ('peer_nexthop', 'I', 0),
        )


class Netflow7(NetflowBase):
    """Netflow Version 7.

    (Obsolete.) Like version 5, with a source router field.

    Attributes:
        __hdr__: Header fields of Netflow Version 7.
    """

    __hdr__ = NetflowBase.__hdr__ + (
        ('flow_sequence', 'I', 0),
        ('reserved', 'I', 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        TODO: Longer class information....

        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
            TODO.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('flags', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('pad2', 'H', 0),
            ('router_sc', 'I', 0),
        )


# No support for v8 yet.


# Netflow Version 9 (RFC 3954).
#
# Unlike the fixed-layout versions above, v9 is template based: Template
# FlowSets carried in the export stream describe the layout of subsequent
# Data FlowSets. Decoding a stream therefore requires state, which lives in
# Netflow9Decoder. Templates are scoped by the caller-supplied exporter
# identity together with the Source ID and Template ID from the packet, so
# templates from different exporters never collide even when they reuse the
# same Template ID.

NETFLOW9_TEMPLATE_FLOWSET_ID = 0
NETFLOW9_OPTIONS_TEMPLATE_FLOWSET_ID = 1
NETFLOW9_MIN_TEMPLATE_ID = 256


class Netflow9(dpkt.Packet):
    """Netflow Version 9 export packet header (RFC 3954).

    Only the header is parsed; the FlowSet payload is left in .data because
    interpreting it requires template state. Feed the whole packet buffer to
    Netflow9Decoder.process_packet() to get the header plus decoded FlowSets.

    Attributes:
        __hdr__: Header fields of Netflow Version 9.
    """

    __hdr__ = (
        ('version', 'H', 9),
        ('count', 'H', 0),
        ('sys_uptime', 'I', 0),
        ('unix_sec', 'I', 0),
        ('sequence_number', 'I', 0),
        ('source_id', 'I', 0),
    )


class Netflow9Template(object):
    """A Netflow v9 Template (or Options Template) learned from a Template FlowSet.

    Attributes:
        template_id: Template ID assigned by the exporter (>= 256).
        fields: Ordered list of (field_type, field_length) tuples covering
            both scope and option/regular fields.
        scope_field_count: Number of leading scope fields; 0 for plain
            templates, > 0 for Options Templates.
    """

    __slots__ = ('template_id', 'fields', 'scope_field_count')

    def __init__(self, template_id, fields, scope_field_count=0):
        self.template_id = template_id
        self.fields = list(fields)
        self.scope_field_count = scope_field_count

    @property
    def is_options(self):
        return self.scope_field_count > 0

    @property
    def record_length(self):
        return sum(field_length for _, field_length in self.fields)

    def __repr__(self):
        return 'Netflow9Template(template_id=%d, fields=%r, scope_field_count=%d)' % (
            self.template_id, self.fields, self.scope_field_count)


class Netflow9Field(object):
    """A single decoded field of a Netflow v9 data record.

    The raw bytes are always kept so that field types unknown to the
    collector survive the round trip with their type number intact.

    Attributes:
        type: Field type number as assigned by the exporter.
        data: Raw field bytes.
    """

    __slots__ = ('type', 'data')

    def __init__(self, field_type, data):
        self.type = field_type
        self.data = data

    @property
    def length(self):
        return len(self.data)

    @property
    def value(self):
        """Integer value for 1/2/4/8-byte fields, raw bytes otherwise."""
        fmt = {1: '>B', 2: '>H', 4: '>I', 8: '>Q'}.get(len(self.data))
        if fmt is None:
            return self.data
        return struct.unpack(fmt, self.data)[0]

    def __repr__(self):
        return 'Netflow9Field(type=%d, data=%r)' % (self.type, self.data)


class Netflow9TemplateFlowSet(object):
    """Decoded Template FlowSet; its templates are already registered."""

    flowset_id = NETFLOW9_TEMPLATE_FLOWSET_ID
    pending = False

    def __init__(self, templates):
        self.templates = templates


class Netflow9OptionsTemplateFlowSet(object):
    """Decoded Options Template FlowSet; its templates are already registered."""

    flowset_id = NETFLOW9_OPTIONS_TEMPLATE_FLOWSET_ID
    pending = False

    def __init__(self, templates):
        self.templates = templates


class Netflow9DataFlowSet(object):
    """Data FlowSet decoded against a known template.

    Attributes:
        flowset_id: FlowSet (== Template) ID.
        template: The Netflow9Template used for decoding.
        records: List of records; each record is a list of Netflow9Field
            following the template field order (scope fields first for
            Options Templates).
    """

    pending = False

    def __init__(self, template, records):
        self.flowset_id = template.template_id
        self.template = template
        self.records = records


class Netflow9UnknownFlowSet(object):
    """FlowSet that could not be interpreted yet.

    Produced for Data FlowSets whose template has not been seen (for this
    exporter/Source ID) and for reserved FlowSet IDs. The raw payload is
    preserved so the caller can decode it later via
    Netflow9Decoder.decode_pending() once the template arrives.

    Attributes:
        flowset_id: FlowSet ID from the packet.
        data: Raw FlowSet payload (without the FlowSet header).
    """

    pending = True

    def __init__(self, flowset_id, data):
        self.flowset_id = flowset_id
        self.data = data


def _decode_netflow9_records(template, buf):
    """Split a Data FlowSet payload into records per the template.

    Trailing bytes shorter than one record are 32-bit alignment padding and
    are not returned as a record.
    """
    records = []
    record_length = template.record_length
    if record_length == 0:
        return records
    offset = 0
    while offset + record_length <= len(buf):
        record = []
        for field_type, field_length in template.fields:
            record.append(Netflow9Field(field_type, buf[offset:offset + field_length]))
            offset += field_length
        records.append(record)
    return records


class Netflow9Decoder(object):
    """Stateful decoder for a stream of Netflow v9 export packets.

    Templates learned from Template FlowSets are remembered per
    (exporter, source_id, template_id) and applied to subsequent Data
    FlowSets. Redefining a Template ID only affects packets processed after
    the redefinition. Sequence numbers are tracked per (exporter, source_id)
    for informational purposes; an out-of-order packet never clears template
    state on its own -- use exporter_restarted() or expire_templates() for
    explicit lifecycle management.
    """

    def __init__(self):
        self.templates = {}
        self.last_sequence = {}

    def process_packet(self, buf, exporter=None):
        """Process one export packet.

        Args:
            buf: Raw bytes of one Netflow v9 export packet.
            exporter: Caller-supplied identity of the exporting device (e.g.
                its source address). Templates are scoped by this identity so
                distinct exporters may reuse the same Template IDs.

        Returns:
            The parsed Netflow9 header with a .flowsets list containing
            Netflow9TemplateFlowSet, Netflow9OptionsTemplateFlowSet,
            Netflow9DataFlowSet and Netflow9UnknownFlowSet objects, and an
            .out_of_order flag noting sequence number regressions.
        """
        pkt = Netflow9(buf)
        if pkt.version != 9:
            raise dpkt.UnpackError('expected Netflow v9, got version %d' % pkt.version)
        domain = (exporter, pkt.source_id)
        last = self.last_sequence.get(domain)
        pkt.out_of_order = last is not None and pkt.sequence_number <= last
        if last is None or pkt.sequence_number > last:
            self.last_sequence[domain] = pkt.sequence_number
        pkt.flowsets = self._parse_flowsets(domain, pkt.data)
        return pkt

    def decode_pending(self, flowset, exporter=None, source_id=0):
        """Decode a previously returned Netflow9UnknownFlowSet.

        Looks up the template registered since the FlowSet was first seen
        and returns a Netflow9DataFlowSet. Raises KeyError if the template
        is still unknown.
        """
        template = self.templates[(exporter, source_id, flowset.flowset_id)]
        return Netflow9DataFlowSet(template, _decode_netflow9_records(template, flowset.data))

    def exporter_restarted(self, exporter=None, source_id=None):
        """Declare that an exporter restarted; drop its template state.

        With source_id=None all sources of the exporter are affected.
        """
        self._purge(exporter=exporter, source_id=source_id, drop_sequence=True)

    def expire_templates(self, exporter=None, source_id=None, template_id=None):
        """Expire matching templates; with no arguments, expire all of them."""
        self._purge(exporter=exporter, source_id=source_id, template_id=template_id)

    def _purge(self, exporter=None, source_id=None, template_id=None, drop_sequence=False):
        for key in list(self.templates):
            exp, src, tid = key
            if exporter is not None and exp != exporter:
                continue
            if source_id is not None and src != source_id:
                continue
            if template_id is not None and tid != template_id:
                continue
            del self.templates[key]
        if drop_sequence:
            for key in list(self.last_sequence):
                exp, src = key
                if exporter is not None and exp != exporter:
                    continue
                if source_id is not None and src != source_id:
                    continue
                del self.last_sequence[key]

    def _parse_flowsets(self, domain, buf):
        flowsets = []
        while len(buf) >= 4:
            flowset_id, length = struct.unpack('>HH', buf[:4])
            if length < 4:
                raise dpkt.UnpackError('invalid Netflow v9 FlowSet length %d' % length)
            if len(buf) < length:
                raise dpkt.NeedData('truncated Netflow v9 FlowSet: got %d, need %d' % (len(buf), length))
            body = buf[4:length]
            buf = buf[length:]
            if flowset_id == NETFLOW9_TEMPLATE_FLOWSET_ID:
                flowsets.append(Netflow9TemplateFlowSet(self._parse_templates(domain, body, options=False)))
            elif flowset_id == NETFLOW9_OPTIONS_TEMPLATE_FLOWSET_ID:
                flowsets.append(Netflow9OptionsTemplateFlowSet(self._parse_templates(domain, body, options=True)))
            elif flowset_id >= NETFLOW9_MIN_TEMPLATE_ID:
                template = self.templates.get((domain[0], domain[1], flowset_id))
                if template is None:
                    flowsets.append(Netflow9UnknownFlowSet(flowset_id, body))
                else:
                    flowsets.append(Netflow9DataFlowSet(template, _decode_netflow9_records(template, body)))
            else:
                # Reserved FlowSet ID; keep the raw payload.
                flowsets.append(Netflow9UnknownFlowSet(flowset_id, body))
        # Any remaining < 4 bytes are alignment padding.
        return flowsets

    def _parse_templates(self, domain, buf, options):
        templates = []
        offset = 0
        while offset + 4 <= len(buf):
            if options:
                template, offset = self._parse_options_template(buf, offset)
            else:
                template, offset = self._parse_template(buf, offset)
            self.templates[(domain[0], domain[1], template.template_id)] = template
            templates.append(template)
        return templates

    @staticmethod
    def _parse_template(buf, offset):
        template_id, field_count = struct.unpack_from('>HH', buf, offset)
        offset += 4
        if offset + field_count * 4 > len(buf):
            raise dpkt.NeedData('truncated Netflow v9 Template record')
        fields = []
        for _ in range(field_count):
            fields.append(struct.unpack_from('>HH', buf, offset))
            offset += 4
        return Netflow9Template(template_id, fields), offset

    @staticmethod
    def _parse_options_template(buf, offset):
        template_id, scope_length, option_length = struct.unpack_from('>HHH', buf, offset)
        offset += 6
        if offset + scope_length + option_length > len(buf):
            raise dpkt.NeedData('truncated Netflow v9 Options Template record')
        fields = []
        for end in (offset + scope_length, offset + scope_length + option_length):
            while offset < end:
                fields.append(struct.unpack_from('>HH', buf, offset))
                offset += 4
        scope_field_count = scope_length // 4
        # Options Template records are padded to a 32-bit boundary.
        offset = (offset + 3) & ~3
        return Netflow9Template(template_id, fields, scope_field_count), offset
def test_net_flow_v1_unpack():
    from binascii import unhexlify
    __sample_v1 = unhexlify(
        '00010018677a613c4200fc1c24930870ac012057c0a863f70a0002010003000a0000000100000228677a372c677a372c5c1b0050ac01112c10000'
        '0000004001bac011853ac18d9aac0a832020003001900000001000005dc677a377c677a377cd8e30050ac01062c100000000004001bac011418ac'
        '188dcdc0a832660003000700000001000005dc677a3790677a37908a81176fac0106361000000000040003ac0f2724ac01e51dc0a832060004001'
        'b0000000100000228677a3a38677a3a38a3511236ac2906fd180000000004001bac011645ac23178ec0a832060003001b0000000100000228677a'
        '3a4c677a3a4cc9ff0050ac1f0686020000000003001bac0d09ffac019995c0a832060004001b00000001000005dc677a3a58677a3a58ee390017a'
        'c0106de1000000000040003ac0e4ad8ac01ae2fc0a832060004001b00000001000005dc677a3a68677a3a68b36e0015ac01068110000000000400'
        '1bac012338ac01d92ac0a832060003001b00000001000005dc677a3a74677a3a7400008350ac2101ab100000000003001bac0a6037ac2a934ac0a'
        '832060004001b00000001000005dc677a3a74677a3a7400000000ac0132a91000000000040007ac0a471fac01fd4ac0a832060004001b00000001'
        '00000028677a3a88677a3a8821996987ac1e067e020000000003001bac0128c9ac0142c4c0a83202000300190000000100000028677a3a88677a3'
        'a887d360050ac0106fe100000000004001bac0b08e8ac0146e2c0a832020004001900000001000005dc677a3a9c677a3a9c60696987ac01063b10'
        '0000000004001bac011d24ac3cf0c3c0a832060003001b00000001000005dc677a3a9c677a3a9c46320014ac0106731800000000040003ac0b115'
        '1ac01de06c0a832060004001b00000001000005dc677a3ab0677a3ab0ef231a2bac2906e9100000000004001bac0c52d9ac016fe8c0a832020004'
        '001900000001000005dc677a3ac4677a3ac4136e006eac1906a81000000000030019ac013dddac017deec0a832660003000700000001000000286'
        '77a3ac4677a3ac40000dcbbac0101d3100000000004001bac0f28d1ac01cca5c0a832060004001b00000001000005dc677a3ad8677a3ad8c57317'
        '6fac1906231800000000030007ac0a855bc0a8636e0a0002010004000a00000001000005dc677a3ae4677a3ae4bf6c0050ac0106cf10000000000'
        '40007ac01301fac182145c0a832660003000700000001000005dc677a3b00677a3b00119504bec0a806ea100000000003000aac0130b6ac1ef4aa'
        'c0a832060003001b00000001000005dc677a3b34677a3b3488640017ac01061f100000000004001bac01235fac1eb009c0a832060003001b00000'
        '001000005dc677a3b48677a3b4881530050ac20064e100000000003001bac0104d9ac019463c0a832060003001b0000000100000228677a3b5c67'
        '7a3b5c55100050ac010650180000000004001bac013caeac2aac21c0a832060003001b00000001000000fa677a3b84677a3b840ce70050ac0111f'
        'd100000000004001bac011f1fac17ed69c0a832020003001900000001000005dc677a3b98677a3b98ba170016ac01067c1000000000030007'
    )
    nf = Netflow1(__sample_v1)
    assert len(nf.data) == 24
    # print repr(nfv1)


def test_net_flow_v5_unpack():
    from binascii import unhexlify
    buf_nf5_header = unhexlify(
        '0005001db5fac9d03a0b4142265677de9b73763100010000'
    )

    buf_nf5_records = list(map(unhexlify, (
        'ac0a86a6ac01aaf7c0a83232027100690000000100000228b5fa8114b5fa811435320050000006000000000000000000',
        'ac019144ac1443e4c0a83216006902710000000100000028b5fa9bbdb5fa9bbd005085d7000006000000000000000000',
        'ac17e2d7ac018c56c0a832320271006900000001000005dcb5fa6fb8b5fa6fb876e8176f000006000000000000000000',
        'ac0ef2e5ac0191b2c0a832320271006900000001000000fab5fa81eeb5fa81eed0eb0015000006000000000000000000',
        'ac0a436aac29a7090a000201027100db0000000100000228b5fa8592b5fa85928cb00035000006000000000000000000',
        'ac01963dac151aa8c0a832160069027100000001000005dcb5fa86e0b5fa86e0b4e700c2000006000000000000000000',
        'ac0156d1ac018615c0a832320271006900000001000005dcb5fa7d3ab5fa7d3a5b510050000006000000000000000000',
        'ac32f1b1ac2919ca0a000201027100db00000001000005dcb5fa83c3b5fa83c3162c0015000006000000000000000000',
        'ac0c4134ac019a7ac0a832320271006900000001000005dcb5fa8da7b5fa8da717330015000006000000000000000000',
        'ac1ed284ac29d8d20a000201027100db00000001000005dcb5fa8e97b5fa8e97372a176f000006000000000000000000',
        'ac01854aac2011fcc0a83216006902710000000100000228b5fa8834b5fa8834f5dd008f000006000000000000000000',
        'ac010480ac3c5b6e0a000201027100db00000001000005dcb5fa9d72b5fa9d7273240016000006000000000000000000',
        'ac01b94aac22c9d7c0a83216006902710000000100000028b5fa9072b5fa90720f8d00c2000006000000000000000000',
        'ac2aa310ac01b419c0a83232027100690000000100000028b5fa9203b5fa920370660015000006000000000000000000',
        'ac01ab6fac1e7f69c0a832160069027100000001000005dcb5fa937fb5fa937f00500b98000006000000000000000000',
        'ac0c0aeaac01a115c0a832320271006900000001000005dcb5fa79cfb5fa79cf5b3317e0000006000000000000000000',
        'ac01bbb3ac29758c0a000201006900db00000001000000fab5fa9433b5fa943300501eca000006000000000000000000',
        'ac0f4a60ac01ab94c0a83232027100690000000100000228b5fa875bb5fa875b9ad62fab000006000000000000000000',
        'ac2a0f93ac01b8a3c0a83232027100690000000100000028b5fa89bbb5fa89bb6ee10050000006000000000000000000',
        'ac0193a1ac16800cc0a83216006902710000000100000028b5fa8726b5fa872600000000000001000000000000000000',
        'ac01835aac1f52cdc0a832160069027100000001000005dcb5fa900db5fa900df72a008a000006000000000000000000',
        'ac0ce0adac01a856c0a832320271006900000001000005dcb5fa9cf6b5fa9cf6e57c1a2b000006000000000000000000',
        'ac1ecc54ac3c78260a000201027100db00000001000005dcb5fa80eab5fa80ea0000000000002f000000000000000000',
        'ac01bb18ac017c7ac0a832160069027100000001000000fab5fa8870b5fa887000500b7d000006000000000000000000',
        'ac170e72ac018fddc0a83232027100690000000100000228b5fa89f7b5fa89f70df7008a000006000000000000000000',
        'ac0abb04ac3cb0150a000201027100db00000001000005dcb5fa90a9b5fa90a99cd0008f000006000000000000000000',
        'ac0a7a3fac2903c80a000201027100db00000001000005dcb5fa7565b5fa7565eea60050000006000000000000000000',
        'ac01b505c0a8639f0a000201006900db00000001000005dcb5fa7bc7b5fa7bc7005086a9000006000000000000000000',
        'ac32a51bac2930bf0a000201027100db00000001000000fab5fa9b5ab5fa9b5a43f917e0000006000000000000000000',
    )))

    buf_input = buf_nf5_header + b''.join(buf_nf5_records)
    nf = Netflow5(buf_input)
    assert nf.version == 5
    assert nf.count == 29
    assert nf.sys_uptime == 3053111760
    assert nf.unix_sec == 973816130

    assert len(nf) == len(buf_input)
    assert bytes(nf) == buf_input

    assert len(nf.data) == 29
    for idx, record in enumerate(nf.data):
        assert bytes(record) == buf_nf5_records[idx]
        assert len(record) == 48


def _v9_export_packet(flowsets, sequence_number=0, source_id=0):
    body = b''.join(flowsets)
    return struct.pack('>HHIIII', 9, 0, 0, 0, sequence_number, source_id) + body


def _v9_template_flowset(templates):
    body = b''
    for template_id, fields in templates:
        body += struct.pack('>HH', template_id, len(fields))
        for field_type, field_length in fields:
            body += struct.pack('>HH', field_type, field_length)
    return struct.pack('>HH', NETFLOW9_TEMPLATE_FLOWSET_ID, 4 + len(body)) + body


def _v9_options_template_flowset(template_id, scope_fields, option_fields):
    body = struct.pack('>HHH', template_id, 4 * len(scope_fields), 4 * len(option_fields))
    for field_type, field_length in scope_fields + option_fields:
        body += struct.pack('>HH', field_type, field_length)
    if len(body) % 4:
        body += b'\x00' * (4 - len(body) % 4)
    return struct.pack('>HH', NETFLOW9_OPTIONS_TEMPLATE_FLOWSET_ID, 4 + len(body)) + body


def _v9_data_flowset(template_id, records, pad=True):
    body = b''.join(records)
    if pad and len(body) % 4:
        body += b'\x00' * (4 - len(body) % 4)
    return struct.pack('>HH', template_id, 4 + len(body)) + body


def test_netflow9_template_then_data():
    decoder = Netflow9Decoder()
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1)]  # srcaddr, dstaddr, srcport, dstport, prot
    pkt = decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, fields)])]), exporter='exp1')
    assert pkt.version == 9
    assert isinstance(pkt.flowsets[0], Netflow9TemplateFlowSet)
    template = pkt.flowsets[0].templates[0]
    assert template.template_id == 256
    assert template.record_length == 13
    assert not template.is_options

    record1 = struct.pack('>IIHHB', 0x0a000001, 0x0a000002, 1234, 80, 6)
    record2 = struct.pack('>IIHHB', 0x0a000003, 0x0a000004, 4321, 443, 17)
    pkt = decoder.process_packet(
        _v9_export_packet([_v9_data_flowset(256, [record1, record2])], sequence_number=2), exporter='exp1')
    flowset = pkt.flowsets[0]
    assert isinstance(flowset, Netflow9DataFlowSet)
    assert not flowset.pending
    # 2 records of 13 bytes = 26, padded to 28; padding must not become a record
    assert len(flowset.records) == 2
    values = [[field.value for field in record] for record in flowset.records]
    assert values[0] == [0x0a000001, 0x0a000002, 1234, 80, 6]
    assert values[1] == [0x0a000003, 0x0a000004, 4321, 443, 17]


def test_netflow9_unknown_template_kept_raw():
    decoder = Netflow9Decoder()
    raw_record = struct.pack('>IH', 0xdeadbeef, 7)
    pkt = decoder.process_packet(_v9_export_packet([_v9_data_flowset(300, [raw_record], pad=False)]))
    flowset = pkt.flowsets[0]
    assert isinstance(flowset, Netflow9UnknownFlowSet)
    assert flowset.pending
    assert flowset.flowset_id == 300
    assert flowset.data == raw_record

    # Once the template arrives, the pending FlowSet can be interpreted.
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(300, [(8, 4), (7, 2)])])]))
    decoded = decoder.decode_pending(flowset)
    assert isinstance(decoded, Netflow9DataFlowSet)
    assert [[f.value for f in r] for r in decoded.records] == [[0xdeadbeef, 7]]


def test_netflow9_templates_scoped_per_exporter():
    decoder = Netflow9Decoder()
    # Both exporters reuse Template ID 256 with different layouts.
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4)])])]), exporter='expA')
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(7, 2), (11, 2)])])]), exporter='expB')

    record_a = struct.pack('>I', 0xc0a80101)
    record_b = struct.pack('>HH', 1024, 2048)
    pkt_a = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [record_a])], 1), exporter='expA')
    pkt_b = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [record_b])], 1), exporter='expB')
    pkt_a2 = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [record_a])], 2), exporter='expA')

    assert [f.value for f in pkt_a.flowsets[0].records[0]] == [0xc0a80101]
    assert [f.value for f in pkt_b.flowsets[0].records[0]] == [1024, 2048]
    assert [f.value for f in pkt_a2.flowsets[0].records[0]] == [0xc0a80101]

    # A third exporter with the same Template ID must not borrow either template.
    pkt_c = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [record_a])]), exporter='expC')
    assert isinstance(pkt_c.flowsets[0], Netflow9UnknownFlowSet)


def test_netflow9_template_scoped_per_source_id():
    decoder = Netflow9Decoder()
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4)])])], source_id=1), exporter='exp')
    pkt = decoder.process_packet(
        _v9_export_packet([_v9_data_flowset(256, [struct.pack('>I', 1)], pad=False)], source_id=2), exporter='exp')
    assert isinstance(pkt.flowsets[0], Netflow9UnknownFlowSet)


def test_netflow9_template_redefinition_affects_only_later_data():
    decoder = Netflow9Decoder()
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4)])])]))
    pkt = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [struct.pack('>I', 42)], pad=False)]))
    assert [f.value for f in pkt.flowsets[0].records[0]] == [42]

    # Redefine the same Template ID; only subsequent data uses the new layout.
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(7, 2), (11, 2)])])]))
    pkt = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [struct.pack('>HH', 1, 2)], pad=False)]))
    assert [f.value for f in pkt.flowsets[0].records[0]] == [1, 2]


def test_netflow9_options_template():
    decoder = Netflow9Decoder()
    scope_fields = [(2, 4)]  # scope: interface
    option_fields = [(34, 4), (35, 2)]  # sampling algorithm, interval-ish
    decoder.process_packet(_v9_export_packet(
        [_v9_options_template_flowset(257, scope_fields, option_fields)]))
    template = decoder.templates[(None, 0, 257)]
    assert template.is_options
    assert template.scope_field_count == 1

    record = struct.pack('>IIH', 5, 1, 100)
    pkt = decoder.process_packet(_v9_export_packet([_v9_data_flowset(257, [record], pad=False)]))
    flowset = pkt.flowsets[0]
    assert isinstance(flowset, Netflow9DataFlowSet)
    assert [f.value for f in flowset.records[0]] == [5, 1, 100]
    assert [f.type for f in flowset.records[0]] == [2, 34, 35]


def test_netflow9_unknown_field_type_preserved():
    decoder = Netflow9Decoder()
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4), (65000, 3)])])]))
    record = struct.pack('>I', 9) + b'\x01\x02\x03'
    pkt = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [record], pad=False)]))
    fields = pkt.flowsets[0].records[0]
    assert fields[1].type == 65000
    assert fields[1].data == b'\x01\x02\x03'
    assert fields[1].value == b'\x01\x02\x03'  # not an integer length


def test_netflow9_exporter_restart_and_expiry():
    decoder = Netflow9Decoder()
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4)])])]), exporter='expA')
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4)])])]), exporter='expB')

    # Restart of expA only clears expA state.
    decoder.exporter_restarted('expA')
    pkt_a = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [struct.pack('>I', 1)], pad=False)]),
                                   exporter='expA')
    pkt_b = decoder.process_packet(_v9_export_packet([_v9_data_flowset(256, [struct.pack('>I', 1)], pad=False)]),
                                   exporter='expB')
    assert isinstance(pkt_a.flowsets[0], Netflow9UnknownFlowSet)
    assert isinstance(pkt_b.flowsets[0], Netflow9DataFlowSet)

    # Selective expiry by Template ID, then full expiry.
    decoder.expire_templates(exporter='expB', template_id=256)
    assert decoder.templates == {}
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4)])])]))
    decoder.expire_templates()
    assert decoder.templates == {}


def test_netflow9_out_of_order_packet_keeps_state():
    decoder = Netflow9Decoder()
    decoder.process_packet(_v9_export_packet([_v9_template_flowset([(256, [(8, 4)])])], sequence_number=10))
    pkt = decoder.process_packet(
        _v9_export_packet([_v9_data_flowset(256, [struct.pack('>I', 7)], pad=False)], sequence_number=3))
    assert pkt.out_of_order
    # Sequence regression alone must not wipe template state.
    assert isinstance(pkt.flowsets[0], Netflow9DataFlowSet)
    assert (None, 0, 256) in decoder.templates

    pkt = decoder.process_packet(
        _v9_export_packet([_v9_data_flowset(256, [struct.pack('>I', 8)], pad=False)], sequence_number=11))
    assert not pkt.out_of_order


def test_netflow9_rejects_other_versions():
    import pytest
    decoder = Netflow9Decoder()
    with pytest.raises(dpkt.UnpackError):
        decoder.process_packet(struct.pack('>HHIIII', 5, 0, 0, 0, 0, 0))
