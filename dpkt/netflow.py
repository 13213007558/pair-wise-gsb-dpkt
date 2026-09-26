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


class Netflow9(dpkt.Packet):
    """Netflow Version 9.

    Version 9 is template based: Template FlowSets carried in the export
    stream describe the layout of the Data FlowSets that follow them, so a
    single packet cannot be fully decoded without the template state that
    was built up from previous packets. This class only parses the packet
    header and splits the payload into raw FlowSets; use Netflow9Decoder to
    interpret them across a stream of packets.

    Attributes:
        __hdr__: Header fields of Netflow Version 9.
    """

    __hdr__ = (
        ('version', 'H', 9),
        ('count', 'H', 0),
        ('sys_uptime', 'I', 0),
        ('unix_sec', 'I', 0),
        ('sequence', 'I', 0),
        ('source_id', 'I', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.flowsets = []
        buf = self.data
        while len(buf) >= 4:
            flowset_id, length = struct.unpack('>HH', buf[:4])
            if length < 4:
                raise dpkt.UnpackError('invalid Netflow9 FlowSet length: %d' % length)
            if length > len(buf):
                raise dpkt.NeedData('truncated Netflow9 FlowSet')
            self.flowsets.append(Netflow9FlowSet(flowset_id, buf[4:length]))
            buf = buf[length:]
        # any trailing bytes shorter than a FlowSet header are padding
        self.data = self.flowsets

    def __len__(self):
        return self.__hdr_len__ + sum(len(flowset) for flowset in self.flowsets)

    def __bytes__(self):
        return self.pack_hdr() + b''.join(map(bytes, self.flowsets))


class Netflow9FlowSet(object):
    """A raw Netflow v9 FlowSet: a 16-bit FlowSet ID and an opaque body.

    FlowSet ID 0 carries Template FlowSets, ID 1 carries Options Template
    FlowSets, IDs 2-255 are reserved, and IDs 256 and above are Data
    FlowSets whose layout is given by the template of the same ID.
    """

    __slots__ = ('id', 'data')

    TEMPLATE_ID = 0
    OPTIONS_TEMPLATE_ID = 1
    MIN_DATA_TEMPLATE_ID = 256

    def __init__(self, flowset_id, data):
        self.id = flowset_id
        self.data = data

    def __len__(self):
        return 4 + len(self.data)

    def __bytes__(self):
        return struct.pack('>HH', self.id, len(self)) + self.data

    def __repr__(self):
        return '%s(id=%d, data=%r)' % (self.__class__.__name__, self.id, self.data)


class Netflow9TemplateFlowSet(Netflow9FlowSet):
    """A Template FlowSet (FlowSet ID 0) with its template definitions."""

    __slots__ = ('templates',)

    def __init__(self, data, templates):
        Netflow9FlowSet.__init__(self, self.TEMPLATE_ID, data)
        self.templates = templates


class Netflow9OptionsTemplateFlowSet(Netflow9FlowSet):
    """An Options Template FlowSet (FlowSet ID 1) with its definitions."""

    __slots__ = ('templates',)

    def __init__(self, data, templates):
        Netflow9FlowSet.__init__(self, self.OPTIONS_TEMPLATE_ID, data)
        self.templates = templates


class Netflow9Template(object):
    """A template learned from a Template or Options Template FlowSet.

    For Options Templates, scope_fields holds the scope field specifiers
    and fields holds the option field specifiers; both are lists of
    (field_type, field_length) tuples. updated records the unix_sec
    timestamp of the packet that (re)defined this template, which the
    caller can use to expire stale templates.
    """

    __slots__ = ('template_id', 'fields', 'scope_fields', 'options', 'updated')

    def __init__(self, template_id, fields, scope_fields=(), options=False, updated=0):
        self.template_id = template_id
        self.fields = list(fields)
        self.scope_fields = list(scope_fields)
        self.options = options
        self.updated = updated

    @property
    def record_length(self):
        return (sum(length for _, length in self.fields) +
                sum(length for _, length in self.scope_fields))

    def __repr__(self):
        return ('Netflow9Template(template_id=%d, fields=%r, scope_fields=%r, options=%r)' %
                (self.template_id, self.fields, self.scope_fields, self.options))


class Netflow9Field(object):
    """One decoded data field: the raw bytes tagged with their field type.

    Field types are not interpreted, so unknown or enterprise-specific
    types keep both their type number and their original bytes.
    """

    __slots__ = ('type', 'data')

    def __init__(self, field_type, data):
        self.type = field_type
        self.data = data

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return 'Netflow9Field(type=%d, data=%r)' % (self.type, self.data)


class Netflow9Record(object):
    """One decoded data record.

    fields holds every field in template order. For records described by
    an Options Template, scope_fields and option_fields additionally split
    the fields into the scope and option sections.
    """

    __slots__ = ('fields', 'scope_fields', 'option_fields')

    def __init__(self, fields, scope_fields=(), option_fields=()):
        self.fields = fields
        self.scope_fields = list(scope_fields)
        self.option_fields = list(option_fields)

    def __repr__(self):
        return 'Netflow9Record(fields=%r)' % (self.fields,)


class Netflow9DataFlowSet(Netflow9FlowSet):
    """A Data FlowSet decoded with its template.

    records holds the decoded Netflow9Record objects. padding holds any
    trailing bytes that do not make up a whole record (FlowSets are padded
    to a 32-bit boundary); it is never mistaken for an extra record.
    """

    __slots__ = ('template_id', 'template', 'records', 'padding')

    def __init__(self, data, template, records, padding):
        Netflow9FlowSet.__init__(self, template.template_id, data)
        self.template_id = template.template_id
        self.template = template
        self.records = records
        self.padding = padding


class Netflow9PendingDataFlowSet(Netflow9FlowSet):
    """A Data FlowSet whose template is not (yet) known.

    The raw FlowSet body is preserved untouched in data so the caller can
    retry decoding it with Netflow9Decoder.resolve() once the matching
    template has been learned. template_id is the FlowSet ID of the
    template this FlowSet refers to, scoped to the exporter and Source ID
    of the packet it arrived in.
    """

    __slots__ = ()

    pending = True

    def __init__(self, template_id, data):
        Netflow9FlowSet.__init__(self, template_id, data)

    @property
    def template_id(self):
        return self.id


class Netflow9Decoder(object):
    """Stateful decoder for a stream of Netflow v9 export packets.

    Templates are scoped by the caller-supplied exporter identity (any
    hashable, e.g. a (host, port) tuple), the packet Source ID and the
    Template ID, so templates from different exporters or observation
    domains never collide. Feed each received datagram to process() along
    with the identity of the exporter it came from; the returned Netflow9
    packet has its flowsets replaced by decoded Template, Options
    Template, Data or PendingData FlowSets.
    """

    def __init__(self):
        # (exporter, source_id, template_id) -> Netflow9Template
        self.templates = {}
        # (exporter, source_id) -> highest sequence number seen
        self.last_sequence = {}

    def process(self, exporter, buf):
        """Decode one export packet received from exporter."""
        packet = Netflow9(buf)
        self._track_sequence(exporter, packet)
        flowsets = []
        for flowset in packet.flowsets:
            if flowset.id == Netflow9FlowSet.TEMPLATE_ID:
                templates = self._parse_template_flowset(flowset.data)
                for template in templates:
                    self._learn_template(exporter, packet, template)
                flowsets.append(Netflow9TemplateFlowSet(flowset.data, templates))
            elif flowset.id == Netflow9FlowSet.OPTIONS_TEMPLATE_ID:
                templates = self._parse_options_template_flowset(flowset.data)
                for template in templates:
                    self._learn_template(exporter, packet, template)
                flowsets.append(Netflow9OptionsTemplateFlowSet(flowset.data, templates))
            elif flowset.id >= Netflow9FlowSet.MIN_DATA_TEMPLATE_ID:
                flowsets.append(self._decode_data_flowset(exporter, packet, flowset))
            else:
                # reserved FlowSet IDs are passed through untouched
                flowsets.append(flowset)
        packet.flowsets = flowsets
        packet.data = flowsets
        return packet

    def resolve(self, exporter, source_id, flowset):
        """Retry decoding a Netflow9PendingDataFlowSet.

        Returns a Netflow9DataFlowSet if the template has been learned by
        now, otherwise the pending FlowSet itself, unchanged.
        """
        template = self.templates.get((exporter, source_id, flowset.template_id))
        if template is None:
            return flowset
        return self._make_data_flowset(template, flowset.data)

    def restart(self, exporter, source_id=None):
        """Declare that an exporter restarted.

        Drops every template (and the sequence tracking) learned from that
        exporter, optionally limited to a single Source ID. Data received
        afterwards is reported as pending until templates are resent.
        """
        for key in [key for key in self.templates
                    if key[0] == exporter and (source_id is None or key[1] == source_id)]:
            del self.templates[key]
        for key in [key for key in self.last_sequence
                    if key[0] == exporter and (source_id is None or key[1] == source_id)]:
            del self.last_sequence[key]

    def expire(self, older_than, exporter=None):
        """Expire templates last (re)defined before the given timestamp.

        older_than is compared against the unix_sec of the packet that
        defined each template; optionally limited to a single exporter.
        """
        for key, template in list(self.templates.items()):
            if template.updated < older_than and (exporter is None or key[0] == exporter):
                del self.templates[key]

    def _track_sequence(self, exporter, packet):
        # Sequence numbers are only tracked to flag out-of-order or
        # duplicate packets; a sequence that goes backwards never clears
        # any template state, only an explicit restart() does.
        key = (exporter, packet.source_id)
        last = self.last_sequence.get(key)
        packet.out_of_order = last is not None and packet.sequence < last
        if last is None or packet.sequence > last:
            self.last_sequence[key] = packet.sequence

    def _learn_template(self, exporter, packet, template):
        # redefining a Template ID replaces the previous definition and
        # only affects Data FlowSets decoded from this point on
        template.updated = packet.unix_sec
        self.templates[(exporter, packet.source_id, template.template_id)] = template

    def _decode_data_flowset(self, exporter, packet, flowset):
        template = self.templates.get((exporter, packet.source_id, flowset.id))
        if template is None:
            return Netflow9PendingDataFlowSet(flowset.id, flowset.data)
        return self._make_data_flowset(template, flowset.data)

    def _make_data_flowset(self, template, body):
        records = []
        record_length = template.record_length
        padding = body
        if record_length:
            count = len(body) // record_length
            for index in range(count):
                chunk = body[index * record_length:(index + 1) * record_length]
                records.append(self._decode_record(template, chunk))
            padding = body[count * record_length:]
        return Netflow9DataFlowSet(body, template, records, padding)

    @staticmethod
    def _decode_record(template, chunk):
        fields = []
        scope_fields = []
        option_fields = []
        offset = 0
        for field_type, field_length in template.scope_fields:
            field = Netflow9Field(field_type, chunk[offset:offset + field_length])
            offset += field_length
            scope_fields.append(field)
            fields.append(field)
        for field_type, field_length in template.fields:
            field = Netflow9Field(field_type, chunk[offset:offset + field_length])
            offset += field_length
            if template.options:
                option_fields.append(field)
            fields.append(field)
        return Netflow9Record(fields, scope_fields, option_fields)

    @staticmethod
    def _parse_field_specifiers(buf, count):
        fields = []
        for _ in range(count):
            if len(buf) < 4:
                raise dpkt.NeedData('truncated Netflow9 template')
            field_type, field_length = struct.unpack('>HH', buf[:4])
            fields.append((field_type, field_length))
            buf = buf[4:]
        return fields, buf

    def _parse_template_flowset(self, buf):
        templates = []
        while len(buf) >= 4:
            template_id, field_count = struct.unpack('>HH', buf[:4])
            fields, buf = self._parse_field_specifiers(buf[4:], field_count)
            templates.append(Netflow9Template(template_id, fields))
        return templates

    def _parse_options_template_flowset(self, buf):
        templates = []
        while len(buf) >= 6:
            template_id, scope_length, option_length = struct.unpack('>HHH', buf[:6])
            body = buf[6:]
            if len(body) < scope_length + option_length:
                raise dpkt.NeedData('truncated Netflow9 options template')
            if scope_length % 4 or option_length % 4:
                raise dpkt.UnpackError('invalid Netflow9 options template lengths')
            scope_fields, _ = self._parse_field_specifiers(
                body[:scope_length], scope_length // 4)
            option_fields, _ = self._parse_field_specifiers(
                body[scope_length:scope_length + option_length], option_length // 4)
            templates.append(Netflow9Template(
                template_id, option_fields, scope_fields=scope_fields, options=True))
            consumed = 6 + scope_length + option_length
            # each options template record is padded to a 32-bit boundary
            pad = (-consumed) % 4
            buf = buf[consumed + pad:]
        return templates
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


def _netflow9_packet(flowsets, sequence=1, source_id=7, unix_sec=1500000000, count=0):
    body = b''.join(flowsets)
    return struct.pack('>HHIIII', 9, count, 123456, unix_sec, sequence, source_id) + body


def _netflow9_flowset(flowset_id, body):
    return struct.pack('>HH', flowset_id, 4 + len(body)) + body


def _netflow9_template_flowset(*templates):
    body = b''
    for template_id, fields in templates:
        body += struct.pack('>HH', template_id, len(fields))
        for field_type, field_length in fields:
            body += struct.pack('>HH', field_type, field_length)
    return _netflow9_flowset(0, body)


def _netflow9_options_template_flowset(template_id, scope_fields, option_fields):
    body = struct.pack('>HHH', template_id, 4 * len(scope_fields), 4 * len(option_fields))
    for field_type, field_length in scope_fields + option_fields:
        body += struct.pack('>HH', field_type, field_length)
    body += b'\x00' * ((-len(body)) % 4)
    return _netflow9_flowset(1, body)


def test_netflow9_template_and_data():
    decoder = Netflow9Decoder()
    exporter = ('10.0.0.1', 9991)

    buf = _netflow9_packet([
        _netflow9_template_flowset((256, [(8, 4), (12, 4), (999, 3)])),
    ], sequence=1)
    packet = decoder.process(exporter, buf)
    assert packet.version == 9
    assert packet.source_id == 7
    assert len(packet.flowsets) == 1
    flowset = packet.flowsets[0]
    assert isinstance(flowset, Netflow9TemplateFlowSet)
    assert flowset.templates[0].template_id == 256
    assert flowset.templates[0].record_length == 11

    # one record of 11 bytes plus 2 bytes of alignment padding
    record = b'\x0a\x00\x00\x01' + b'\x0a\x00\x00\x02' + b'\x01\x02\x03'
    buf = _netflow9_packet([_netflow9_flowset(256, record + b'\x00\x00')], sequence=2)
    packet = decoder.process(exporter, buf)
    flowset = packet.flowsets[0]
    assert isinstance(flowset, Netflow9DataFlowSet)
    assert flowset.template_id == 256
    assert len(flowset.records) == 1
    # padding is not mistaken for an extra record
    assert flowset.padding == b'\x00\x00'
    fields = flowset.records[0].fields
    assert [field.type for field in fields] == [8, 12, 999]
    assert fields[0].data == b'\x0a\x00\x00\x01'
    assert fields[1].data == b'\x0a\x00\x00\x02'
    # unknown field types keep their type number and raw bytes
    assert fields[2].type == 999
    assert fields[2].data == b'\x01\x02\x03'

    # packet round-trips byte for byte
    assert bytes(packet) == buf


def test_netflow9_interleaved_exporters():
    decoder = Netflow9Decoder()
    exporter_a = ('10.0.0.1', 9991)
    exporter_b = ('10.0.0.2', 9991)

    # both exporters (and even the same Source ID) reuse Template ID 256
    # with different layouts
    decoder.process(exporter_a, _netflow9_packet(
        [_netflow9_template_flowset((256, [(8, 4)]))], sequence=1))
    decoder.process(exporter_b, _netflow9_packet(
        [_netflow9_template_flowset((256, [(8, 4), (7, 2), (11, 2)]))], sequence=1))

    packet_a = decoder.process(exporter_a, _netflow9_packet(
        [_netflow9_flowset(256, b'\x0a\x00\x00\x01')], sequence=2))
    packet_b = decoder.process(exporter_b, _netflow9_packet(
        [_netflow9_flowset(256, b'\x0a\x00\x00\x02\x00\x50\x01\xbb')], sequence=2))

    flowset_a = packet_a.flowsets[0]
    flowset_b = packet_b.flowsets[0]
    assert isinstance(flowset_a, Netflow9DataFlowSet)
    assert isinstance(flowset_b, Netflow9DataFlowSet)
    assert len(flowset_a.records[0].fields) == 1
    assert [field.type for field in flowset_b.records[0].fields] == [8, 7, 11]
    assert flowset_b.records[0].fields[1].data == b'\x00\x50'

    # a third exporter using the same Template ID must not borrow the
    # templates learned from the others
    exporter_c = ('10.0.0.3', 9991)
    packet_c = decoder.process(exporter_c, _netflow9_packet(
        [_netflow9_flowset(256, b'\xde\xad\xbe\xef')], sequence=1))
    flowset_c = packet_c.flowsets[0]
    assert isinstance(flowset_c, Netflow9PendingDataFlowSet)
    assert flowset_c.pending
    assert flowset_c.template_id == 256
    assert flowset_c.data == b'\xde\xad\xbe\xef'


def test_netflow9_template_update_only_affects_later_data():
    decoder = Netflow9Decoder()
    exporter = 'router1'

    decoder.process(exporter, _netflow9_packet(
        [_netflow9_template_flowset((256, [(8, 4)]))], sequence=1))
    packet = decoder.process(exporter, _netflow9_packet(
        [_netflow9_flowset(256, b'\x01\x02\x03\x04')], sequence=2))
    assert len(packet.flowsets[0].records[0].fields) == 1

    # redefining Template ID 256 replaces the previous layout
    decoder.process(exporter, _netflow9_packet(
        [_netflow9_template_flowset((256, [(8, 4), (12, 4)]))], sequence=3))
    packet = decoder.process(exporter, _netflow9_packet(
        [_netflow9_flowset(256, b'\x01\x02\x03\x04\x05\x06\x07\x08')], sequence=4))
    assert len(packet.flowsets[0].records[0].fields) == 2


def test_netflow9_pending_data_and_resolve():
    decoder = Netflow9Decoder()
    exporter = 'router1'

    # data arrives before its template
    raw = b'\x0a\x00\x00\x01\x0a\x00\x00\x02'
    packet = decoder.process(exporter, _netflow9_packet(
        [_netflow9_flowset(300, raw)], sequence=1))
    pending = packet.flowsets[0]
    assert isinstance(pending, Netflow9PendingDataFlowSet)
    assert pending.template_id == 300
    assert pending.data == raw

    # still unknown: resolve returns the pending FlowSet unchanged
    assert decoder.resolve(exporter, 7, pending) is pending

    # once the template arrives, the buffered FlowSet can be interpreted
    decoder.process(exporter, _netflow9_packet(
        [_netflow9_template_flowset((300, [(8, 4), (12, 4)]))], sequence=2))
    flowset = decoder.resolve(exporter, 7, pending)
    assert isinstance(flowset, Netflow9DataFlowSet)
    assert len(flowset.records) == 1
    assert [field.type for field in flowset.records[0].fields] == [8, 12]


def test_netflow9_restart_and_expire():
    decoder = Netflow9Decoder()
    exporter_a = 'router-a'
    exporter_b = 'router-b'

    decoder.process(exporter_a, _netflow9_packet(
        [_netflow9_template_flowset((256, [(8, 4)]))], sequence=10, unix_sec=1000))
    decoder.process(exporter_b, _netflow9_packet(
        [_netflow9_template_flowset((256, [(8, 4)]))], sequence=10, unix_sec=2000))

    # expiring by template age only drops the old definition
    decoder.expire(1500)
    packet = decoder.process(exporter_a, _netflow9_packet(
        [_netflow9_flowset(256, b'\x01\x02\x03\x04')], sequence=11))
    assert isinstance(packet.flowsets[0], Netflow9PendingDataFlowSet)
    packet = decoder.process(exporter_b, _netflow9_packet(
        [_netflow9_flowset(256, b'\x01\x02\x03\x04')], sequence=11))
    assert isinstance(packet.flowsets[0], Netflow9DataFlowSet)

    # declaring an exporter restart drops only that exporter's state
    decoder.restart(exporter_b)
    packet = decoder.process(exporter_b, _netflow9_packet(
        [_netflow9_flowset(256, b'\x01\x02\x03\x04')], sequence=1))
    assert isinstance(packet.flowsets[0], Netflow9PendingDataFlowSet)


def test_netflow9_out_of_order_keeps_templates():
    decoder = Netflow9Decoder()
    exporter = 'router1'

    decoder.process(exporter, _netflow9_packet(
        [_netflow9_template_flowset((256, [(8, 4)]))], sequence=100))
    # an out-of-order packet is flagged but must not clear any state
    packet = decoder.process(exporter, _netflow9_packet(
        [_netflow9_flowset(256, b'\x0a\x00\x00\x01')], sequence=3))
    assert packet.out_of_order
    assert isinstance(packet.flowsets[0], Netflow9DataFlowSet)
    assert packet.flowsets[0].records[0].fields[0].data == b'\x0a\x00\x00\x01'


def test_netflow9_options_template():
    decoder = Netflow9Decoder()
    exporter = 'router1'

    decoder.process(exporter, _netflow9_packet([
        _netflow9_options_template_flowset(256, [(2, 4)], [(4, 1), (5, 2)]),
    ], sequence=1))

    # scope (4 bytes) + options (1 + 2 bytes) = 7 bytes per record,
    # followed by 1 byte of padding
    raw = b'\x00\x00\x00\x02' + b'\x03' + b'\x00\x78' + b'\x00'
    packet = decoder.process(exporter, _netflow9_packet(
        [_netflow9_flowset(256, raw)], sequence=2))
    flowset = packet.flowsets[0]
    assert isinstance(flowset, Netflow9DataFlowSet)
    assert flowset.template.options
    assert len(flowset.records) == 1
    assert flowset.padding == b'\x00'
    record = flowset.records[0]
    assert [field.type for field in record.scope_fields] == [2]
    assert record.scope_fields[0].data == b'\x00\x00\x00\x02'
    assert [field.type for field in record.option_fields] == [4, 5]
    assert record.option_fields[1].data == b'\x00\x78'
    assert len(record.fields) == 3
