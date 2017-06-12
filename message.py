#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol messages.
"""
import logging
import os

from collections import OrderedDict
from ipaddress import ip_address, ip_network
from random import SystemRandom
from struct import error as struct_error, pack, pack_into, unpack_from

from crypto import Cipher, DiffieHellman, ESN, Integrity, Prf

from helpers import SafeIntEnum, hexstring

__author__ = 'Alejandro Perez <alex@um.es>'


class IkeSaError(Exception):
    pass


class ChildSaError(Exception):
    pass


class InvalidSyntax(IkeSaError):
    pass


class UnsupportedCriticalPayload(IkeSaError):
    pass


class NoProposalChosen(IkeSaError):
    pass


class InvalidKePayload(IkeSaError):
    def __init__(self, msg, group):
        super(InvalidKePayload, self).__init__(self, msg)
        self.group = group


class AuthenticationFailed(IkeSaError):
    pass


class InvalidSelectors(IkeSaError):
    pass


class PayloadNotFound(IkeSaError):
    pass


class ChildSaNotFound(ChildSaError):
    def __init__(self, msg, spi):
        super(ChildSaNotFound, self).__init__(self, msg)
        self.spi = spi


class Payload:
    class Type(SafeIntEnum):
        NONE = 0
        SA = 33
        KE = 34
        IDi = 35
        IDr = 36
        CERT = 37
        CERTREQ = 38
        AUTH = 39
        NONCE = 40
        NOTIFY = 41
        DELETE = 42
        VENDOR = 43
        TSi = 44
        TSr = 45
        SK = 46
        CP = 47
        EAP = 48

    type = Type.NONE

    def __init__(self, critical=False):
        self.critical = critical

    def to_dict(self):
        return OrderedDict([
            ('type', Payload.Type.safe_name(self.type)),
            ('critical', self.critical)])


class PayloadKE(Payload):
    type = Payload.Type.KE

    def __init__(self, dh_group, ke_data, critical=False):
        super(PayloadKE, self).__init__(critical)
        self.dh_group = dh_group
        self.ke_data = ke_data

    @classmethod
    def parse(cls, data, critical=False):
        try:
            dh_group, _, = unpack_from('>2H', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload KE.')
        return PayloadKE(dh_group, data[4:], critical)

    def to_bytes(self):
        data = bytearray(pack('>2H', self.dh_group, 0))
        data += self.ke_data
        return data

    def to_dict(self):
        result = super(PayloadKE, self).to_dict()
        result.update(OrderedDict([
            ('dh_group', self.dh_group),
            ('ke_data', hexstring(self.ke_data))]))
        return result


class Transform:
    class Type(SafeIntEnum):
        ENCR = 1
        PRF = 2
        INTEG = 3
        DH = 4
        ESN = 5

    _transform_id_enums = {
        Type.ENCR: Cipher.Id,
        Type.PRF: Prf.Id,
        Type.INTEG: Integrity.Id,
        Type.DH: DiffieHellman.Id,
        Type.ESN: ESN.Id,
    }

    def __init__(self, type, id, keylen=None):
        self.type = type
        self.id = id
        self.keylen = keylen

    @classmethod
    def parse(cls, data):
        try:
            type, _, id = unpack_from('>BBH', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Tranform.')
        offset = 4
        keylen = None
        while offset < len(data):
            try:
                # TODO: Change this to attr_type, attr_value = ...
                attribute = unpack_from('>HH', data, offset)
            except struct_error:
                raise InvalidSyntax('Error parsing Transform attribute.')
            # Not used as we only care about the KEYLEN attribute
            # is_tv = attribute[0] >> 15
            # attr_type = attribute[0] & 0x7FFF
            # if we find a KeyLen attribute, we can abort to save some cycles
            if attribute[0] == (14 | 0x8000):
                keylen = attribute[1]
                break
            offset += 4
        return Transform(type, id, keylen)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.type, 0, self.id))
        if self.keylen:
            data += pack('>HH', (14 | 0x8000), self.keylen)
        return data

    def to_dict(self):
        id_name = Transform._transform_id_enums[self.type].safe_name(self.id)
        result = OrderedDict([
            ('type', Transform.Type.safe_name(self.type)),
            ('id', id_name)])
        if self.keylen:
            result['keylen'] = self.keylen
        return result

    def __hash__(self):
        return hash((self.type, self.id, self.keylen),)

    def __eq__(self, other):
        return hash(self) == hash(other)


class Proposal:
    class Protocol(SafeIntEnum):
        NONE = 0
        IKE = 1
        AH = 2
        ESP = 3

    def __init__(self, num, protocol_id, spi, transforms):
        self.num = num
        self.protocol_id = protocol_id
        self.spi = spi
        self.transforms = transforms
        if len(self.transforms) == 0:
            raise InvalidSyntax('A proposal without transforms is not allowed')

    @classmethod
    def parse(cls, data):
        try:
            num, protocol_id, spi_size, n_transforms = unpack_from('>BBBB', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Proposal')

        if spi_size > 0:
            spi = data[4:4 + spi_size]
        else:
            spi = b''

        # iterate over the transforms (if any)
        offset = 4 + spi_size
        transforms = []
        while offset < len(data):
            try:
                more, _, length = unpack_from('>BBH', data, offset)
            except struct_error as ex:
                raise InvalidSyntax('Error parsing Transform header') from ex
            start = offset + 4
            end = offset + length
            transform = Transform.parse(data[start:end])
            transforms.append(transform)
            offset += length

        if n_transforms != len(transforms):
            raise InvalidSyntax('Indicated # of transforms ({}) differs from the actual # of '
                                ' transforms ({})'.format(n_transforms, len(transforms)))

        return Proposal(num, protocol_id, spi, transforms)

    def to_bytes(self):
        data = bytearray(pack('>BBBB', self.num, self.protocol_id, len(self.spi),
                              len(self.transforms)))
        if len(self.spi):
            data += self.spi

        for index in range(0, len(self.transforms)):
            transform = self.transforms[index]
            transform_data = transform.to_bytes()
            data += pack('>BBH', 0 if index == len(self.transforms) - 1 else 3, 0,
                         len(transform_data) + 4)
            data += transform_data

        return data

    def to_dict(self):
        return OrderedDict([
            ('num', self.num),
            ('protocol_id', Proposal.Protocol.safe_name(self.protocol_id)),
            ('spi', hexstring(self.spi)),
            ('transforms', [x.to_dict() for x in self.transforms]),
        ])

    def get_transform(self, type):
        return next(x for x in self.transforms if x.type == type)

    def get_transforms(self, type):
        return [x for x in self.transforms if x.type == type]

    def intersection(self, other):
        """ Returns the intersection between this Proposal and other Proposal
            It contains one Transform per type (e.g. ENCR, AUTH, DH...)
            The Proposal num and SPI values are taken from "other"
        """
        if self.protocol_id == other.protocol_id:
            selected = {}
            for my_transform in self.transforms:
                for peer_transform in other.transforms:
                    if my_transform == peer_transform and my_transform.type not in selected:
                        selected[my_transform.type] = my_transform
            # If we have a transform of each type => success
            if set(selected) == set(x.type for x in self.transforms):
                return Proposal(other.num, self.protocol_id, other.spi, list(selected.values()))
        return None

    def __eq__(self, other):
        return ((self.num, self.protocol_id, self.spi, set(self.transforms))
                == (other.num, other.protocol_id, other.spi, set(other.transforms)))

    def is_subset(self, other):
        intersection = self.intersection(other)
        return (intersection is not None) and (intersection == self)


class PayloadSA(Payload):
    type = Payload.Type.SA

    def __init__(self, proposals, critical=False):
        super(PayloadSA, self).__init__(critical)
        self.proposals = proposals
        if len(self.proposals) == 0:
            raise InvalidSyntax('Emtpy Payload SA is not allowed')

    @classmethod
    def parse(cls, data, critical=False):
        proposals = []
        # iterate over the proposals (if any)
        if len(data):
            offset = 0
            while offset < len(data):
                more, _, length = unpack_from('>BBH', data)
                start = offset + 4
                end = offset + length
                proposal = Proposal.parse(data[start:end])
                proposals.append(proposal)
                offset += length
        return PayloadSA(proposals, critical=critical)

    def to_bytes(self):
        data = bytearray()
        for index in range(0, len(self.proposals)):
            proposal_data = self.proposals[index].to_bytes()
            data += pack('>BBH', 0 if index == len(self.proposals) - 1 else 2, 0,
                         len(proposal_data) + 4)
            data += proposal_data
        return data

    def to_dict(self):
        result = super(PayloadSA, self).to_dict()
        result.update(OrderedDict([
            ('proposals', [x.to_dict() for x in self.proposals])]))
        return result


class PayloadVENDOR(Payload):
    type = Payload.Type.VENDOR

    def __init__(self, vendor_id, critical=False):
        super(PayloadVENDOR, self).__init__(critical)
        if len(vendor_id) == 0:
            raise InvalidSyntax('Vendor ID should have some data.')
        self.vendor_id = vendor_id

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadVENDOR(data, critical)

    def to_bytes(self):
        return self.vendor_id

    def to_dict(self):
        result = super(PayloadVENDOR, self).to_dict()
        result.update(OrderedDict([
            ('vendor_id', self.vendor_id.decode())]))
        return result


class PayloadNONCE(Payload):
    type = Payload.Type.NONCE

    def __init__(self, nonce=None, critical=False):
        super(PayloadNONCE, self).__init__(critical)
        if nonce is not None:
            if len(nonce) < 16 or len(nonce) > 256:
                raise InvalidSyntax('Invalid Payload NONCE length: {}'.format(len(nonce)))
            self.nonce = nonce
        else:
            random = SystemRandom()
            length = random.randrange(16, 256)
            self.nonce = os.urandom(length)

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadNONCE(data, critical)

    def to_bytes(self):
        return self.nonce

    def to_dict(self):
        result = super(PayloadNONCE, self).to_dict()
        result.update(OrderedDict([('nonce', hexstring(self.nonce))]))
        return result


class PayloadNOTIFY(Payload):
    type = Payload.Type.NOTIFY

    class Type(SafeIntEnum):
        UNSUPPORTED_CRITICAL_PAYLOAD = 1
        INVALID_IKE_SPI = 4
        INVALID_MAJOR_VERSION = 5
        INVALID_SYNTAX = 7
        INVALID_MESSAGE_ID = 9
        INVALID_SPI = 11
        NO_PROPOSAL_CHOSEN = 14
        INVALID_KE_PAYLOAD = 17
        AUTHENTICATION_FAILED = 24
        SINGLE_PAIR_REQUIRED = 34
        NO_ADDITIONAL_SAS = 35
        INTERNAL_ADDRESS_FAILURE = 36
        FAILED_CP_REQUIRED = 37
        TS_UNACCEPTABLE = 38
        INVALID_SELECTORS = 39
        TEMPORARY_FAILURE = 43
        CHILD_SA_NOT_FOUND = 44
        INITIAL_CONTACT = 16384
        SET_WINDOW_SIZE = 16385
        ADDITIONAL_TS_POSSIBLE = 16386
        IPCOMP_SUPPORTED = 16387
        NAT_DETECTION_SOURCE_IP = 16388
        NAT_DETECTION_DESTINATION_IP = 16389
        COOKIE = 16390
        USE_TRANSPORT_MODE = 16391
        HTTP_CERT_LOOKUP_SUPPORTED = 16392
        REKEY_SA = 16393
        ESP_TFC_PADDING_NOT_SUPPORTED = 16394
        NON_FIRST_FRAGMENTS_ALSO = 16395

    def __init__(self, protocol_id, notification_type, spi, notification_data, critical=False):
        super(PayloadNOTIFY, self).__init__(critical)
        self.protocol_id = protocol_id
        self.notification_type = notification_type
        self.spi = spi
        self.notification_data = notification_data

    @classmethod
    def parse(cls, data, critical=False):
        try:
            (protocol_id, spi_size, notification_type) = unpack_from('>BBH', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload Notify.')
        if spi_size > 0:
            spi = data[4:4 + spi_size]
        else:
            spi = b''
        notification_data = data[4 + spi_size:]
        return PayloadNOTIFY(protocol_id, notification_type, spi, notification_data,
                             critical=critical)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.protocol_id, len(self.spi), self.notification_type))
        if len(self.spi) > 0:
            data += self.spi
        data += self.notification_data
        return data

    def to_dict(self):
        result = super(PayloadNOTIFY, self).to_dict()
        result.update(OrderedDict([
            ('protocol_id', Proposal.Protocol.safe_name(self.protocol_id)),
            ('spi', hexstring(self.spi)),
            ('notification_type', PayloadNOTIFY.Type.safe_name(self.notification_type)),
            ('notification_data', hexstring(self.notification_data))]))
        return result


class PayloadID(Payload):
    type = None

    class Type(SafeIntEnum):
        ID_IPV4_ADDR = 1
        ID_FQDN = 2
        ID_RFC822_ADDR = 3
        ID_IPV6_ADDR = 5
        ID_DER_ASN1_DN = 9
        ID_DER_ASN1_GN = 10
        ID_KEY_ID = 11

    def __init__(self, id_type, id_data, critical=False):
        super(PayloadID, self).__init__(critical)
        self.id_type = id_type
        self.id_data = id_data

    @classmethod
    def parse(cls, data, critical=False):
        try:
            id_type, _ = unpack_from('>B3s', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload ID.')
        id_data = data[4:]
        # we need to use cls as it might be PayloadIDi or PayloadIDr
        return cls(id_type, id_data, critical=critical)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.id_type, 0, 0))
        data += self.id_data
        return data

    def _id_data_str(self):
        if self.id_type in (PayloadID.Type.ID_RFC822_ADDR, PayloadID.Type.ID_FQDN):
            return self.id_data.decode()
        elif self.id_type in (PayloadID.Type.ID_IPV4_ADDR, PayloadID.Type.ID_IPV6_ADDR):
            return str(ip_address(self.id_data.decode())),
        else:
            return hexstring(self.id_data)

    def to_dict(self):
        result = super(PayloadID, self).to_dict()
        result.update(OrderedDict([
            ('id_type', PayloadID.Type.safe_name(self.id_type)),
            ('id_data', self._id_data_str()), ]))
        return result


class PayloadIDi(PayloadID):
    type = Payload.Type.IDi


class PayloadIDr(PayloadID):
    type = Payload.Type.IDr


class PayloadAUTH(Payload):
    type = Payload.Type.AUTH

    class Method(SafeIntEnum):
        RSA = 1
        PSK = 2
        DSS = 3

    def __init__(self, method, auth_data, critical=False):
        super(PayloadAUTH, self).__init__(critical)
        self.method = method
        self.auth_data = auth_data

    @classmethod
    def parse(cls, data, critical=False):
        try:
            method, _ = unpack_from('>B3s', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload AUTH.')
        auth_data = data[4:]
        return PayloadAUTH(method, auth_data, critical=critical)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.method, 0, 0))
        data += self.auth_data
        return data

    def to_dict(self):
        result = super(PayloadAUTH, self).to_dict()
        result.update(OrderedDict([
            ('method', PayloadAUTH.Method.safe_name(self.method)),
            ('auth_data', hexstring(self.auth_data)), ]))
        return result


class TrafficSelector(object):
    class Type(SafeIntEnum):
        TS_IPV4_ADDR_RANGE = 7
        TS_IPV6_ADDR_RANGE = 8

    class IpProtocol(SafeIntEnum):
        ANY = 0
        ICMP = 1
        TCP = 6
        UDP = 17
        ICMPv6 = 58
        MH = 135

    def __init__(self, ts_type, ip_proto, start_port, end_port, start_addr, end_addr):
        self.ts_type = ts_type
        self.ip_proto = ip_proto
        self.start_port = start_port
        self.end_port = end_port
        self.start_addr = start_addr
        self.end_addr = end_addr

    @classmethod
    def from_network(cls, subnet, port, ip_proto):
        return TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE, ip_proto, port,
                               65535 if port == 0 else port, subnet[0], subnet[-1])

    def get_network(self):
        network = ip_network(self.start_addr)
        while self.end_addr not in network:
            network = network.supernet()
        return network

    def get_port(self):
        if self.start_port == 0 and self.end_port == 65535:
            return 0
        else:
            return self.end_port

    @classmethod
    def parse(cls, data):
        try:
            ts_type, ip_proto, _, start_port, end_port = unpack_from('>BBHHH', data)
            addr_len = (4 if ts_type == TrafficSelector.Type.TS_IPV4_ADDR_RANGE else 16)
            start_addr, end_addr = unpack_from('>{0}s{0}s'.format(addr_len), data, 8)
        except struct_error:
            raise InvalidSyntax('Error parsing Traffic selector.')
        return TrafficSelector(ts_type, ip_proto, start_port, end_port, ip_address(start_addr),
                               ip_address(end_addr))

    def to_bytes(self):
        addr_len = (4 if self.ts_type == TrafficSelector.Type.TS_IPV4_ADDR_RANGE else 16)
        return pack('>BBHHH{0}s{0}s'.format(addr_len), self.ts_type, self.ip_proto,
                    8 + addr_len * 2, self.start_port, self.end_port, self.start_addr.packed,
                    self.end_addr.packed)

    def to_dict(self):
        return OrderedDict([
            ('ts_type', TrafficSelector.Type.safe_name(self.ts_type)),
            ('ip_proto', TrafficSelector.IpProtocol.safe_name(self.ip_proto)),
            ('port-range', '{} - {}'.format(self.start_port, self.end_port)),
            ('addr-range', '{} - {}'.format(self.start_addr, self.end_addr))])

    def is_subset(self, other):
        if self.ts_type != other.ts_type:
            return False

        if other.ip_proto != TrafficSelector.IpProtocol.ANY and self.ip_proto != other.ip_proto:
            return False

        if self.start_port < other.start_port or self.end_port > other.end_port:
            return False

        if self.start_addr < other.start_addr or self.end_addr > other.end_addr:
            return False

        return True

    def __eq__(self, other):
        return ((self.ts_type, self.ip_proto, self.start_port, self.end_port, self.start_addr,
                 self.end_addr)
                == (other.ts_type, other.ip_proto, other.start_port, other.end_port,
                    other.start_addr, other.end_addr))


class PayloadTS(Payload):
    type = None

    def __init__(self, traffic_selectors, critical=False):
        super(PayloadTS, self).__init__(critical)
        self.traffic_selectors = traffic_selectors

    @classmethod
    def parse(cls, data, critical=False):
        try:
            n_ts, _ = unpack_from('>B3s', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload TS.')
        traffic_selectors = []
        offset = 4
        while offset < len(data):
            # parse TSs
            try:
                _, length = unpack_from('>HH', data, offset)
            except struct_error:
                raise InvalidSyntax('Error parsing Traffic selector.')
            ts = TrafficSelector.parse(data[offset:offset + length])
            traffic_selectors.append(ts)
            offset += length
        if n_ts != len(traffic_selectors):
            raise InvalidSyntax('Payload TS has invalid number of selectors. Expected {} got {}'
                                ''.format(n_ts, len(traffic_selectors)))
        # we need to use cls as it might be PayloadTSi or PayloadTSr
        return cls(traffic_selectors, critical=critical)

    def to_bytes(self):
        data = bytearray(pack('>BBH', len(self.traffic_selectors), 0, 0))
        for ts in self.traffic_selectors:
            data += ts.to_bytes()
        return data

    def to_dict(self):
        result = super(PayloadTS, self).to_dict()
        result.update(OrderedDict([
            ('traffic_selectors', [x.to_dict() for x in self.traffic_selectors])]))
        return result


class PayloadTSi(PayloadTS):
    type = Payload.Type.TSi


class PayloadTSr(PayloadTS):
    type = Payload.Type.TSr


class PayloadSK(Payload):
    type = Payload.Type.SK

    def __init__(self, ciphertext, critical=False):
        super(PayloadSK, self).__init__(critical)
        self.ciphertext = ciphertext

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadSK(data, critical)

    def to_bytes(self):
        return self.ciphertext

    def decrypt(self, crypto):
        iv = self.ciphertext[:crypto.cipher.block_size]
        ciphertext = self.ciphertext[crypto.cipher.block_size:-crypto.integrity.hash_size]
        decrypted = crypto.cipher.decrypt(crypto.sk_e, bytes(iv), bytes(ciphertext))
        padlen = decrypted[-1]
        return decrypted[:-1 - padlen]

    @classmethod
    def generate(cls, cleartext, crypto):
        iv = crypto.cipher.generate_iv()
        padlen = (crypto.cipher.block_size - (len(cleartext) % crypto.cipher.block_size) - 1)
        cleartext += b'\x00' * padlen + pack('>B', padlen)
        encrypted = crypto.cipher.encrypt(crypto.sk_e, bytes(iv), bytes(cleartext))
        return PayloadSK(iv + encrypted + b'\x00' * crypto.integrity.hash_size)

    def to_dict(self):
        result = super(PayloadSK, self).to_dict()
        result.update(OrderedDict([('ciphertext', hexstring(self.ciphertext))]))
        return result


class PayloadDELETE(Payload):
    type = Payload.Type.DELETE

    def __init__(self, protocol_id, spis, critical=False):
        super(PayloadDELETE, self).__init__(critical)
        self.protocol_id = protocol_id
        self.spis = spis

    @classmethod
    def parse(cls, data, critical=False):
        try:
            protocol_id, spi_size, num_spis = unpack_from('>BBH', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload DELETE.')
        spis = []
        offset = 4
        for i in range(0, num_spis):
            spis.append(data[offset:offset + spi_size])
            offset += spi_size
        return PayloadDELETE(protocol_id, spis, critical=critical)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.protocol_id, len(self.spis[0]) if self.spis else 0,
                              len(self.spis)))
        for spi in self.spis:
            data += spi
        return data

    def to_dict(self):
        result = super(PayloadDELETE, self).to_dict()
        result.update(OrderedDict([
            ('protocol_id', Proposal.Protocol.safe_name(self.protocol_id)),
            ('spis', [hexstring(x) for x in self.spis])]))
        return result


class Message:
    class Exchange(SafeIntEnum):
        IKE_SA_INIT = 34
        IKE_AUTH = 35
        CREATE_CHILD_SA = 36
        INFORMATIONAL = 37

    type_2_payload = {
        Payload.Type.SA: PayloadSA,
        Payload.Type.KE: PayloadKE,
        Payload.Type.IDi: PayloadIDi,
        Payload.Type.IDr: PayloadIDr,
        Payload.Type.AUTH: PayloadAUTH,
        Payload.Type.NONCE: PayloadNONCE,
        Payload.Type.VENDOR: PayloadVENDOR,
        Payload.Type.NOTIFY: PayloadNOTIFY,
        Payload.Type.TSi: PayloadTSi,
        Payload.Type.TSr: PayloadTSr,
        Payload.Type.SK: PayloadSK,
        Payload.Type.DELETE: PayloadDELETE,
    }

    def __init__(self, spi_i, spi_r, major, minor, exchange_type, is_response,
                 can_use_higher_version, is_initiator, message_id, payloads, encrypted_payloads):
        self.spi_i = spi_i
        self.spi_r = spi_r
        self.major = major
        self.minor = minor
        self.exchange_type = exchange_type
        self.is_response = is_response
        self.can_use_higher_version = can_use_higher_version
        self.is_initiator = is_initiator
        self.message_id = message_id
        self.payloads = payloads
        self.encrypted_payloads = encrypted_payloads

    @classmethod
    def _parse_payloads(cls, data, first_payload_type):
        payloads = []
        offset = 0
        payload_type = first_payload_type

        while payload_type != Payload.Type.NONE:
            # Read payload common header
            try:
                (next_payload_type, critical, length) = unpack_from('>BBH', data, offset)
            except struct_error as ex:
                raise InvalidSyntax(ex)
            critical = bool(critical >> 7)
            start = offset + 4
            end = offset + length
            # Parse the payload. If not known and critical, raise exception
            try:
                payload_class = cls.type_2_payload[payload_type]
                payload = payload_class.parse(data[start:end], critical)
                # If payload SK, annotate next_payload_type and set it to NONE
                if payload_type == Payload.Type.SK:
                    payload.next_payload_type = next_payload_type
                    next_payload_type = Payload.Type.NONE
                # offset is increased in any case
                payloads.append(payload)
            except KeyError:
                logging.warning(
                    'Unrecognized payload with type {}'.format(
                        Payload.Type.safe_name(payload_type)))
                if critical:
                    raise UnsupportedCriticalPayload

            offset += length
            payload_type = next_payload_type

        # check we read all the data
        if offset != len(data):
            raise InvalidSyntax('Amount of actual payload data {} differs from'
                                ' message length {}'.format(offset, len(data)))

        return payloads

    @classmethod
    def parse(cls, data, header_only=False, crypto=None):
        try:
            header = unpack_from('>8s8s4B2L', data)
        except struct_error as ex:
            raise InvalidSyntax(ex)

        message = Message(
            spi_i=header[0],
            spi_r=header[1],
            major=header[3] >> 4,
            minor=header[3] & 0x0F,
            exchange_type=header[4],
            is_response=bool(header[5] & 0x20),
            can_use_higher_version=bool(header[5] & 0x10),
            is_initiator=bool(header[5] & 0x08),
            message_id=header[6],
            payloads=[],
            encrypted_payloads=[],
        )

        if not header_only:
            # parse unencrypted payloads
            message.payloads = cls._parse_payloads(data[28:], header[2])

            # if there is a Payload SK
            if (message.payloads and message.payloads[-1].type == Payload.Type.SK
                    and crypto is not None):
                # read the payload SK and remove it from the list
                payload_sk = message.payloads.pop()

                # check integrity
                checksum = crypto.integrity.compute(crypto.sk_a,
                                                    data[:-crypto.integrity.hash_size])
                if checksum != data[-crypto.integrity.hash_size:]:
                    raise InvalidSyntax('CHECKSUM ERROR')

                # parse decrypted payloads and remove Payload SK
                decrypted_data = payload_sk.decrypt(crypto)
                message.encrypted_payloads = cls._parse_payloads(decrypted_data,
                                                                 payload_sk.next_payload_type)
        return message

    @staticmethod
    def _payloads_to_bytes(payloads):
        # generate payloads
        payloads_data = bytearray()
        for index in range(0, len(payloads)):
            payload = payloads[index]
            payload_data = payload.to_bytes()
            if index < len(payloads) - 1:
                next_payload_type = payloads[index + 1].type
            elif payload.type == Payload.Type.SK:
                next_payload_type = payload.next_payload_type
            else:
                next_payload_type = Payload.Type.NONE

            payloads_data += pack('>BBH', next_payload_type, 0, len(payload_data) + 4)
            payloads_data += payload_data
        return payloads_data

    def to_bytes(self, crypto=None):
        # create a temporary copy of payloads list
        _payloads = self.payloads[:]

        # if crypto is provided, encrypt everything into a SK payload
        if (crypto is not None
                and self.exchange_type != Message.Exchange.IKE_SA_INIT):
            cleartext = self._payloads_to_bytes(self.encrypted_payloads)
            payload_sk = PayloadSK.generate(cleartext, crypto)
            payload_sk.next_payload_type = (self.encrypted_payloads[0].type
                                            if self.encrypted_payloads else Payload.Type.NONE)
            _payloads.append(payload_sk)

        # generate header_data
        first_payload_type = _payloads[0].type if _payloads else Payload.Type.NONE
        header_data = bytearray(pack(
            '>8s8s4B2L', self.spi_i, self.spi_r, first_payload_type,
            (self.major << 4 | self.minor & 0x0F), self.exchange_type,
            (self.is_response << 5 | self.can_use_higher_version << 4 | self.is_initiator << 3),
            self.message_id, 28))

        # generate payloads
        payloads_data = self._payloads_to_bytes(_payloads)

        # generate final data
        data = header_data + payloads_data

        # update length once we know it
        pack_into('>L', data, 24, len(data))

        # calculate checksum (if payload SK is present)
        if crypto is not None and _payloads[-1].type == Payload.Type.SK:
            # check integrity
            checksum = crypto.integrity.compute(crypto.sk_a, data[:-crypto.integrity.hash_size])
            pack_into('>{}s'.format(len(checksum)), data, len(data) - len(checksum), checksum)

        return data

    def to_dict(self):
        return OrderedDict([
            ('spi_i', hexstring(self.spi_i)),
            ('spi_r', hexstring(self.spi_r)),
            ('major', self.major),
            ('minor', self.minor),
            ('exchange_type', Message.Exchange.safe_name(self.exchange_type)),
            ('is_request', self.is_request),
            ('is_response', self.is_response),
            ('can_use_higher_version', self.can_use_higher_version),
            ('is_initiator', self.is_initiator),
            ('is_responder', self.is_responder),
            ('message_id', self.message_id),
            ('payloads', [x.to_dict() for x in self.payloads]),
            ('encrypted_payloads', [x.to_dict() for x in self.encrypted_payloads])])

    @property
    def is_request(self):
        return not self.is_response

    @property
    def is_responder(self):
        return not self.is_initiator

    def get_notifies(self, notification_type, encrypted=False):
        notifies = self.get_payloads(Payload.Type.NOTIFY, encrypted)
        return [x for x in notifies if x.notification_type == notification_type]

    def get_payloads(self, payload_type, encrypted=False):
        collection = self.payloads if not encrypted else self.encrypted_payloads
        return [x for x in collection if x.type == payload_type]

    def get_payload(self, payload_type, encrypted=False):
        try:
            return self.get_payloads(payload_type, encrypted)[0]
        except IndexError:
            raise PayloadNotFound('Required payload {} was not found in message'
                                  ''.format(Payload.Type.safe_name(payload_type)))
