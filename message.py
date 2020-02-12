#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol messages.
"""
import logging
import os
from collections import OrderedDict
from enum import Enum
from ipaddress import ip_address, ip_network
from random import SystemRandom
from struct import error as struct_error, pack, pack_into, unpack_from

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class IkeSaError(Exception):
    pass


class InvalidSyntax(IkeSaError):
    pass


class UnsupportedCriticalPayload(IkeSaError):
    pass


class NoProposalChosen(IkeSaError):
    pass


class InvalidKePayload(IkeSaError):
    def __init__(self, msg, group):
        super().__init__(msg)
        self.group = group


class CookieRequired(IkeSaError):
    def __init__(self, msg, cookie):
        super().__init__(msg)
        self.cookie = cookie


class AuthenticationFailed(IkeSaError):
    pass


class PayloadNotFound(IkeSaError):
    pass


class TemporaryFailure(IkeSaError):
    pass


class TsUnacceptable(IkeSaError):
    pass


class ChildSaNotFound(IkeSaError):
    def __init__(self, msg, spi, protocol):
        super().__init__(msg)
        self.spi = spi
        self.protocol = protocol


class SafeIntEnum(int, Enum):
    @classmethod
    def _missing_(cls, value):
        obj = int.__new__(cls, value)
        obj._name_ = f'{cls.__name__}_{value}'
        obj._value_ = value
        return obj


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
            ('type', self.type.name),
            ('critical', self.critical)])

    def __str__(self):
        return self.type.name


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
            ('ke_data', self.ke_data.hex())]))
        return result


class Transform:
    class Type(SafeIntEnum):
        ENCR = 1
        PRF = 2
        INTEG = 3
        DH = 4
        ESN = 5

    class EncrId(SafeIntEnum):
        ENCR_DES = 2
        ENCR_3DES = 3
        ENCR_RC5 = 4
        ENCR_IDEA = 5
        ENCR_CAST = 6
        ENCR_BLOWFISH = 7
        ENCR_3IDEA = 8
        ENCR_DES_IV32 = 9
        ENCR_NULL = 11
        ENCR_AES_CBC = 12
        ENCR_AES_CTR = 13

    class PrfId(SafeIntEnum):
        PRF_HMAC_MD5 = 1
        PRF_HMAC_SHA1 = 2
        PRF_HMAC_TIGER = 3
        PRF_HMAC_SHA2_256 = 5
        PRF_HMAC_SHA2_384 = 6
        PRF_HMAC_SHA2_512 = 7

    class DhId(SafeIntEnum):
        DH_NONE = 0
        DH_1 = 1
        DH_2 = 2
        DH_5 = 5
        DH_14 = 14
        DH_15 = 15
        DH_16 = 16
        DH_17 = 17
        DH_18 = 18
        DH_19 = 19
        DH_20 = 20
        DH_21 = 21

    class IntegId(SafeIntEnum):
        INTEG_NONE = 0
        AUTH_HMAC_MD5_96 = 1
        AUTH_HMAC_SHA1_96 = 2
        AUTH_DES_MAC = 3
        AUTH_KPDK_MD5 = 4
        AUTH_AES_XCBC_96 = 5
        AUTH_HMAC_SHA2_256_128 = 12
        AUTH_HMAC_SHA2_512_256 = 14

    class EsnId(SafeIntEnum):
        NO_ESN = 0
        ESN = 1

    _transform_id_enums = {
        Type.ENCR: EncrId,
        Type.PRF: PrfId,
        Type.INTEG: IntegId,
        Type.DH: DhId,
        Type.ESN: EsnId
    }

    def __init__(self, type, id, keylen=None):
        self.type = self.Type(type)
        self.id = self._transform_id_enums.get(type, self.EncrId)(id)
        self.keylen = keylen

    @classmethod
    def parse(cls, data):
        try:
            type, _, id = unpack_from('>BBH', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Transform.')
        offset = 4
        while offset < len(data):
            try:
                attr_type, attr_value = unpack_from('>HH', data, offset)
            except struct_error:
                raise InvalidSyntax('Error parsing Transform attribute.')
            # We only care about the KEYLEN attribute, so if we find a KeyLen attribute,
            # we can abort to save some cycles
            if attr_type & 0x7FFF == 14:
                return Transform(type, id, attr_value)
            offset += 4
        return Transform(type, id, None)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.type, 0, self.id))
        if self.keylen:
            data += pack('>HH', (14 | 0x8000), self.keylen)
        return data

    def to_dict(self):
        result = OrderedDict([('type', self.type.name),
                              ('id', self.id.name)])
        if self.keylen:
            result['keylen'] = self.keylen
        return result

    def __hash__(self):
        return hash((self.type, self.id, self.keylen), )

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
        self.protocol_id = self.Protocol(protocol_id)
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
        data = bytearray(pack('>BBBB', self.num, self.protocol_id, len(self.spi), len(self.transforms)))
        if len(self.spi):
            data += self.spi

        for index in range(0, len(self.transforms)):
            transform = self.transforms[index]
            transform_data = transform.to_bytes()
            data += pack('>BBH', 0 if index == len(self.transforms) - 1 else 3, 0, len(transform_data) + 4)
            data += transform_data

        return data

    def to_dict(self):
        return OrderedDict([
            ('num', self.num),
            ('protocol_id', self.protocol_id.name),
            ('spi', self.spi.hex()),
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
        return ((self.protocol_id, set(self.transforms))
                == (other.protocol_id, set(other.transforms)))

    def is_subset(self, other):
        intersection = self.intersection(other)
        return (intersection is not None) and (intersection == self)

    def copy_without_dh_transforms(self):
        return Proposal(self.num, self.protocol_id, self.spi,
                        [x for x in self.transforms if x.type != Transform.Type.DH])


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
            data += pack('>BBH', 0 if index == len(self.proposals) - 1 else 2, 0, len(proposal_data) + 4)
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
        result.update(OrderedDict([('nonce', self.nonce.hex())]))
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
        self.protocol_id = Proposal.Protocol(protocol_id)
        self.notification_type = self.Type(notification_type)
        self.spi = spi
        self.notification_data = notification_data

    @classmethod
    def from_exception(cls, ex):
        exception_2_notify = {
            NoProposalChosen: PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN,
            UnsupportedCriticalPayload: PayloadNOTIFY.Type.UNSUPPORTED_CRITICAL_PAYLOAD,
            InvalidSyntax: PayloadNOTIFY.Type.INVALID_SYNTAX,
            AuthenticationFailed: PayloadNOTIFY.Type.AUTHENTICATION_FAILED,
            TsUnacceptable: PayloadNOTIFY.Type.TS_UNACCEPTABLE,
            InvalidKePayload: PayloadNOTIFY.Type.INVALID_KE_PAYLOAD,
            ChildSaNotFound: PayloadNOTIFY.Type.CHILD_SA_NOT_FOUND,
            TemporaryFailure: PayloadNOTIFY.Type.TEMPORARY_FAILURE,
            CookieRequired: PayloadNOTIFY.Type.COOKIE
        }
        notification_type = exception_2_notify.get(type(ex), PayloadNOTIFY.Type.INVALID_SYNTAX)

        if type(ex) is InvalidKePayload:
            notification_data = pack('>H', ex.group)
        elif type(ex) is CookieRequired:
            notification_data = ex.cookie
        else:
            notification_data = b''

        notification_protocol = ex.protocol if type(ex) is ChildSaNotFound else Proposal.Protocol.NONE
        notification_spi = ex.spi if type(ex) is ChildSaNotFound else b''
        return PayloadNOTIFY(notification_protocol, notification_type, notification_spi, notification_data)

    @classmethod
    def parse(cls, data, critical=False):
        try:
            protocol_id, spi_size, notification_type = unpack_from('>BBH', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload Notify.')
        if spi_size > 0:
            spi = data[4:4 + spi_size]
        else:
            spi = b''
        notification_data = data[4 + spi_size:]
        return PayloadNOTIFY(protocol_id, notification_type, spi, notification_data, critical=critical)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.protocol_id, len(self.spi), self.notification_type))
        if len(self.spi) > 0:
            data += self.spi
        data += self.notification_data
        return data

    def to_dict(self):
        result = super(PayloadNOTIFY, self).to_dict()
        result.update(OrderedDict([
            ('protocol_id', self.protocol_id.name),
            ('spi', self.spi.hex()),
            ('notification_type', self.notification_type.name),
            ('notification_data', self.notification_data.hex())]))
        return result

    def is_error(self):
        return self.notification_type < 16384

    def __str__(self):
        return f'N({self.notification_type.name})'


class PayloadID(Payload):
    type = Payload.Type.NONE

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
        self.id_type = self.Type(id_type)
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
            return str(ip_address(self.id_data)),
        else:
            return self.id_data.hex()

    def to_dict(self):
        result = super(PayloadID, self).to_dict()
        result.update(OrderedDict([
            ('id_type', self.id_type.name),
            ('id_data', self._id_data_str())]))
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
        self.method = self.Method(method)
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
            ('method', self.method.name),
            ('auth_data', self.auth_data.hex()), ]))
        return result

    def __eq__(self, other):
        return (self.method, self.auth_data) == (other.method, other.auth_data)


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
        self.ts_type = self.Type(ts_type)
        self.ip_proto = self.IpProtocol(ip_proto)
        self.start_port = start_port
        self.end_port = end_port
        self.start_addr = start_addr
        self.end_addr = end_addr

    @classmethod
    def from_network(cls, subnet, port, ip_proto):
        return TrafficSelector((TrafficSelector.Type.TS_IPV6_ADDR_RANGE if subnet[0].version == 6
                                else TrafficSelector.Type.TS_IPV4_ADDR_RANGE), ip_proto, port,
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
        return TrafficSelector(ts_type, ip_proto, start_port, end_port, ip_address(start_addr), ip_address(end_addr))

    def to_bytes(self):
        addr_len = (4 if self.ts_type == TrafficSelector.Type.TS_IPV4_ADDR_RANGE else 16)
        return pack('>BBHHH{0}s{0}s'.format(addr_len), self.ts_type, self.ip_proto,
                    8 + addr_len * 2, self.start_port, self.end_port, self.start_addr.packed,
                    self.end_addr.packed)

    def to_dict(self):
        return OrderedDict([
            ('ts_type', self.ts_type.name),
            ('ip_proto', self.ip_proto.name),
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
    type = Payload.Type.NONE

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
        result.update(OrderedDict([('traffic_selectors', [x.to_dict() for x in self.traffic_selectors])]))
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
        return iv, decrypted[:-1 - padlen]

    @classmethod
    def generate(cls, cleartext, iv, crypto):
        padlen = (crypto.cipher.block_size - (len(cleartext) % crypto.cipher.block_size) - 1)
        cleartext += b'\x00' * padlen + pack('>B', padlen)
        encrypted = crypto.cipher.encrypt(crypto.sk_e, bytes(iv), bytes(cleartext))
        return PayloadSK(iv + encrypted + b'\x00' * crypto.integrity.hash_size)

    def to_dict(self):
        result = super(PayloadSK, self).to_dict()
        result.update(OrderedDict([('ciphertext', self.ciphertext.hex())]))
        return result


class PayloadDELETE(Payload):
    type = Payload.Type.DELETE

    def __init__(self, protocol_id, spis, critical=False):
        super(PayloadDELETE, self).__init__(critical)
        self.protocol_id = Proposal.Protocol(protocol_id)
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
        data = bytearray(pack('>BBH', self.protocol_id, len(self.spis[0]) if self.spis else 0, len(self.spis)))
        for spi in self.spis:
            data += spi
        return data

    def to_dict(self):
        result = super(PayloadDELETE, self).to_dict()
        result.update(OrderedDict([
            ('protocol_id', self.protocol_id.name),
            ('spis', [x.hex() for x in self.spis])]))
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

    def __init__(self, spi_i, spi_r, major, minor, exchange_type, is_response, can_use_higher_version, is_initiator,
                 message_id, payloads, encrypted_payloads, crypto=None, iv=None):
        self.spi_i = spi_i
        self.spi_r = spi_r
        self.major = major
        self.minor = minor
        self.exchange_type = self.Exchange(exchange_type)
        self.is_response = is_response
        self.can_use_higher_version = can_use_higher_version
        self.is_initiator = is_initiator
        self.message_id = message_id
        self.payloads = payloads
        self.encrypted_payloads = encrypted_payloads
        self.crypto = crypto
        self.iv = iv
        if self.crypto is not None and self.iv is None:
            self.iv = self.crypto.cipher.generate_iv()

    @classmethod
    def _parse_payloads(cls, data, first_payload_type):
        payloads = []
        offset = 0
        payload_type = first_payload_type

        while payload_type != Payload.Type.NONE:
            # Read payload common header
            try:
                next_payload_type, critical, length = unpack_from('>BBH', data, offset)
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
                logging.warning(f'Unrecognized payload with type {payload_type.name}')
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
            crypto=crypto
        )

        if not header_only:
            # parse unencrypted payloads
            message.payloads = cls._parse_payloads(data[28:], Payload.Type(header[2]))

            # if there is a Payload SK
            if (message.payloads and message.payloads[-1].type == Payload.Type.SK
                    and crypto is not None):
                # read the payload SK and remove it from the list
                payload_sk = message.payloads.pop()

                # check integrity
                checksum = crypto.integrity.compute(crypto.sk_a, data[:-crypto.integrity.hash_size])
                if checksum != data[-crypto.integrity.hash_size:]:
                    raise InvalidSyntax('CHECKSUM ERROR')

                # parse decrypted payloads and remove Payload SK
                message.iv, decrypted_data = payload_sk.decrypt(crypto)
                message.encrypted_payloads = cls._parse_payloads(decrypted_data, payload_sk.next_payload_type)

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

    def to_bytes(self):
        # create a temporary copy of payloads list
        _payloads = self.payloads[:]

        # if crypto is provided, encrypt everything into a SK payload
        if self.crypto is not None:
            cleartext = self._payloads_to_bytes(self.encrypted_payloads)
            payload_sk = PayloadSK.generate(cleartext, self.iv, self.crypto)
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
        if self.crypto is not None:
            checksum = self.crypto.integrity.compute(self.crypto.sk_a, data[:-self.crypto.integrity.hash_size])
            pack_into('>{}s'.format(len(checksum)), data, len(data) - len(checksum), checksum)

        return data

    def to_dict(self):
        return OrderedDict([
            ('spi_i', self.spi_i.hex()),
            ('spi_r', self.spi_r.hex()),
            ('major', self.major),
            ('minor', self.minor),
            ('exchange_type', self.exchange_type.name),
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
            raise PayloadNotFound(f'Required payload {payload_type.name} was not found in message')
