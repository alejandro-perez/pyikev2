#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol messages.
"""
__author__ = 'Alejandro Perez <alex@um.es>'

from struct import pack, unpack, pack_into, unpack_from
import json
from collections import OrderedDict
from helpers import hexstring
from enum import Enum
class SafeEnum(Enum):
    @classmethod
    def safe_name(cls, value):
        try:
            return cls(value).name
        except ValueError:
            return '{} (not registered)'.format(value)

class SafeIntEnum(int, SafeEnum):
    pass

class Ikev2ParsingError(Exception):
    pass

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

    def __init__(self, type, critical=False):
        self.critical = critical
        self.type = type

    def to_dict(self):
        result = OrderedDict([
            ('type', Payload.Type.safe_name(self.type)),
        ])
        if self.critical:
            result.update(OrderedDict([
                ('critical', self.critical)
            ]))
        return result

class PayloadKE(Payload):
    def __init__(self, dh_group, ke_data, critical=False):
        super(PayloadKE, self).__init__(Payload.Type.KE, critical)
        self.dh_group = dh_group
        self.ke_data = ke_data

    @classmethod
    def parse(cls, data, critical=False):
        dh_group, _, ke_data = unpack_from('>2H{}s'.format(len(data) - 4), data)
        return PayloadKE(dh_group, ke_data, critical)

    def to_dict(self):
        result = super(PayloadKE, self).to_dict()
        result.update(OrderedDict([
            ('dh_group', self.dh_group),
            ('ke_data', hexstring(self.ke_data))
        ]))
        return result

class Transform:
    class Algorithm(SafeEnum):
        ENCR_DES_IV64 = (1, 1)
        ENCR_DES = (1, 2)
        ENCR_3DES = (1, 3)
        ENCR_RC5 = (1, 4)
        ENCR_IDEA = (1, 5)
        ENCR_CAST = (1, 6)
        ENCR_BLOWFISH = (1, 7)
        ENCR_3IDEA = (1, 8)
        ENCR_DES_IV32 = (1, 9)
        ENCR_NULL = (1, 11)
        ENCR_AES_CBC = (1, 12)
        ENCR_AES_CTR = (1, 13)
        PRF_HMAC_MD5 = (2, 1)
        PRF_HMAC_SHA1 = (2, 2)
        PRF_HMAC_TIGER = (2, 3)
        INTEG_NONE = (3, 0)
        AUTH_HMAC_MD5_96 = (3, 1)
        AUTH_HMAC_SHA1_96 = (3, 2)
        AUTH_DES_MAC = (3, 3)
        AUTH_KPDK_MD5 = (3, 4)
        AUTH_AES_XCBC_96 = (3, 5)
        DH_NONE = (4, 0)
        DH_1 = (4, 1)
        DH_2 = (4, 2)
        DH_5 = (4, 5)
        DH_14 = (4, 14)
        DH_15 = (4, 15)
        DH_16 = (4, 16)
        DH_17 = (4, 17)
        DH_18 = (4, 18)
        NO_ESN = (5, 0)
        ESN = (5, 1)

    def __init__(self, algorithm, keylen = None):
        self.type = algorithm[0]
        self.transform_id = algorithm[1]
        self.keylen = keylen

    @classmethod
    def parse(cls, data):
        transform_type, _, transform_id = unpack_from('>BBH', data)
        offset = 4
        keylen = None
        while offset < len(data):
            attribute = unpack_from('>HH', data, offset)
            is_tv = attribute[0] >> 15
            attr_type = attribute[0] & 0x7FFF
            # omit any Transform attribute other than KeyLen
            if not is_tv or attr_type != 14:
                continue
            keylen = attribute[1]
            offset += 4
        return Transform((transform_type, transform_id), keylen)

    def to_dict(self):
        result = OrderedDict([
            ('transform_id', Transform.Algorithm.safe_name(
                (self.type, self.transform_id))),
        ])
        if self.keylen:
            result['keylen'] = self.keylen
        return result


class Proposal:
    class Protocol(SafeIntEnum):
        IKE = 1
        AH = 2
        ESP = 3

    def __init__(self, num, protocol_id, num_transforms, spi):
        self.num = num
        self.protocol_id = protocol_id
        self.num_transforms = num_transforms
        self.spi = spi
        self.transforms = []

    @classmethod
    def parse(cls, data):
        spi = b''
        num, protocol_id, spi_size, num_transforms = unpack_from('>BBBB', data)
        if spi_size > 0:
            spi = data[4:4 + spi_size]
        proposal = Proposal(num, protocol_id, num_transforms, spi)

        # iterate over the transforms (if any)
        offset = 4 + spi_size
        while offset < len(data):
            more, _, length = unpack_from('>BBH', data, offset)
            start = offset + 4
            end = offset + length
            transform = Transform.parse(data[start:end])
            proposal.transforms.append(transform)
            offset += length

        return proposal

    def to_dict(self):
        return OrderedDict([
            ('num', self.num),
            ('protocol_id', Proposal.Protocol.safe_name(self.protocol_id)),
            ('num_transforms', self.num_transforms),
            ('spi', hexstring(self.spi)),
            ('transforms', [x.to_dict() for x in self.transforms]),
        ])

class PayloadSA(Payload):
    def __init__(self, critical=False):
        super(PayloadSA, self).__init__(Payload.Type.SA, critical)
        self.proposals = []

    @classmethod
    def parse(cls, data, critical=False):
        payload_sa = PayloadSA()
        # iterate over the proposals (if any)
        if len(data):
            offset = 0
            while offset < len(data):
                more, _, length = unpack_from('>BBH', data)
                start = offset + 4
                end = offset + length
                proposal = Proposal.parse(data[start:end])
                payload_sa.add_proposal(proposal)
                offset += length

        return payload_sa

    def add_proposal(self, proposal):
        self.proposals.append(proposal)

    def to_dict(self):
        result = super(PayloadSA, self).to_dict()
        result.update(OrderedDict([
            ('proposals', [x.to_dict() for x in self.proposals]),
        ]))
        return result

class PayloadVendor(Payload):
    def __init__(self, vendor_id, critical=False):
        super(PayloadVendor, self).__init__(Payload.Type.VENDOR, critical)
        self.vendor_id = vendor_id

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadVendor(data, critical)

    def to_dict(self):
        result = super(PayloadVendor, self).to_dict()
        result.update(OrderedDict([
            ('vendor_id', hexstring(self.vendor_id)),
        ]))
        return result

class PayloadNonce(Payload):
    def __init__(self, nonce, critical=False):
        super(PayloadNonce, self).__init__(Payload.Type.NONCE, critical)
        self.nonce = nonce

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadNonce(data, critical)

    def to_dict(self):
        result = super(PayloadNonce, self).to_dict()
        result.update(OrderedDict([
            ('nonce', hexstring(self.nonce)),
        ]))
        return result

class PayloadFactory:
    payload_classes = {
        Payload.Type.SA: PayloadSA,
        Payload.Type.KE: PayloadKE,
        Payload.Type.NONCE: PayloadNonce,
        Payload.Type.VENDOR: PayloadVendor,
    }

    @classmethod
    def parse(cls, payload_type, data, critical=False):
        """ Parses a payload and returns an object.
            If the payload type is not recognized and critical, raise and
            exception. Else, returns None
        """
        payload_class = cls.payload_classes.get(payload_type, None)
        if payload_class is None:
            if critical:
                raise Ikev2ParsingError(
                    'Unrecognized payload with code {}'.format(payload_type))
            else:
                return None
        return payload_class.parse(data, critical)

class Message:
    class Exchange(SafeIntEnum):
        # IKE_SA_INIT = 34
        IKE_AUTH = 35
        CREATE_CHILD_SA = 36
        INFORMATIONAL = 37
        header = unpack_from('>8s8s4B2L', data)
        self.spi_i = header[0]
        self.spi_r = header[1]
        next_payload_type = header[2]
        self.major = header[3] >> 4
        self.minor = header[3] & 0x0F
        self.type = header[4]
        self.is_response = (header[5] & 0x20) != 0
        self.can_use_higher_version = (header[5] & 0x10) != 0
        self.is_initiator = (header[5] & 0x08) != 0
        self.message_id = header[6]
        self.payloads = []

        # unpack payloads
        offset = 28
        while next_payload_type != 0:
            current_payload_type = next_payload_type
            next_payload_type, critical, length = unpack_from('>BBH', data, offset)
            critical = critical >> 7
            start = offset + 4
            end = offset + length
            payload = PayloadFactory.parse(
                current_payload_type, data[start:end], critical)
            if payload is not None:
                self.payloads.append(payload)
            offset += length

    def to_dict(self):
        return OrderedDict([
            ('spi_i', hexstring(self.spi_i)),
            ('spi_r', hexstring(self.spi_r)),
            ('major', self.major),
            ('minor', self.minor),
            ('exchange_type', Message.Exchange.safe_name(self.exchange_type)),
            ('is_response', self.is_response),
            ('can_use_higher_version', self.can_use_higher_version),
            ('is_initiator', self.is_initiator),
            ('message_id', self.message_id),
            ('payloads', [x.to_dict() for x in self.payloads]),
        ])
    def __str__(self):
        return json.dumps(self.to_dict(), indent=2)

