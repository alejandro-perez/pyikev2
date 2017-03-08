#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol messages.
"""
__author__ = 'Alejandro Perez <alex@um.es>'

from struct import pack, unpack, pack_into, unpack_from
import json
import codecs
from collections import OrderedDict

def hexstring(data):
    return codecs.encode(data, 'hex').decode()

class Ikev2ParsingError(Exception):
    pass

class Payload:
    def __init__(self, critical=False):
        self.critical = critical

    def to_dict(self):
        if self.critical:
            return OrderedDict([('critical', self.critical)])
        else:
            return OrderedDict()

class PayloadKE(Payload):
    def __init__(self, dh_group, ke_data, critical=False):
        super(PayloadKE, self).__init__(critical)
        self.dh_group = dh_group
        self.ke_data = ke_data

    @classmethod
    def parse(cls, data, critical=False):
        dh_group, _, ke_data = unpack_from('>2H{}s'.format(len(data) - 4), data)
        return PayloadKE(dh_group, ke_data, critical)

    def to_dict(self):
        result = super(PayloadKE, self).to_dict()
        result.update(OrderedDict([
            ('type', 'PayloadKE'),
            ('dh_group', self.dh_group),
            ('ke_data', hexstring(self.ke_data))
        ]))
        return result

class Transform:
    types = [
        ('ENCR', 1),
        ('PRF', 2),
        ('INTEG', 3),
        ('DH', 4),
        ('ESN', 5),
    ]

    algorithms = {
        # ENCR
        1: [
            ('ENCR_DES_IV64', 1),
            ('ENCR_DES', 2),
            ('ENCR_3DES', 3),
            ('ENCR_RC5', 4),
            ('ENCR_IDEA', 5),
            ('ENCR_CAST', 6),
            ('ENCR_BLOWFISH', 7),
            ('ENCR_3IDEA', 8),
            ('ENCR_DES_IV32', 9),
            ('ENCR_NULL', 11),
            ('ENCR_AES_CBC', 12),
            ('ENCR_AES_CTR', 13),
        ],
        # PRF
        2: [
            ('PRF_HMAC_MD5', 1),
            ('PRF_HMAC_SHA1', 2),
            ('PRF_HMAC_TIGER', 3),
        ],
        # INTEG
        3: [
            ('INTEG_NONE', 0),
            ('AUTH_HMAC_MD5_96', 1),
            ('AUTH_HMAC_SHA1_96', 2),
            ('AUTH_DES_MAC', 3),
            ('AUTH_KPDK_MD5', 4),
            ('AUTH_AES_XCBC_96', 5),
        ],
        # DH
        4: [
            ('DH_NONE', 0),
            ('DH_1', 1),
            ('DH_2', 2),
            ('DH_5', 5),
            ('DH_14', 14),
            ('DH_14', 14),
            ('DH_15', 15),
            ('DH_16', 16),
            ('DH_17', 17),
            ('DH_18', 18),
        ],
        # ESN
        5: [
            ('NO_ESN', 0),
            ('ESN', 1),
        ],
    }

    @classmethod
    def get_type_name(cls, type_id):
        return {v:k for k, v in cls.types}.get(type_id, type_id)

    @classmethod
    def get_alg_name(cls, type_id, transform_id):
        algs = cls.algorithms.get(type_id, type_id)
        return {v:k for k, v in algs}.get(transform_id, transform_id)

    def __init__(self, type, transform_id, keylen = None):
        self.type = type
        self.transform_id = transform_id
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
        return Transform(transform_type, transform_id, keylen)

    def to_dict(self):
        result = OrderedDict([
            ('type', Transform.get_type_name(self.type)),
            ('transform_id', Transform.get_alg_name(self.type, self.transform_id)),
        ])
        if self.keylen:
            result['keylen'] = self.keylen
        return result


class Proposal:
    protocols = [
        ('IKE', 1),
        ('AH', 2),
        ('ESP', 3),
    ]

    @classmethod
    def get_protocol_name(cls, protocol_id):
        return {v:k for k, v in cls.protocols}.get(protocol_id, protocol_id)

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
            ('protocol_id', Proposal.get_protocol_name(self.protocol_id)),
            ('num_transforms', self.num_transforms),
            ('spi', hexstring(self.spi)),
            ('transforms', [x.to_dict() for x in self.transforms]),
        ])

class PayloadSA(Payload):
    def __init__(self, critical=False):
        super(PayloadSA, self).__init__(critical)
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
            ('type', 'PayloadSA'),
            ('proposals', [x.to_dict() for x in self.proposals]),
        ]))
        return result

class PayloadVendor(Payload):
    def __init__(self, vendor_id, critical=False):
        super(PayloadVendor, self).__init__(critical)
        self.vendor_id = vendor_id

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadVendor(data, critical)

    def to_dict(self):
        result = super(PayloadVendor, self).to_dict()
        result.update(OrderedDict([
            ('type', 'PayloadVendor'),
            ('vendor_id', hexstring(self.vendor_id)),
        ]))
        return result

class PayloadNonce(Payload):
    def __init__(self, nonce, critical=False):
        super(PayloadNonce, self).__init__(critical)
        self.nonce = nonce

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadNonce(data, critical)

    def to_dict(self):
        result = super(PayloadNonce, self).to_dict()
        result.update(OrderedDict([
            ('type', 'PayloadNonce'),
            ('nonce', hexstring(self.nonce)),
        ]))
        return result

class PayloadFactory:
    payload_classes = {
        33: PayloadSA,
        34: PayloadKE,
        40: PayloadNonce,
        43: PayloadVendor,
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
    def __init__(self, data):
        # Unpack the header
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
            ('type', self.type),
            ('is_response', self.is_response),
            ('can_use_higher_version', self.can_use_higher_version),
            ('is_initiator', self.is_initiator),
            ('message_id', self.message_id),
            ('payloads', [x.to_dict() for x in self.payloads]),
        ])
    def __str__(self):
        return json.dumps(self.to_dict(), indent=2)

