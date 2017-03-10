#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol messages.
"""
__author__ = 'Alejandro Perez <alex@um.es>'

import logging
import os
from random import SystemRandom
import json
from struct import pack, unpack, pack_into, unpack_from, error as struct_error
from collections import OrderedDict, namedtuple

from helpers import hexstring, SafeTupleEnum, SafeIntEnum

class InvalidSyntax(Exception):
    pass

class UnsupportedCriticalPayload(Exception):
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
        try:
            dh_group, _, = unpack_from('>2H', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload KE.')
        ke_data = data[4:]
        return PayloadKE(dh_group, ke_data, critical)

    def to_bytes(self):
        data = bytearray(pack('>2H', self.dh_group, 0))
        data += self.ke_data
        return data

    def to_dict(self):
        result = super(PayloadKE, self).to_dict()
        result.update(OrderedDict([
            ('dh_group', self.dh_group),
            ('ke_data', hexstring(self.ke_data))
        ]))
        return result

class Transform:
    class Algorithm(SafeTupleEnum):
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
        try:
            transform_type, _, transform_id = unpack_from('>BBH', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Tranform.')
        offset = 4
        keylen = None
        while offset < len(data):
            try:
                attribute = unpack_from('>HH', data, offset)
            except struct_error:
                raise InvalidSyntax('Error parsing Transform attribute.')
            is_tv = attribute[0] >> 15
            attr_type = attribute[0] & 0x7FFF
            # if we find a KeyLen attribute, we can abort to save some cycles
            if attribute[0] == (14 | 0x8000):
                keylen = attribute[1]
                break
            offset += 4
        return Transform((transform_type, transform_id), keylen)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.type, 0, self.transform_id))
        if self.keylen:
            data += pack('>HH', (14 | 0x8000), self.keylen)
        return data

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

    def __init__(self, num, protocol_id, spi, transforms):
        self.num = num
        self.protocol_id = protocol_id
        self.spi = spi
        self.transforms = transforms
        if len(self.transforms) == 0:
            raise InvalidSyntax('A proposal without transforms is not allowed')

    @classmethod
    def parse(cls, data):
        spi = b''
        try:
            num, protocol_id, spi_size, num_transforms = unpack_from('>BBBB', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Proposal')

        if spi_size > 0:
            spi = data[4:4 + spi_size]

        # iterate over the transforms (if any)
        offset = 4 + spi_size
        transforms = []
        while offset < len(data):
            try:
                more, _, length = unpack_from('>BBH', data, offset)
            except struct_error:
                raise InvalidSyntax('Error parsing Transform header')
            start = offset + 4
            end = offset + length
            transform = Transform.parse(data[start:end])
            transforms.append(transform)
            offset += length

        if num_transforms != len(transforms):
            raise InvalidSyntax(
                'Indicated # of transforms ({}) differs from the actual # of '
                ' transforms ({})'.format(num_transforms, len(transforms)))

        return Proposal(num, protocol_id, spi, transforms)

    def to_bytes(self):
        data = bytearray(pack(
            '>BBBB', self.num, self.protocol_id, len(self.spi), len(self.transforms)
        ))

        if len(self.spi):
            data += self.spi

        for index in range(0, len(self.transforms)):
            transform = self.transforms[index]
            transform_data = transform.to_bytes()
            data += pack(
                '>BBH', (0 if index == len(self.transforms) - 1 else 3),
                0, len(transform_data) + 4
            )
            data += transform_data

        return data

    def to_dict(self):
        return OrderedDict([
            ('num', self.num),
            ('protocol_id', Proposal.Protocol.safe_name(self.protocol_id)),
            ('spi', hexstring(self.spi)),
            ('transforms', [x.to_dict() for x in self.transforms]),
        ])

class PayloadSA(Payload):
    def __init__(self, proposals, critical=False):
        super(PayloadSA, self).__init__(Payload.Type.SA, critical)
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

        return PayloadSA(proposals)

    def to_bytes(self):
        data = bytearray()
        for index in range(0, len(self.proposals)):
            proposal_data = self.proposals[index].to_bytes()
            data += pack(
                '>BBH', (0 if index == len(self.proposals) - 1 else 2),
                0, len(proposal_data) + 4
            )
            data += proposal_data
        return data

    def to_dict(self):
        result = super(PayloadSA, self).to_dict()
        result.update(OrderedDict([
            ('proposals', [x.to_dict() for x in self.proposals]),
        ]))
        return result

class PayloadVendor(Payload):
    def __init__(self, vendor_id, critical=False):
        super(PayloadVendor, self).__init__(Payload.Type.VENDOR, critical)
        if len(vendor_id) == 0:
            raise InvalidSyntax('Vendor ID should have some data.')
        self.vendor_id = vendor_id

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadVendor(data, critical)

    def to_bytes(self):
        return self.vendor_id

    def to_dict(self):
        result = super(PayloadVendor, self).to_dict()
        result.update(OrderedDict([
            ('vendor_id', self.vendor_id.decode()),
        ]))
        return result

class PayloadNonce(Payload):
    def __init__(self, nonce=None, critical=False):
        super(PayloadNonce, self).__init__(Payload.Type.NONCE, critical)
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
        return PayloadNonce(data, critical)

    def to_bytes(self):
        return self.nonce

    def to_dict(self):
        result = super(PayloadNonce, self).to_dict()
        result.update(OrderedDict([
            ('nonce', hexstring(self.nonce)),
        ]))
        return result


class PayloadSK(Payload):
    def __init__(self, payload_data, critical=False):
        super(PayloadSK, self).__init__(Payload.Type.SK, critical)
        if len(payload_data) == 0:
            raise InvalidSyntax('PayloadSK cannot have 0 length payload data')
        self.payload_data = payload_data

    @classmethod
    def parse(cls, data, critical=False):
        return PayloadSK(data, critical)

    def to_bytes(self):
        return self.payload_data

    def to_dict(self):
        result = super(PayloadSK, self).to_dict()
        result.update(OrderedDict([
            ('payload_data', hexstring(self.payload_data)),
        ]))
        return result

class PayloadFactory:
    payload_classes = {
        Payload.Type.SA: PayloadSA,
        Payload.Type.KE: PayloadKE,
        Payload.Type.NONCE: PayloadNonce,
        Payload.Type.VENDOR: PayloadVendor,
        Payload.Type.SK: PayloadSK,
    }

    @classmethod
    def parse(cls, payload_type, data, critical=False):
        """ Parses a payload and returns an object.
            If the payload type is not recognized and critical, raise and
            exception. Else, returns None
        """
        try:
            return cls.payload_classes[payload_type].parse(data, critical)
        except KeyError:
            raise InvalidSyntax(
                'Unrecognized payload with code '
                '{}'.format(Payload.Type.safe_name(payload_type)))

class Message:
    class Exchange(SafeIntEnum):
        IKE_SA_INIT = 34
        IKE_AUTH = 35
        CREATE_CHILD_SA = 36
        INFORMATIONAL = 37

    def __init__(self, spi_i, spi_r, major, minor,
                 exchange_type, is_response, can_use_higher_version,
                 is_initiator, message_id, payloads):
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

    @classmethod
    def parse(cls, data, header_only=False):
        try:
            header = unpack_from('>2Q4B2L', data)
        except struct_error as ex:
            raise InvalidSyntax(ex)

        payloads = []
        if not header_only:
            # unpack payloads
            offset = 28
            next_payload_type = header[2]
            payload_type = Payload.Type.NONE

            # Two stop conditions, either next payload is NONE
            while (next_payload_type != Payload.Type.NONE):
                payload_type = next_payload_type
                try:
                    next_payload_type, critical, length = unpack_from('>BBH', data, offset)
                except struct_error as ex:
                    raise InvalidSyntax(ex)

                if length < 4:
                    raise InvalidSyntax('Payloads with length < 4 are  not allowed: {}'.format(length))

                critical = critical >> 7
                start = offset + 4
                end = offset + length

                # We try to parse the payload. If not known and critical, propagate
                # exception
                try:
                    payload = PayloadFactory.parse(
                        payload_type, data[start:end], critical
                    )
                except InvalidSyntax as ex:
                    logging.warning(ex)
                    if critical:
                        raise UnsupportedCriticalPayload
                else:
                    payloads.append(payload)

                # offset is increased in any case
                offset += length

                # abort if this was a SK payload
                if payload_type == Payload.Type.SK:
                    break

            # check we read all the data
            if offset != len(data):
                raise InvalidSyntax('Amount of actual payload data {} differs from '
                    ' message length {}'.format(offset, len(data)))

        return Message(
            spi_i=header[0],
            spi_r=header[1],
            major=header[3] >> 4,
            minor=header[3] & 0x0F,
            exchange_type=header[4],
            is_response=(header[5] & 0x20) != 0,
            can_use_higher_version=(header[5] & 0x10) != 0,
            is_initiator=(header[5] & 0x08) != 0,
            message_id=header[6],
            payloads=payloads
        )

    def to_bytes(self):
        first_payload_type = self.payloads[0].type if self.payloads else Payload.Type.NONE
        data = bytearray(28)
        pack_into(
            '>2Q4B2L', data, 0, self.spi_i, self.spi_r, first_payload_type,
            (self.major << 4 | self.minor & 0x0F), self.exchange_type,
            (self.is_response << 5 | self.can_use_higher_version << 4 |
                self.is_initiator << 3),
            self.message_id, 28
        )
        for index in range(0, len(self.payloads)):
            payload = self.payloads[index]
            payload_data = payload.to_bytes()
            if index < len(self.payloads) - 1:
                next_payload_type = self.payloads[index + 1].type
            else:
                next_payload_type = Payload.Type.NONE

            data += pack('>BBH', next_payload_type, 0, len(payload_data) + 4)
            data += payload_data

        # update length once we know it
        pack_into('>L', data, 24, len(data))

        return data

    def to_dict(self):
        return OrderedDict([
            ('spi_i', hexstring(pack('>Q', self.spi_i))),
            ('spi_r', hexstring(pack('>Q', self.spi_r))),
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
        ])

    @property
    def is_request(self):
        return not self.is_response

    @property
    def is_responder(self):
        return not self.is_initiator

    def get_payload_by_type(self, payload_type):
        return next(x for x in self.payloads if x.type == payload_type)

    def __str__(self):
        return json.dumps(self.to_dict(), indent=2)

