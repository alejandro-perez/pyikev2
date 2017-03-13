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
from collections import OrderedDict
from helpers import hexstring, SafeIntEnum
from crypto import Prf, Cipher, Integrity, DiffieHellman, ESN
from ipaddress import ip_address

class InvalidSyntax(Exception):
    pass

class UnsupportedCriticalPayload(Exception):
    pass

class NoProposalChosen(Exception):
    pass

class InvalidKePayload(Exception):
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

    def __init__(self, critical=False):
        self.critical = critical

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

    def __init__(self, type, id, keylen = None):
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
        return Transform(type, id, keylen)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.type, 0, self.id))
        if self.keylen:
            data += pack('>HH', (14 | 0x8000), self.keylen)
        return data

    def to_dict(self):
        result = OrderedDict([
            ('type', Transform.Type.safe_name(self.type)),
            ('id', Transform._transform_id_enums[self.type].safe_name(self.id)),
        ])
        if self.keylen:
            result['keylen'] = self.keylen
        return result

    def __eq__(self, other):
        return ((self.type, self.id, self.keylen) ==
            (other.type, other.id, other.keylen))


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
            num, protocol_id, spi_size, num_transforms = unpack_from('>BBBB', data)
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

    def get_transform(self, type):
        return next(x for x in self.transforms if x.type == type)

    def get_transforms(self, type):
        return [x for x in self.transforms if x.type == type]

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
            ('vendor_id', self.vendor_id.decode()),
        ]))
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
        result.update(OrderedDict([
            ('nonce', hexstring(self.nonce)),
        ]))
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
            protocol_id, spi_size, notification_type = unpack_from('>BBH', data)
        except struct_error:
            raise InvalidSyntax('Error parsing Payload Notify.')
        if spi_size > 0:
            spi = data[4:4 + spi_size]
        else:
            spi = b''
        notification_data = data[4 + spi_size:]
        return PayloadNOTIFY(protocol_id, notification_type, spi, notification_data)

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
            ('notification_data', hexstring(self.notification_data)),
        ]))
        return result

class PayloadID(Payload):
    type = None

    class Type(SafeIntEnum):
        ID_IPV4_ADDR = 1
        ID_FQDN = 2
        ID_RFC822_ADDR = 3
        ID_IPV6_ADDR = 5
        ID_DER_ASN1_DN = 9
        ID_DER_ASN1_GN =  10
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
        return cls(id_type, id_data)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.id_type, 0, 0))
        data += self.id_data
        return data

    def to_dict(self):
        result = super(PayloadID, self).to_dict()
        result.update(OrderedDict([
            ('id_type', PayloadID.Type.safe_name(self.id_type)),
            ('id_data', hexstring(self.id_data)),
        ]))
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
        return PayloadAUTH(method, auth_data)

    def to_bytes(self):
        data = bytearray(pack('>BBH', self.method, 0, 0))
        data += self.auth_data
        return data

    def to_dict(self):
        result = super(PayloadAUTH, self).to_dict()
        result.update(OrderedDict([
            ('method', PayloadAUTH.Method.safe_name(self.method)),
            ('auth_data', hexstring(self.auth_data)),
        ]))
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

    def __init__(self, ts_type, ip_proto, start_port, end_port,
            start_addr, end_addr):
        self.ts_type = ts_type
        self.ip_proto = ip_proto
        self.start_port = start_port
        self.end_port = end_port
        self.start_addr = start_addr
        self.end_addr = end_addr

    @classmethod
    def parse(cls, data, critical=False):
        try:
            (ts_type, ip_proto, _, start_port, end_port) = unpack_from('>BBHHH', data)
            addr_len = 4 if ts_type == TrafficSelector.Type.TS_IPV4_ADDR_RANGE else 16
            start_addr, end_addr = unpack_from('>{0}s{0}s'.format(addr_len), data, 8)
        except struct_error:
            raise InvalidSyntax('Error parsing Traffic selector.')
        return TrafficSelector(ts_type, ip_proto, start_port, end_port,
            ip_address(start_addr), ip_address(end_addr))

    def to_bytes(self):
        addr_len = 4 if self.ts_type == TrafficSelector.Type.TS_IPV4_ADDR_RANGE else 16
        return pack('>BBHHH{0}s{0}s'.format(addr_len),
            self.ts_type, self.ip_proto, 8 + addr_len * 2, self.start_port,
            self.end_port, self.start_addr.packed, self.end_addr.packed)

    def to_dict(self):
        return OrderedDict([
            ('ts_type', TrafficSelector.Type.safe_name(self.ts_type)),
            ('ip_proto', TrafficSelector.IpProtocol.safe_name(self.ip_proto)),
            ('port-range', '{} - {}'.format(self.start_port, self.end_port)),
            ('addr-range', '{} - {}'.format(self.start_addr, self.end_addr)),
        ])
        return result

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
            raise InvalidSyntax('Payload TS has invalid number of selectors.'
                'Expected {} got {}'.format(n_ts, len(traffic_selectors)))
        # we need to use cls as it might be PayloadTSi or PayloadTSr
        return cls(traffic_selectors)

    def to_bytes(self):
        data = bytearray(pack('>BBH', len(self.traffic_selectors), 0, 0))
        for ts in self.traffic_selectors:
            data += ts.to_bytes()
        return data

    def to_dict(self):
        result = super(PayloadTS, self).to_dict()
        result.update(OrderedDict([
            ('traffic_selectors', [x.to_dict() for x in self.traffic_selectors]),
        ]))
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

    def decrypt(self, integrity, cipher, encryption_key):
        iv = self.ciphertext[:cipher.block_size]
        ciphertext = self.ciphertext[cipher.block_size:-integrity.hash_size]
        decrypted = cipher.decrypt(encryption_key, bytes(iv), bytes(ciphertext))
        padlen = decrypted[-1]
        return decrypted[:-1-padlen]

    @classmethod
    def generate(cls, cleartext, integrity, cipher, encryption_key):
        iv = cipher.generate_iv()
        padlen = cipher.block_size - (len(cleartext) % cipher.block_size) - 1
        cleartext += b'\x00' * padlen + padlen.to_bytes(1, 'big')
        encrypted = cipher.encrypt(encryption_key, bytes(iv), bytes(cleartext))
        return PayloadSK(iv + encrypted + b'\x00' * integrity.hash_size)

    def to_dict(self):
        result = super(PayloadSK, self).to_dict()
        result.update(OrderedDict([
            ('ciphertext', hexstring(self.ciphertext)),
        ]))
        return result


class PayloadFactory:
    payload_classes = {
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
        Payload.Type.SK: PayloadSK
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
                'Unrecognized payload with type '
                '{}'.format(Payload.Type.safe_name(payload_type)))

class Message:
    class Exchange(SafeIntEnum):
        IKE_SA_INIT = 34
        IKE_AUTH = 35
        CREATE_CHILD_SA = 36
        INFORMATIONAL = 37

    def __init__(self, spi_i, spi_r, major, minor,
                 exchange_type, is_response, can_use_higher_version,
                 is_initiator, message_id, payloads, encrypted_payloads):
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

        while (payload_type != Payload.Type.NONE):
            # Read payload common header
            try:
                (next_payload_type,critical, length) = unpack_from('>BBH', data, offset)
            except struct_error as ex:
                raise InvalidSyntax(ex)

            critical = critical >> 7
            start = offset + 4
            end = offset + length

            # Parse the payload. If not known and critical, raise exception
            try:
                payload = PayloadFactory.parse(
                    payload_type, data[start:end], critical)
            except InvalidSyntax as ex:
                logging.warning(ex)
                if critical:
                    raise UnsupportedCriticalPayload

            # If payload SK, annotate next_payload_type and set it to NONE
            if payload_type == Payload.Type.SK:
                payload.next_payload_type = next_payload_type
                next_payload_type = Payload.Type.NONE

            # offset is increased in any case
            payloads.append(payload)
            offset += length
            payload_type = next_payload_type

        # check we read all the data
        if offset != len(data):
            raise InvalidSyntax('Amount of actual payload data {} differs from '
                ' message length {}'.format(offset, len(data)))

        return payloads

    @classmethod
    def parse(cls, data, header_only=False, keyring=None, proposal=None):
        try:
            header = unpack_from('>2Q4B2L', data)
        except struct_error as ex:
            raise InvalidSyntax(ex)

        message = Message(
            spi_i=header[0],
            spi_r=header[1],
            major=header[3] >> 4,
            minor=header[3] & 0x0F,
            exchange_type=header[4],
            is_response=(header[5] & 0x20) != 0,
            can_use_higher_version=(header[5] & 0x10) != 0,
            is_initiator= (header[5] & 0x08) != 0,
            message_id=header[6],
            payloads=[],
            encrypted_payloads=[]
        )

        if not header_only:
            message.payloads = cls._parse_payloads(data[28:], header[2])
            if message.payloads and message.payloads[-1].type == Payload.Type.SK:
                payload_sk = message.payloads[-1]
                integrity = Integrity(proposal.get_transform(Transform.Type.INTEG).id)
                cipher = Cipher(proposal.get_transform(Transform.Type.ENCR).id,
                    proposal.get_transform(Transform.Type.ENCR).keylen)
                encryption_key = keyring.sk_ei if message.is_initiator else keyring.sk_er
                authentication_key = keyring.sk_ai if message.is_initiator else keyring.sk_ar

                # check integrity
                checksum = integrity.compute(authentication_key, data[:-integrity.hash_size])
                if checksum != data[-integrity.hash_size:]:
                    raise InvalidSyntax('CHECKSUM ERROR')

                # parse decrypted payloads
                decrypted_data = payload_sk.decrypt(integrity, cipher, encryption_key)
                message.encrypted_payloads += cls._parse_payloads(
                    decrypted_data, payload_sk.next_payload_type)

                message.payloads.remove(payload_sk)

        return message

    def _payloads_to_bytes(self, payloads):
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


    def to_bytes(self, keyring=None, proposal=None):
        # if keyring is provided, encrypt everything into a SK payload
        if self.encrypted_payloads:
            integrity = Integrity(proposal.get_transform(Transform.Type.INTEG).id)
            cipher = Cipher(proposal.get_transform(Transform.Type.ENCR).id,
                proposal.get_transform(Transform.Type.ENCR).keylen)
            encryption_key = keyring.sk_ei if self.is_initiator else keyring.sk_er
            authentication_key = keyring.sk_ai if self.is_initiator else keyring.sk_ar

            cleartext = self._payloads_to_bytes(self.encrypted_payloads)
            payload_sk = PayloadSK.generate(
                cleartext, integrity, cipher, encryption_key)
            payload_sk.next_payload_type = self.encrypted_payloads[0].type
            self.payloads.append(payload_sk)

        # generate header
        first_payload_type = self.payloads[0].type if self.payloads else Payload.Type.NONE
        header_data = bytearray(pack(
            '>2Q4B2L', self.spi_i, self.spi_r, first_payload_type,
            (self.major << 4 | self.minor & 0x0F), self.exchange_type,
            (self.is_response << 5 | self.can_use_higher_version << 4 |
                self.is_initiator << 3),
            self.message_id, 28
        ))

        # generate payloads
        payloads_data = self._payloads_to_bytes(self.payloads)

        # generate final data
        data = header_data + payloads_data

        # update length once we know it
        pack_into('>L', data, 24, len(data))

        # calculate checksum
        if self.encrypted_payloads:
            # check integrity
            checksum = integrity.compute(authentication_key, data[:-integrity.hash_size])
            pack_into('>{}s'.format(len(checksum)), data, len(data) - len(checksum), checksum)

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
            ('encrypted_payloads', [x.to_dict() for x in self.encrypted_payloads]),
        ])

    @property
    def is_request(self):
        return not self.is_response

    @property
    def is_responder(self):
        return not self.is_initiator

    def get_payload(self, payload_type):
        return next(x for x in self.payloads if x.type == payload_type)

    def get_payloads(self, payload_type):
        return [x for x in self.payloads if x.type == payload_type]

    def get_encr_payload(self, payload_type):
        return next(x for x in self.encrypted_payloads if x.type == payload_type)

    def get_encr_payloads(self, payload_type):
        return [x for x in self.encrypted_payloads if x.type == payload_type]

    def __str__(self):
        return json.dumps(self.to_dict(), indent=2)

