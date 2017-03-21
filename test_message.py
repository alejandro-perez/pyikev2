#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for protocol messages.
"""
__author__ = 'Alejandro Perez <alex@um.es>'

import unittest
from message import (
    PayloadNONCE, PayloadKE, PayloadVENDOR, PayloadSK, InvalidSyntax, Transform,
    Proposal, PayloadSA, Message, UnsupportedCriticalPayload, PayloadNOTIFY,
    PayloadID, TrafficSelector, PayloadTS, PayloadAUTH, PayloadNOTIFY,
    PayloadDELETE
)
from protocol import Keyring
from crypto import Prf, Cipher, Integrity, DiffieHellman, ESN, Crypto
from ipaddress import ip_address
from helpers import hexstring
import json

class TestPayloadMixin(object):
    def setUp(self):
        self.random_data = b'''c\xace\x81h\xa4\x07\x11\xf3\xdb\x83\x7f
I\xae\x81\x922/\xe6\xdf^Zh\x87\xe9\x8e\xf6F\xf7\xb62\xb5\xf4\xa2\x84\xb5\x8f
\xb5A5,\xe4d=\xfa^G\'\x13-\xa8"\x01Ek\xca46\x89\x8d6\xfc?.\xcc\xd01\x99\xee
\x9e\xa1\xf9a\x11:\x81\x8f\xb4\xf8\xdb\x01\x0f\xe3\xa0\xfa\xe9cH\xee\xf8\xfe
\xc7-]\xa0\xacU\xee\xed\xf0'''

    def test_to_dict(self):
        self.object.to_dict()

    def test_dump_parse_dump(self):
        payload_class = type(self.object)
        data1 = self.object.to_bytes()
        new_payload = self.object.parse(data1)
        data2 = new_payload.to_bytes()
        self.assertEqual(data1,  data2)

    def test_parse_no_data(self):
        payload_class = type(self.object)
        with self.assertRaises(InvalidSyntax):
            payload_class.parse(b'')

    def test_parse_random(self):
        payload_class = type(self.object)
        payload = payload_class.parse(self.random_data)


class TestPayloadNONCE(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadNONCE, self).setUp()
        self.object = PayloadNONCE()

    def test_parse_large(self):
        with self.assertRaises(InvalidSyntax):
            PayloadNONCE.parse(b'1234567890' * 100)

class TestPayloadKE(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadKE, self).setUp()
        self.object = PayloadKE(5, b'1234567890'*10)

    def test_parse_large(self):
        PayloadKE.parse(b'1234567890' * 100)

class TestPayloadVENDOR(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadVENDOR, self).setUp()
        self.object = PayloadVENDOR(b'pyikev2-test-0.1')

    def test_parse_large(self):
        PayloadVENDOR.parse(b'1234567890' * 100)

class TestPayloadSK(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadSK, self).setUp()
        self.object = PayloadSK(b'pyikev2-test-0.1')

    def test_parse_large(self):
        PayloadSK.parse(b'1234567890' * 100)

    def test_parse_no_data(self):
        payload_class = type(self.object)
        payload_class.parse(b'')

    def test_encrypt_decrypt(self):
        integrity = Integrity(Integrity.Id.AUTH_HMAC_SHA1_96)
        cipher = Cipher(Cipher.Id.ENCR_AES_CBC, 256)
        encryption_key = b'Mypassword121111'*2

        crypto = Crypto(cipher, encryption_key, integrity, b'', None, b'')

        payload_sk = PayloadSK.generate(b'Hello there!', crypto)
        clear = payload_sk.decrypt(crypto)
        self.assertEqual(clear, b'Hello there!')

class TestTransformWithKeylen(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTransformWithKeylen, self).setUp()
        self.object = Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96, 128)

class TestTransformWithoutKeylen(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTransformWithoutKeylen, self).setUp()
        self.object = Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1)

class TestProposal(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestProposal, self).setUp()
        transform1 = Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96, 128)
        transform2 = Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1)
        self.object = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever',
            [transform1, transform2]
        )

    def test_parse_random(self):
        with self.assertRaises(InvalidSyntax):
            super(TestProposal, self).test_parse_random()

    def test_no_transforms(self):
        with self.assertRaises(InvalidSyntax):
            Proposal(20, Proposal.Protocol.IKE, b'aspiwhatever', [])

class TestPayloadSA(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadSA, self).setUp()
        transform1 = Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96, 128)
        transform2 = Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1)
        transform3 = Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1, 64)
        proposal1 = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever', [transform1, transform2]
        )
        proposal2 = Proposal(
            20, Proposal.Protocol.IKE, b'anotherone', [transform3]
        )
        self.object = PayloadSA([proposal1, proposal2])

    def test_parse_random(self):
        with self.assertRaises(InvalidSyntax):
            super(TestPayloadSA, self).test_parse_random()

    def test_no_proposals(self):
        with self.assertRaises(InvalidSyntax):
            PayloadSA([])

class TestPayloadNOTIFY(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadNOTIFY, self).setUp()
        self.object = PayloadNOTIFY(
            Proposal.Protocol.IKE, PayloadNOTIFY.Type.NO_ADDITIONAL_SAS,
            b'12345678', b'this is notification data')

class TestPayloadID(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadID, self).setUp()
        self.object = PayloadID(PayloadID.Type.ID_IPV4_ADDR, b'192.168.1.1')

class TestTrafficSelector(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTrafficSelector, self).setUp()
        self.object = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            TrafficSelector.IpProtocol.UDP, 0, 10, ip_address('192.168.1.1'),
            ip_address('192.168.10.10'))

    def test_intersection_bijective(self):
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            TrafficSelector.IpProtocol.ANY, 4, 15, ip_address('192.167.1.5'),
            ip_address('193.168.10.10'))
        result1 = ts2.intersection(self.object)
        result2 = self.object.intersection(ts2)
        self.assertEqual(result1, result2)

    def test_intersection_different_proto(self):
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            TrafficSelector.IpProtocol.TCP, 0, 10, ip_address('192.168.1.1'),
            ip_address('192.168.10.10'))
        result = ts2.intersection(self.object)
        self.assertIsNone(result)

    def test_intersection_invalid_type(self):
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV6_ADDR_RANGE,
            TrafficSelector.IpProtocol.UDP, 0, 10, ip_address('192.168.1.1'),
            ip_address('192.168.10.10'))
        result = ts2.intersection(self.object)
        self.assertIsNone(result)

class TestPayloadTS(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadTS, self).setUp()
        ts1 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            TrafficSelector.IpProtocol.UDP, 0, 10, ip_address('192.168.1.1'),
            ip_address('192.168.10.10'))
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            TrafficSelector.IpProtocol.ICMP, 100, 200, ip_address('192.168.1.1'),
            ip_address('192.168.10.10'))

        self.object = PayloadTS([ts1, ts2])

    def test_parse_random(self):
        with self.assertRaises(InvalidSyntax):
            super(TestPayloadTS, self).test_parse_random()

class TestPayloadAUTH(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadAUTH, self).setUp()
        self.object = PayloadAUTH(PayloadAUTH.Method.PSK, b'hello')

class TestPayloadNOTIFY(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadNOTIFY, self).setUp()
        self.object = PayloadNOTIFY(Proposal.Protocol.AH,
            PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN, b'spi', b'data')

class TestPayloadDELETE(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadDELETE, self).setUp()
        self.object = PayloadDELETE(Proposal.Protocol.AH, [b'1234', b'1235'])

class TestMessage(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestMessage, self).setUp()
        transform1 = Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96, 128)
        transform2 = Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1)
        transform3 = Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 256)
        proposal1 = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever', [transform1, transform2, transform3]
        )
        proposal2 = Proposal(
            20, Proposal.Protocol.IKE, b'anotherone', [transform3]
        )
        payload_sa = PayloadSA([proposal1, proposal2])
        payload_nonce = PayloadNONCE()
        payload_ke = PayloadKE(5, b'1234567890'*10)
        payload_vendor = PayloadVENDOR(b'pyikev2-test-0.1')
        payload_sk = PayloadSK(b'pyikev2-test-0.1')

        self.object = Message(
            spi_i=0,
            spi_r=0,
            major=2,
            minor=0,
            exchange_type=Message.Exchange.IKE_SA_INIT,
            is_response=False,
            can_use_higher_version=False,
            is_initiator=False,
            message_id=0,
            payloads=[payload_sa, payload_ke, payload_nonce, payload_vendor],
            encrypted_payloads = []
        )

    def test_parse_random(self):
        with self.assertRaises(UnsupportedCriticalPayload):
            super(TestMessage, self).test_parse_random()

    def test_no_proposals(self):
        with self.assertRaises(InvalidSyntax):
            PayloadSA([])

    def test_encrypted(self):
        transform1 = Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96, 128)
        transform2 = Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 256)
        proposal1 = Proposal(
            1, Proposal.Protocol.IKE, b'aspiwhatever', [transform1, transform2])

        payload_sa = PayloadSA([proposal1])
        payload_nonce = PayloadNONCE()

        message = Message(
            spi_i=0,
            spi_r=0,
            major=2,
            minor=0,
            exchange_type=Message.Exchange.IKE_SA_INIT,
            is_response=False,
            can_use_higher_version=False,
            is_initiator=False,
            message_id=0,
            payloads=[],
            encrypted_payloads = [payload_sa, payload_nonce]
        )

        crypto = Crypto(Cipher(Cipher.Id.ENCR_AES_CBC, 256), b'a' * 32,
            Integrity(Integrity.Id.AUTH_HMAC_SHA1_96), b'a' * 16,
            None, b'')

        a = str(message.to_dict())
        data = message.to_bytes(crypto)
        new_message = self.object.parse(data, header_only=False, crypto=crypto)
        b = str(new_message.to_dict())
        self.assertEqual(a, b)



if __name__ == '__main__':
    unittest.main()
