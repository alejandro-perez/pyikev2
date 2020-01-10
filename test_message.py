#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for protocol messages.
"""
import unittest
from ipaddress import ip_address
from ipaddress import ip_network

from crypto import Cipher, Integrity, Crypto
from message import (
    PayloadNONCE, PayloadKE, PayloadVENDOR, PayloadSK, InvalidSyntax,
    Transform, Proposal, PayloadSA, Message, UnsupportedCriticalPayload,
    PayloadID, TrafficSelector, PayloadTS, PayloadAUTH, PayloadNOTIFY,
    PayloadDELETE
)

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


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
        data1 = self.object.to_bytes()
        new_payload = self.object.parse(data1)
        data2 = new_payload.to_bytes()
        self.assertEqual(data1, data2)

    def test_parse_no_data(self):
        payload_class = type(self.object)
        with self.assertRaises(InvalidSyntax):
            payload_class.parse(b'')

    def test_parse_random(self):
        payload_class = type(self.object)
        payload_class.parse(self.random_data)


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
        self.object = PayloadKE(5, b'1234567890' * 10)

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
        integrity = Integrity(Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA1_96))
        cipher = Cipher(Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 256))
        encryption_key = b'Mypassword121111' * 2
        iv = cipher.generate_iv()
        crypto = Crypto(cipher, encryption_key, integrity, b'', None, b'')

        payload_sk = PayloadSK.generate(b'Hello there!', iv, crypto)
        iv2, clear = payload_sk.decrypt(crypto)
        self.assertEqual(clear, b'Hello there!')
        self.assertEqual(iv, iv2)


class TestTransformWithKeylen(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTransformWithKeylen, self).setUp()
        self.object = Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 128)

    def test_eq(self):
        another = Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 128)
        self.assertEqual(self.object, another)

    def test_not_eq(self):
        another = Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 256)
        self.assertNotEqual(self.object, another)


class TestTransformWithoutKeylen(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTransformWithoutKeylen, self).setUp()
        self.object = Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)


class TestProposal(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestProposal, self).setUp()
        transform1 = Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA1_96)
        transform2 = Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)
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

    def test_no_spi(self):
        transform1 = Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA1_96)
        transform2 = Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)
        proposal = Proposal(20, Proposal.Protocol.IKE, b'', [transform1, transform2])
        data = proposal.to_bytes()
        proposal = Proposal.parse(data)
        self.assertEqual(proposal.spi, b'')

    def test_invalid_transform_header(self):
        data = self.object.to_bytes()
        with self.assertRaises(InvalidSyntax):
            Proposal.parse(data[:-5])

    def test_get_transform(self):
        self.object.get_transform(Transform.Type.INTEG)
        self.object.get_transforms(Transform.Type.PRF)

    def test_intersection(self):
        proposal = Proposal(20, Proposal.Protocol.IKE, b'aspiwhatever',
                            [Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA1_96),
                             Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 128),
                             Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)])
        intersection = self.object.intersection(proposal)
        self.assertEqual(intersection, self.object)
        self.assertIsNone(proposal.intersection(self.object))

    def test_is_subset(self):
        proposal = Proposal(20, Proposal.Protocol.IKE, b'aspiwhatever',
                            [Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA1_96),
                             Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 128),
                             Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)])
        self.assertTrue(self.object.is_subset(proposal))

    def test_eq(self):
        transform1 = Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA1_96)
        transform2 = Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)
        transform3 = Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_MD5)
        proposal = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever',
            [transform2, transform1]
        )
        proposal2 = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever',
            [transform2]
        )
        proposal3 = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever',
            [transform1, transform2, transform3]
        )
        self.assertEqual(self.object, proposal)
        self.assertNotEqual(self.object, proposal2)
        self.assertNotEqual(self.object, proposal3)


class TestPayloadSA(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadSA, self).setUp()
        transform1 = Transform(Transform.Type.INTEG,
                               Transform.IntegId.AUTH_HMAC_SHA1_96)
        transform2 = Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)
        transform3 = Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 128)
        proposal1 = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever',
            [transform1, transform2]
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

    def test_no_spi(self):
        payload = PayloadNOTIFY(Proposal.Protocol.IKE, PayloadNOTIFY.Type.NO_ADDITIONAL_SAS,
                                b'', b'this is notification data')
        data = payload.to_bytes()
        payload = PayloadNOTIFY.parse(data)
        self.assertEqual(payload.spi, b'')


class TestPayloadIDIpAddr(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadIDIpAddr, self).setUp()
        self.object = PayloadID(PayloadID.Type.ID_IPV4_ADDR, b'192.168.1.1')


class TestPayloadIDEmail(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadIDEmail, self).setUp()
        self.object = PayloadID(PayloadID.Type.ID_RFC822_ADDR, b'pyikev2@github')


class TestPayloadIDOther(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadIDOther, self).setUp()
        self.object = PayloadID(PayloadID.Type.ID_DER_ASN1_DN, b'something')


class TestTrafficSelector(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTrafficSelector, self).setUp()
        self.object = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                      TrafficSelector.IpProtocol.UDP, 0, 10,
                                      ip_address('192.168.1.1'),
                                      ip_address('192.168.10.10'))

    def test_issubnet(self):
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                              TrafficSelector.IpProtocol.UDP, 4, 10,
                              ip_address('192.168.1.5'),
                              ip_address('192.168.10.10'))
        self.assertTrue(ts2.is_subset(self.object))

    def test_isnotsubset(self):
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                              TrafficSelector.IpProtocol.TCP, 0, 10,
                              ip_address('192.168.1.1'),
                              ip_address('192.168.10.10'))
        self.assertFalse(ts2.is_subset(self.object))

    def test_from_network(self):
        ts = TrafficSelector.from_network(
            ip_network('192.168.2.0/22', strict=False), 0, 0)
        self.assertEqual(ts.end_addr, ip_address('192.168.3.255'))

    def test_get_network(self):
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                              TrafficSelector.IpProtocol.TCP, 0, 10,
                              ip_address('192.168.1.1'),
                              ip_address('192.168.10.10'))
        self.assertEqual(ts2.get_network(), ip_network('192.168.0.0/20'))


class TestPayloadTS(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadTS, self).setUp()
        ts1 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                              TrafficSelector.IpProtocol.UDP, 0, 10,
                              ip_address('192.168.1.1'),
                              ip_address('192.168.10.10'))
        ts2 = TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                              TrafficSelector.IpProtocol.ICMP, 100, 200,
                              ip_address('192.168.1.1'),
                              ip_address('192.168.10.10'))

        self.object = PayloadTS([ts1, ts2])

    def test_parse_random(self):
        with self.assertRaises(InvalidSyntax):
            super(TestPayloadTS, self).test_parse_random()


class TestPayloadAUTH(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadAUTH, self).setUp()
        self.object = PayloadAUTH(PayloadAUTH.Method.PSK, b'hello')


class TestPayloadDELETE(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadDELETE, self).setUp()
        self.object = PayloadDELETE(Proposal.Protocol.AH, [b'1234', b'1235'])


class TestMessage(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestMessage, self).setUp()
        transform1 = Transform(Transform.Type.INTEG,
                               Transform.IntegId.AUTH_HMAC_SHA1_96)
        transform2 = Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1)
        transform3 = Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC,
                               256)
        proposal1 = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever',
            [transform1, transform2, transform3]
        )
        proposal2 = Proposal(
            20, Proposal.Protocol.IKE, b'anotherone', [transform3]
        )
        payload_sa = PayloadSA([proposal1, proposal2])
        payload_nonce = PayloadNONCE()
        payload_ke = PayloadKE(5, b'1234567890' * 10)
        payload_vendor = PayloadVENDOR(b'pyikev2-test-0.1')

        self.object = Message(
            spi_i=b'12345678',
            spi_r=b'12345678',
            major=2,
            minor=0,
            exchange_type=Message.Exchange.IKE_SA_INIT,
            is_response=False,
            can_use_higher_version=False,
            is_initiator=False,
            message_id=0,
            payloads=[payload_sa, payload_ke, payload_nonce, payload_vendor],
            encrypted_payloads=[]
        )

    def test_parse_random(self):
        with self.assertRaises(UnsupportedCriticalPayload):
            super(TestMessage, self).test_parse_random()

    def test_no_proposals(self):
        with self.assertRaises(InvalidSyntax):
            PayloadSA([])

    def test_encrypted(self):
        transform1 = Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA2_256_128)
        transform2 = Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 256)
        proposal1 = Proposal(1, Proposal.Protocol.IKE, b'aspiwhatever', [transform1, transform2])

        payload_sa = PayloadSA([proposal1])
        payload_nonce = PayloadNONCE(b'123456789012341232132132131')

        crypto = Crypto(Cipher(Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 256)),
                        b'a' * 32,
                        Integrity(Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA2_512_256)),
                        b'a' * 8,
                        None, b'')

        message = Message(
            spi_i=b'12345678',
            spi_r=b'12345678',
            major=2,
            minor=0,
            exchange_type=Message.Exchange.IKE_AUTH,
            is_response=False,
            can_use_higher_version=False,
            is_initiator=False,
            message_id=0,
            payloads=[],
            encrypted_payloads=[payload_sa, payload_nonce],
            crypto=crypto
        )

        data = message.to_bytes()
        new_message = Message.parse(data, crypto=crypto)
        data2 = new_message.to_bytes()
        self.assertEqual(data, data2)


if __name__ == '__main__':
    unittest.main()
