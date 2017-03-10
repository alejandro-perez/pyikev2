#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol messages.
"""
__author__ = 'Alejandro Perez <alex@um.es>'

import unittest
from message import (
    PayloadNonce, PayloadKE, PayloadVendor, PayloadSK, InvalidSyntax, Transform,
    Proposal, PayloadSA, Message, UnsupportedCriticalPayload
)
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

    def test_parse_twice(self):
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


class TestPayloadNonce(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadNonce, self).setUp()
        self.object = PayloadNonce()

    def test_parse_large(self):
        with self.assertRaises(InvalidSyntax):
            PayloadNonce.parse(b'1234567890' * 100)

class TestPayloadKE(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadKE, self).setUp()
        self.object = PayloadKE(5, b'1234567890'*10)

    def test_parse_large(self):
        PayloadKE.parse(b'1234567890' * 100)

class TestPayloadVendor(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadVendor, self).setUp()
        self.object = PayloadVendor(b'pyikev2-test-0.1')

    def test_parse_large(self):
        PayloadVendor.parse(b'1234567890' * 100)

class TestPayloadSK(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestPayloadSK, self).setUp()
        self.object = PayloadSK(b'pyikev2-test-0.1')

    def test_parse_large(self):
        PayloadSK.parse(b'1234567890' * 100)

class TestTransformWithKeylen(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTransformWithKeylen, self).setUp()
        self.object = Transform(Transform.Algorithm.AUTH_HMAC_SHA1_96, 128)

class TestTransformWOKeylen(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestTransformWOKeylen, self).setUp()
        self.object = Transform(Transform.Algorithm.PRF_HMAC_SHA1)

class TestProposal(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestProposal, self).setUp()
        transform1 = Transform(Transform.Algorithm.AUTH_HMAC_SHA1_96, 128)
        transform2 = Transform(Transform.Algorithm.PRF_HMAC_SHA1)
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
        transform1 = Transform(Transform.Algorithm.AUTH_HMAC_SHA1_96, 128)
        transform2 = Transform(Transform.Algorithm.PRF_HMAC_SHA1)
        transform3 = Transform(Transform.Algorithm.PRF_HMAC_SHA1, 64)
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

class TestMessage(TestPayloadMixin, unittest.TestCase):
    def setUp(self):
        super(TestMessage, self).setUp()
        transform1 = Transform(Transform.Algorithm.AUTH_HMAC_SHA1_96, 128)
        transform2 = Transform(Transform.Algorithm.PRF_HMAC_SHA1)
        transform3 = Transform(Transform.Algorithm.PRF_HMAC_SHA1, 64)
        proposal1 = Proposal(
            20, Proposal.Protocol.IKE, b'aspiwhatever', [transform1, transform2]
        )
        proposal2 = Proposal(
            20, Proposal.Protocol.IKE, b'anotherone', [transform3]
        )
        payload_sa = PayloadSA([proposal1, proposal2])
        payload_nonce = PayloadNonce()
        payload_ke = PayloadKE(5, b'1234567890'*10)
        payload_vendor = PayloadVendor(b'pyikev2-test-0.1')
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
            payloads=[payload_sa, payload_ke, payload_nonce, payload_vendor]
        )


    def test_parse_random(self):
        with self.assertRaises(UnsupportedCriticalPayload):
            super(TestMessage, self).test_parse_random()

    def test_no_proposals(self):
        with self.assertRaises(InvalidSyntax):
            PayloadSA([])

if __name__ == '__main__':
    unittest.main()
