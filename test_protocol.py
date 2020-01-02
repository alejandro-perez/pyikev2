#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for protocol messages.
"""

__author__ = 'Alejandro Perez <alex@um.es>'

import logging
from ipaddress import ip_address, ip_network
from unittest import TestCase
from unittest.mock import patch

import xfrm
from configuration import Configuration
from message import TrafficSelector, Transform, Proposal, Message, Payload, PayloadAUTH
from protocol import IkeSa, Acquire

logging.indent = 2
logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-6s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


class TestIkeSa(TestCase):
    @patch('xfrm.Xfrm')
    def setUp(self, MockClass1):
        self.ip1 = ip_address("192.168.0.1")
        self.ip2 = ip_address("192.168.0.2")
        self.configuration1 = Configuration(
            self.ip1,
            {
                "192.168.0.2": {
                    "id": "alice@openikev2",
                    "psk": "testing",
                    "dh": [5],
                    "protect": [{
                        "index": 1,
                        "ip_proto": "tcp",
                        "mode": "transport",
                        "lifetime": 5,
                        "peer_port": 0,
                        "ipsec_proto": "esp",
                        "encr": ["aes256", "aes128"]
                    }]
                }
            })
        self.configuration2 = Configuration(
            self.ip2,
            {
                "192.168.0.1": {
                    "id": "bob@openikev2",
                    "psk": "testing",
                    "dh": [5],
                    "protect": [{
                        "index": 2,
                        "ip_proto": "tcp",
                        "mode": "transport",
                        "lifetime": 5,
                        "peer_port": 0,
                        "ipsec_proto": "esp",
                        "encr": ["aes256", "aes128"]
                    }]
                }
            })
        self.ike_sa1 = IkeSa(is_initiator=True, peer_spi=b'\0' * 8,
                             configuration=self.configuration1.get_ike_configuration(self.ip2), my_addr=self.ip1,
                             peer_addr=self.ip2)
        self.ike_sa2 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi,
                             configuration=self.configuration2.get_ike_configuration(self.ip1), my_addr=self.ip2,
                             peer_addr=self.ip1)

    @patch('xfrm.Xfrm')
    def test_ok_transport(self, MockClass1):
        # initial exchanges
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

        # create additional CHILD_SA
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)

    @patch('xfrm.Xfrm')
    def test_ike_sa_init_no_proposal_chosen(self, MockClass1):
        self.ike_sa1.configuration['dh'][0].id = Transform.DhId.DH_1
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_sa_init_invalid_ke(self, MockClass1):
        self.ike_sa1.configuration['dh'].insert(0, Transform(Transform.Type.DH, Transform.DhId.DH_1))
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        ike_sa3 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi, my_addr=self.ip2, peer_addr=self.ip1,
                        configuration=self.configuration2.get_ike_configuration(self.ip1))
        ike_sa3.process_message(request, None)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.INIT_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(ike_sa3.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        self.assertEqual(len(ike_sa3.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_no_proposal_chosen(self, MockClass1):
        self.ike_sa1.configuration['protect'][0]['ipsec_proto'] = Proposal.Protocol.AH
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_mode(self, MockClass1):
        self.ike_sa2.configuration['protect'][0]['mode'] = xfrm.Mode.TUNNEL
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_auth_type(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        message = Message.parse(request, crypto=self.ike_sa1.my_crypto)
        payload_auth = message.get_payload(Payload.Type.AUTH, encrypted=True)
        payload_auth.method = PayloadAUTH.Method.RSA
        request = message.to_bytes()
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_auth_data(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        message = Message.parse(request, crypto=self.ike_sa1.my_crypto)
        payload_auth = message.get_payload(Payload.Type.AUTH, encrypted=True)
        payload_auth.auth_data += b'invalid'
        request = message.to_bytes()
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_ts(self, MockClass1):
        self.ike_sa2.configuration['protect'][0]['my_subnet'] = ip_network("10.0.0.0/24")
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_missing_payload(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        message = Message.parse(request, crypto=self.ike_sa1.my_crypto)
        payload_sa = message.get_payload(Payload.Type.SA, True)
        message.encrypted_payloads.remove(payload_sa)
        new_request = message.to_bytes()
        response = self.ike_sa2.process_message(new_request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_retransmit(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        response = self.ike_sa2.process_message(request, self.ip1)
        self.assertIsNone(self.ike_sa1.process_message(response, self.ip1))
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)
        response2 = self.ike_sa2.process_message(request, self.ip1)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(response, response2)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_invalid_message_id_on_request(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        response = self.ike_sa2.process_message(request, self.ip1)
        self.assertIsNone(self.ike_sa1.process_message(response, self.ip1))
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)
        message = Message.parse(request, crypto=self.ike_sa1.my_crypto)
        message.message_id = 100
        new_request = message.to_bytes()
        response = self.ike_sa2.process_message(new_request, self.ip1)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertIsNone(response)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_invalid_message_id_on_response(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        message = Message.parse(response, crypto=self.ike_sa2.my_crypto)
        message.message_id = 100
        response = message.to_bytes()
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.INIT_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_invalid_exchange_type_on_request(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        message = Message.parse(request, crypto=self.ike_sa1.my_crypto)
        message.exchange_type = 100
        request = message.to_bytes()
        response = self.ike_sa2.process_message(request, self.ip1)
        self.assertIsNone(response)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.AUTH_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_invalid_exchange_type_on_response(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        message = Message.parse(response)
        message.exchange_type = 100
        response = message.to_bytes()
        request = self.ike_sa1.process_message(response, self.ip1)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.INIT_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_create_child_invalid_ts(self, MockClass1):
        # initial exchanges
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

        # create additional CHILD_SA
        self.ike_sa2.configuration['protect'][0]['my_subnet'] = ip_network("10.0.0.0/24")
        acquire = Acquire(small_tsi, small_tsr, 1)
        request = self.ike_sa1.process_acquire(acquire)
        response = self.ike_sa2.process_message(request, self.ip1)
        request = self.ike_sa1.process_message(response, self.ip2)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa(self, MockClass1):
        self.test_ok_transport()
        request = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        response = self.ike_sa2.process_message(request, self.ike_sa1.my_addr)
        request = self.ike_sa1.process_message(response, self.ike_sa1.peer_addr)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DEL_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 3)
        self.assertEqual(len(self.ike_sa2.child_sas), 3)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa_invalid_spi(self, MockClass1):
        self.test_ok_transport()
        request = self.ike_sa1.process_expire(b'')
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
