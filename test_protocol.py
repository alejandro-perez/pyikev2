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
from message import TrafficSelector, Transform, Proposal, Message, Payload, PayloadAUTH, PayloadNOTIFY
from protocol import IkeSa

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
                        "peer_port": 23,
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

    def assertMessageHasNotification(self, message_data, ikesa, notification_type):
        message = Message.parse(message_data, crypto=ikesa.my_crypto)
        self.assertTrue(message.get_notifies(notification_type, ikesa.my_crypto is not None))

    @patch('xfrm.Xfrm')
    def test_initial_exchanges_transport(self, MockClass1):
        # initial exchanges
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_create_child_ok(self, MockClass1):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_res = self.ike_sa2.process_message(create_child_req)
        request = self.ike_sa1.process_message(create_child_res)
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
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        self.assertIsNone(ike_auth_req)
        self.assertMessageHasNotification(ike_sa_init_res, self.ike_sa2, PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_sa_init_invalid_ke(self, MockClass1):
        self.ike_sa1.configuration['dh'].insert(0, Transform(Transform.Type.DH, Transform.DhId.DH_1))
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_sa_init_req_newgroup = self.ike_sa1.process_message(ike_sa_init_res)
        ike_sa3 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi, my_addr=self.ip2, peer_addr=self.ip1,
                        configuration=self.configuration2.get_ike_configuration(self.ip1))
        ike_sa3.process_message(ike_sa_init_req_newgroup)
        self.assertMessageHasNotification(ike_sa_init_res, self.ike_sa2, PayloadNOTIFY.Type.INVALID_KE_PAYLOAD)
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
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN)
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
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.TS_UNACCEPTABLE)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_auth_type(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        message = Message.parse(ike_auth_req, crypto=self.ike_sa1.my_crypto)
        message.get_payload(Payload.Type.AUTH, encrypted=True).method = PayloadAUTH.Method.RSA
        ike_auth_req = message.to_bytes()
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.AUTHENTICATION_FAILED)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_auth_data(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        message = Message.parse(ike_auth_req, crypto=self.ike_sa1.my_crypto)
        message.get_payload(Payload.Type.AUTH, encrypted=True).auth_data += b'invalid'
        ike_auth_req = message.to_bytes()
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.AUTHENTICATION_FAILED)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_ts(self, MockClass1):
        self.ike_sa2.configuration['protect'][0]['my_subnet'] = ip_network("10.0.0.0/24")
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.TS_UNACCEPTABLE)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_missing_sa_payload(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        message = Message.parse(ike_auth_req, crypto=self.ike_sa1.my_crypto)
        payload_sa = message.get_payload(Payload.Type.SA, True)
        message.encrypted_payloads.remove(payload_sa)
        ike_auth_req = message.to_bytes()
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_retransmit(self, MockClass1):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_sa_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        create_child_sa_res2 = self.ike_sa2.process_message(create_child_sa_req)
        request = self.ike_sa1.process_message(create_child_sa_res2)
        self.assertIsNone(request)
        self.assertEqual(create_child_sa_res, create_child_sa_res2)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)

    @patch('xfrm.Xfrm')
    def test_invalid_message_id_on_request(self, MockClass1):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_sa_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        message = Message.parse(create_child_sa_req, crypto=self.ike_sa1.my_crypto)
        message.message_id = 100
        create_child_sa_req = message.to_bytes()
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.NEW_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertIsNone(create_child_sa_res)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_invalid_message_id_on_response(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        message = Message.parse(ike_sa_init_res, crypto=self.ike_sa2.my_crypto)
        message.message_id = 100
        ike_sa_init_res = message.to_bytes()
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        self.assertIsNone(ike_auth_req)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.INIT_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_invalid_exchange_type_on_request(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        message = Message.parse(ike_sa_init_req, crypto=self.ike_sa1.my_crypto)
        message.exchange_type = 100
        ike_sa_init_req = message.to_bytes()
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        self.assertIsNone(ike_sa_init_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.INIT_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.INITIAL)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_invalid_exchange_type_on_response(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        message = Message.parse(ike_sa_init_res)
        message.exchange_type = 100
        ike_sa_init_res = message.to_bytes()
        ike_auth_res = self.ike_sa1.process_message(ike_sa_init_res, self.ip1)
        self.assertIsNone(ike_auth_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.INIT_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_create_child_invalid_ts(self, MockClass1):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        # create additional CHILD_SA
        self.ike_sa2.configuration['protect'][0]['my_subnet'] = ip_network("10.0.0.0/24")
        create_child_sa_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        request = self.ike_sa1.process_message(create_child_sa_res, self.ip2)
        self.assertIsNone(request)
        self.assertMessageHasNotification(create_child_sa_res, self.ike_sa2, PayloadNOTIFY.Type.TS_UNACCEPTABLE)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa(self, MockClass1):
        self.test_initial_exchanges_transport()
        create_child_sa_req = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        delete_child_sa_req = self.ike_sa1.process_message(create_child_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DEL_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)
        delete_child_sa_res = self.ike_sa2.process_message(delete_child_sa_req)
        request = self.ike_sa1.process_message(delete_child_sa_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa_from_responder(self, MockClass1):
        self.test_initial_exchanges_transport()
        create_child_sa_req = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi)
        create_child_sa_res = self.ike_sa1.process_message(create_child_sa_req)
        delete_child_sa_req = self.ike_sa2.process_message(create_child_sa_res)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DEL_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)
        delete_child_sa_res = self.ike_sa1.process_message(delete_child_sa_req)
        request = self.ike_sa2.process_message(delete_child_sa_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa_invalid_spi_initiator(self, MockClass1):
        self.test_initial_exchanges_transport()
        create_child_sa_req = self.ike_sa1.process_expire(b'')
        self.assertIsNone(create_child_sa_req)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa_invalid_spi_responder(self, MockClass1):
        self.test_initial_exchanges_transport()
        self.ike_sa2.child_sas = []
        create_child_sa_req = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        delete_child_sa_req = self.ike_sa1.process_message(create_child_sa_res)
        self.assertIsNotNone(delete_child_sa_req)
        self.assertMessageHasNotification(create_child_sa_res, self.ike_sa2, PayloadNOTIFY.Type.CHILD_SA_NOT_FOUND)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DEL_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_delete_child_sa(self, MockClass1):
        self.test_initial_exchanges_transport()
        delete_child_sa_req = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi, hard=True)
        delete_child_sa_res = self.ike_sa2.process_message(delete_child_sa_req)
        request = self.ike_sa1.process_message(delete_child_sa_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_delete_child_sa_invalid_spi_on_response(self, MockClass1):
        self.test_initial_exchanges_transport()
        delete_child_sa_req = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi, hard=True)
        delete_child_sa_res = self.ike_sa2.process_message(delete_child_sa_req)
        message = Message.parse(delete_child_sa_res, crypto=self.ike_sa1.peer_crypto)
        message.get_payload(Payload.Type.DELETE, True).spis = []
        delete_child_sa_res = message.to_bytes()
        request = self.ike_sa1.process_message(delete_child_sa_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_simultaneous_rekey_child_delete_child(self, MockClass1):
        self.test_initial_exchanges_transport()
        rekey_request = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        delete_request = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi, hard=True)
        rekey_response = self.ike_sa2.process_message(rekey_request)
        delete_response = self.ike_sa1.process_message(delete_request)
        self.assertMessageHasNotification(rekey_response, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        delete_request_alice = self.ike_sa1.process_message(rekey_response)
        self.ike_sa2.process_message(delete_response)
        self.assertIsNone(delete_request_alice)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_simultaneous_delete_child_delete_child(self, MockClass1):
        self.test_initial_exchanges_transport()
        delete_request_alice = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi, hard=True)
        delete_request_bob = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi, hard=True)
        delete_response_bob = self.ike_sa2.process_message(delete_request_alice)
        delete_response_alice = self.ike_sa1.process_message(delete_request_bob)
        self.ike_sa1.process_message(delete_response_bob)
        self.ike_sa2.process_message(delete_response_alice)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_simultaneous_rekey_child_rekey_child(self, MockClass1):
        self.test_initial_exchanges_transport()
        logging.debug("==========================================")
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)
        rekey_request_alice = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        rekey_request_bob = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi)
        rekey_response_bob = self.ike_sa2.process_message(rekey_request_alice)
        rekey_response_alice = self.ike_sa1.process_message(rekey_request_bob)
        delete_request_alice = self.ike_sa1.process_message(rekey_response_bob)
        delete_request_bob = self.ike_sa2.process_message(rekey_response_alice)
        self.assertEqual(len(self.ike_sa1.child_sas), 3)
        self.assertEqual(len(self.ike_sa2.child_sas), 3)
        delete_response_alice = self.ike_sa1.process_message(delete_request_bob)
        delete_response_bob = self.ike_sa2.process_message(delete_request_alice)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DEL_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DEL_CHILD_REQ_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)
        self.ike_sa1.process_message(delete_response_bob)
        self.ike_sa2.process_message(delete_response_alice)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)

