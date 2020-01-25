#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for protocol messages.
"""

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'

import logging
import time
import unittest
from ipaddress import ip_address, ip_network
from unittest import TestCase
from unittest.mock import patch

import xfrm
from configuration import Configuration
from message import TrafficSelector, Transform, Proposal, Message, Payload, PayloadAUTH, PayloadNOTIFY
from ikesa import IkeSa

logging.indent = 2
logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


# logging.disable()

class TestIkeSa(TestCase):
    @patch('xfrm.Xfrm')
    def setUp(self, mockclass):
        self.ip1 = ip_address("192.168.0.1")
        self.ip2 = ip_address("192.168.0.2")
        self.confdict = {
            "testconn_alice": {
                "my_addr": str(self.ip1),
                "peer_addr": str(self.ip2),
                "my_auth": {"id": "alice@openikev2", "psk": "testing"},
                "peer_auth": {"id": "bob@openikev2", "psk": "testing2"},
                "dh": [14],
                "integ": ["sha256"],
                "prf": ["sha256"],
                "protect": [{
                    "index": 1,
                    "ip_proto": "tcp",
                    "mode": "transport",
                    "lifetime": 5,
                    "peer_port": 0,
                    "ipsec_proto": "esp",
                    "encr": ["aes256", "aes128"],
                }]
            },
            "testconn_bob": {
                "my_addr": str(self.ip2),
                "peer_addr": str(self.ip1),
                "my_auth": {"id": "bob@openikev2", "psk": "testing2"},
                "peer_auth": {"id": "alice@openikev2", "psk": "testing"},
                "dh": [14],
                "integ": ["sha256"],
                "prf": ["sha256"],
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
        }
        self.configuration = Configuration([self.ip1, self.ip2], self.confdict)
        self.ike_sa1 = IkeSa(is_initiator=True, peer_spi=b'\0' * 8,
                             configuration=self.configuration.get_ike_configuration(self.ip2), my_addr=self.ip1,
                             peer_addr=self.ip2)
        self.ike_sa2 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi,
                             configuration=self.configuration.get_ike_configuration(self.ip1), my_addr=self.ip2,
                             peer_addr=self.ip1)

    def assertMessageHasNotification(self, message_data, ikesa, notification_type):
        message = Message.parse(message_data, crypto=ikesa.my_crypto)
        self.assertTrue(message.get_notifies(notification_type, ikesa.my_crypto is not None))

    @patch('xfrm.Xfrm')
    def test_initial_exchanges_transport(self, mockclass):
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
    def test_initial_exchanges_transport_rsa(self, mockclass):
        privkey = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDEkT4cscvAVzUjuK4rsCvETPixVfGGep/hUBcHnZyxN7XiFmaO
EdE+W4TZ9EZy06W83qPfSYJrKt9n++mlFNWYgFsRtFMsP0X9Z6c7QBTt684+NRZ6
Te4Jyv/VrKxN/mCSufdQ88s6Wa/KhV8JiWvYs1l+sEuNUHHDSswFehNOFQIDAQAB
AoGAQDmIhs2c2hJkXXCJD+M22aOgmiiPirXkKTUG4UkhGlIujlltVrwBlxNF/ASx
Q/FdNLG1703QW/2dExefBn4hL2jYObHAwFVGaiBLBEa0RzzkhHdQ0AE5Q0sPZL1w
MW6TbIvI7DkXlTb8A1TaVrgQLf3AAtBs/6VQj7SkvfctLV0CQQDu0+jYXPGxIXeM
QDCR2HzNu7IcvV0tyRqgToqFVf6tLFu60mX/kKgGPubcjU5qmU8D4Mqw3aEoJVs1
nDCZ8NarAkEA0rNyn7/Usf/yV+pyuzylUw++0tw5bGd+16R3xebdExj9tEARfGcQ
1KnmjeNGSbIN8se1lSYFqpjuu8R0BrNuPwJAaqDZ+J+mmPrkMQ4HoVYSgpgmcYZq
L6L17FSkq9s1FYQUgFiniW7AVemHkTjVpepEyOp4FHcfGJl1G35chJ5ueQJBAMv+
lxyZorkPf7eksp4bEkl/9hW6yBHvhfwMLTY61ZG24XMRkJxsQPxU3nZDM/sH279R
obmcjWHlHUZH5rnSIQsCQQCDGkbQJcDHS0bRSjVryAHZ8jQTTjTPBUAtHjzr4Xn0
IFf9L0pXd5MDpf5FhuOofyKzFYd08dMG1J/hm6DLFX0F
-----END RSA PRIVATE KEY-----
"""
        pubkey = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEkT4cscvAVzUjuK4rsCvETPix
VfGGep/hUBcHnZyxN7XiFmaOEdE+W4TZ9EZy06W83qPfSYJrKt9n++mlFNWYgFsR
tFMsP0X9Z6c7QBTt684+NRZ6Te4Jyv/VrKxN/mCSufdQ88s6Wa/KhV8JiWvYs1l+
sEuNUHHDSswFehNOFQIDAQAB
-----END PUBLIC KEY-----'''
        self.confdict['testconn_alice']['my_auth']['privkey'] = privkey
        self.confdict['testconn_bob']['peer_auth']['pubkey'] = pubkey
        self.configuration = Configuration([self.ip1, self.ip2], self.confdict)
        self.ike_sa1.configuration = self.configuration.get_ike_configuration(self.ip2)
        self.ike_sa2.configuration = self.configuration.get_ike_configuration(self.ip1)
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
    def test_create_child_ok(self, mockclass):
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
    def test_create_child_with_ke(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.configuration.protect[0] = self.ike_sa1.configuration.protect[0]._replace(
            dh=[Transform(Transform.Type.DH, Transform.DhId.DH_14)])
        self.ike_sa2.configuration.protect[0] = self.ike_sa2.configuration.protect[0]._replace(
            dh=[Transform(Transform.Type.DH, Transform.DhId.DH_14)])
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
    def test_create_child_invalid_ke(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.configuration.protect[0] = self.ike_sa1.configuration.protect[0]._replace(
            dh=[Transform(Transform.Type.DH, Transform.DhId.DH_18),
                Transform(Transform.Type.DH, Transform.DhId.DH_14)])
        self.ike_sa2.configuration.protect[0] = self.ike_sa2.configuration.protect[0]._replace(
            dh=[Transform(Transform.Type.DH, Transform.DhId.DH_14)])
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_res = self.ike_sa2.process_message(create_child_req)
        self.assertMessageHasNotification(create_child_res, self.ike_sa2, PayloadNOTIFY.Type.INVALID_KE_PAYLOAD)
        create_child_req = self.ike_sa1.process_message(create_child_res)
        create_child_res = self.ike_sa2.process_message(create_child_req)
        request = self.ike_sa1.process_message(create_child_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)

    @patch('xfrm.Xfrm')
    def test_ike_sa_init_no_proposal_chosen(self, mockclass):
        self.ike_sa1.configuration.dh[0].id = Transform.DhId.DH_16
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
    def test_ike_sa_init_invalid_ke(self, mockclass):
        self.ike_sa1.configuration.dh.insert(0, Transform(Transform.Type.DH, Transform.DhId.DH_16))
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        self.assertMessageHasNotification(ike_sa_init_res, self.ike_sa2, PayloadNOTIFY.Type.INVALID_KE_PAYLOAD)
        ike_sa_init_req_newgroup = self.ike_sa1.process_message(ike_sa_init_res)
        ike_sa3 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi, my_addr=self.ip2, peer_addr=self.ip1,
                        configuration=self.configuration.get_ike_configuration(self.ip1))
        ike_sa_init_res = ike_sa3.process_message(ike_sa_init_req_newgroup)
        self.ike_sa1.process_message(ike_sa_init_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.AUTH_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(ike_sa3.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        self.assertEqual(len(ike_sa3.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_sa_init_cookie(self, mockclass):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        self.ike_sa2.cookie_secret = b'secret'
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        self.assertMessageHasNotification(ike_sa_init_res, self.ike_sa2, PayloadNOTIFY.Type.COOKIE)
        ike_sa_init_req_cookie = self.ike_sa1.process_message(ike_sa_init_res)
        ike_sa3 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi, my_addr=self.ip2, peer_addr=self.ip1,
                        configuration=self.configuration.get_ike_configuration(self.ip1))
        ike_sa_init_res = ike_sa3.process_message(ike_sa_init_req_cookie)
        self.ike_sa1.process_message(ike_sa_init_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.AUTH_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(ike_sa3.state, IkeSa.State.INIT_RES_SENT)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        self.assertEqual(len(ike_sa3.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_no_proposal_chosen(self, mockclass):
        self.ike_sa1.configuration.protect[0] = self.ike_sa1.configuration.protect[0]._replace(
            ipsec_proto=Proposal.Protocol.AH)
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
    def test_ike_auth_invalid_mode(self, mockclass):
        self.ike_sa2.configuration.protect[0] = self.ike_sa2.configuration.protect[0]._replace(mode=xfrm.Mode.TUNNEL)
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
    def test_ike_auth_invalid_auth_type(self, mockclass):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        message = Message.parse(ike_auth_req, crypto=self.ike_sa1.my_crypto)
        message.get_payload(Payload.Type.AUTH, encrypted=True).method = 100
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
    def test_ike_auth_invalid_auth_data(self, mockclass):
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
    def test_ike_auth_invalid_id_type(self, mockclass):
        self.confdict['testconn_alice']['my_auth']['id'] = 'carol'
        self.configuration = Configuration([self.ip1, self.ip2], self.confdict)
        self.ike_sa1.configuration = self.configuration.get_ike_configuration(self.ip2)
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.AUTHENTICATION_FAILED)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_id_type_responder(self, mockclass):
        self.confdict['testconn_bob']['my_auth']['id'] = 'carol'
        self.configuration = Configuration([self.ip1, self.ip2], self.confdict)
        self.ike_sa2.configuration = self.configuration.get_ike_configuration(self.ip1)
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_id_data(self, mockclass):
        self.confdict['testconn_alice']['my_auth']['id'] = 'alice@openikev3'
        self.configuration = Configuration([self.ip1, self.ip2], self.confdict)
        self.ike_sa1.configuration = self.configuration.get_ike_configuration(self.ip2)
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(ike_auth_res, self.ike_sa2, PayloadNOTIFY.Type.AUTHENTICATION_FAILED)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_id_data_responder(self, mockclass):
        self.confdict['testconn_bob']['my_auth']['id'] = 'carol@openikev2'
        self.configuration = Configuration([self.ip1, self.ip2], self.confdict)
        self.ike_sa2.configuration = self.configuration.get_ike_configuration(self.ip1)
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        ike_sa_init_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        ike_sa_init_res = self.ike_sa2.process_message(ike_sa_init_req)
        ike_auth_req = self.ike_sa1.process_message(ike_sa_init_res)
        ike_auth_res = self.ike_sa2.process_message(ike_auth_req)
        request = self.ike_sa1.process_message(ike_auth_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_ike_auth_invalid_ts(self, mockclass):
        self.ike_sa2.configuration.protect[0] = self.ike_sa2.configuration.protect[0]._replace(
            my_subnet=ip_network("10.0.0.0/24"))
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
    def test_ike_auth_missing_sa_payload(self, mockclass):
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
    def test_retransmit(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_sa_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        create_child_sa_req = self.ike_sa1.check_retransmission_timer()
        self.assertIsNone(create_child_sa_req)
        self.ike_sa1.retransmit_at = time.time()
        create_child_sa_req = self.ike_sa1.check_retransmission_timer()
        self.assertIsNotNone(create_child_sa_req)
        create_child_sa_res2 = self.ike_sa2.process_message(create_child_sa_req)
        request = self.ike_sa1.process_message(create_child_sa_res2)
        self.assertIsNone(request)
        self.assertEqual(create_child_sa_res, create_child_sa_res2)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)

    @patch('xfrm.Xfrm')
    def test_max_retransmit(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_sa_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        self.assertIsNotNone(create_child_sa_req)
        for i in range(0, IkeSa.MAX_RETRANSMISSIONS - 1):
            self.ike_sa1.retransmit_at = time.time()
            create_child_sa_req = self.ike_sa1.check_retransmission_timer()
            self.assertIsNotNone(create_child_sa_req)
        self.ike_sa1.retransmit_at = time.time()
        create_child_sa_req = self.ike_sa1.check_retransmission_timer()
        self.assertIsNone(create_child_sa_req)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)

    @patch('xfrm.Xfrm')
    def test_invalid_mode_in_response(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_sa_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        message = Message.parse(create_child_sa_res, crypto=self.ike_sa2.my_crypto)
        message.encrypted_payloads.remove(message.get_notifies(PayloadNOTIFY.Type.USE_TRANSPORT_MODE, True)[0])
        create_child_sa_res = message.to_bytes()
        request = self.ike_sa1.process_message(create_child_sa_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_invalid_message_id_on_request(self, mockclass):
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
    def test_invalid_message_id_on_response(self, mockclass):
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
    def test_invalid_exchange_type_on_request(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        message = Message.parse(create_child_req, crypto=self.ike_sa1.my_crypto)
        message.exchange_type = 100
        create_child_req = message.to_bytes()
        create_child_res = self.ike_sa2.process_message(create_child_req)
        self.assertIsNone(create_child_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.NEW_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_invalid_exchange_type_on_response(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        crate_child_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        crate_child_res = self.ike_sa2.process_message(crate_child_req)
        message = Message.parse(crate_child_res, self.ike_sa1.peer_crypto)
        message.exchange_type = 100
        crate_child_res = message.to_bytes()
        request = self.ike_sa1.process_message(crate_child_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.NEW_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)

    @patch('xfrm.Xfrm')
    def test_create_child_invalid_ts(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        # create additional CHILD_SA
        self.ike_sa2.configuration.protect[0] = self.ike_sa2.configuration.protect[0]._replace(
            my_subnet=ip_network("10.0.0.0/24"))
        create_child_sa_req = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        request = self.ike_sa1.process_message(create_child_sa_res)
        self.assertIsNone(request)
        self.assertMessageHasNotification(create_child_sa_res, self.ike_sa2, PayloadNOTIFY.Type.TS_UNACCEPTABLE)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa(self, mockclass):
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
    def test_rekey_child_sa_from_responder(self, mockclass):
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
    def test_rekey_child_sa_invalid_spi_initiator(self, mockclass):
        self.test_initial_exchanges_transport()
        create_child_sa_req = self.ike_sa1.process_expire(b'')
        self.assertIsNone(create_child_sa_req)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_rekey_child_sa_invalid_spi_responder(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa2.child_sas = []
        create_child_sa_req = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        create_child_sa_res = self.ike_sa2.process_message(create_child_sa_req)
        delete_child_sa_req = self.ike_sa1.process_message(create_child_sa_res)
        self.assertIsNone(delete_child_sa_req)
        self.assertMessageHasNotification(create_child_sa_res, self.ike_sa2, PayloadNOTIFY.Type.CHILD_SA_NOT_FOUND)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_delete_child_sa(self, mockclass):
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
    def test_delete_child_sa_invalid_spi(self, mockclass):
        self.test_initial_exchanges_transport()
        delete_child_sa_req = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi, hard=True)
        self.ike_sa2.delete_child_sas()
        delete_child_sa_res = self.ike_sa2.process_message(delete_child_sa_req)
        request = self.ike_sa1.process_message(delete_child_sa_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)

    @patch('xfrm.Xfrm')
    def test_delete_child_sa_invalid_spi_on_response(self, mockclass):
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
    def test_simultaneous_rekey_child_delete_child(self, mockclass):
        self.test_initial_exchanges_transport()
        rekey_request = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        delete_request = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi, hard=True)
        rekey_response = self.ike_sa2.process_message(rekey_request)
        delete_response = self.ike_sa1.process_message(delete_request)
        self.assertMessageHasNotification(rekey_response, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        delete_request_alice = self.ike_sa1.process_message(rekey_response)
        request_bob = self.ike_sa2.process_message(delete_response)
        self.assertIsNone(delete_request_alice)
        self.assertIsNone(request_bob)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_simultaneous_delete_child_delete_child(self, mockclass):
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
    def test_simultaneous_rekey_child_rekey_child(self, mockclass):
        self.test_initial_exchanges_transport()
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)
        rekey_request_alice = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi)
        rekey_request_bob = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi)
        rekey_response_bob = self.ike_sa2.process_message(rekey_request_alice)
        rekey_response_alice = self.ike_sa1.process_message(rekey_request_bob)
        self.assertMessageHasNotification(rekey_response_alice, self.ike_sa1, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        self.assertMessageHasNotification(rekey_response_bob, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        delete_request_alice = self.ike_sa1.process_message(rekey_response_bob)
        delete_request_bob = self.ike_sa2.process_message(rekey_response_alice)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(len(self.ike_sa2.child_sas), 1)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertIsNone(delete_request_alice)
        self.assertIsNone(delete_request_bob)

    @patch('xfrm.Xfrm')
    def test_dead_peer_detection(self, mockclass):
        self.test_initial_exchanges_transport()
        dpd_req = self.ike_sa1.check_dead_peer_detection_timer()
        self.assertIsNone(dpd_req)
        self.ike_sa1.start_dpd_at = time.time()
        dpd_req = self.ike_sa1.check_dead_peer_detection_timer()
        dpd_res = self.ike_sa2.process_message(dpd_req)
        request = self.ike_sa1.process_message(dpd_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.ike_sa2.start_dpd_at = time.time()
        dpd_req = self.ike_sa2.check_dead_peer_detection_timer()
        dpd_res = self.ike_sa1.process_message(dpd_req)
        request = self.ike_sa2.process_message(dpd_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_peer_changes_spi(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.start_dpd_at = time.time()
        dpd_req = self.ike_sa1.check_dead_peer_detection_timer()
        message = Message.parse(dpd_req, self.ike_sa1.peer_crypto)
        message.spi_i = b'1' * 8
        dpd_req = message.to_bytes()
        dpd_res = self.ike_sa2.process_message(dpd_req)
        self.assertIsNone(dpd_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DPD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)

    @patch('xfrm.Xfrm')
    def test_delete_ike_sa(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.delete_ike_sa_at = time.time()
        delete_req = self.ike_sa1.check_rekey_ike_sa_timer()
        delete_res = self.ike_sa2.process_message(delete_req)
        req = self.ike_sa1.process_message(delete_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)

    @patch('xfrm.Xfrm')
    def test_rekey_ike_sa(self, mockclass):
        self.test_initial_exchanges_transport()
        rekey_req = self.ike_sa1.check_rekey_ike_sa_timer()
        self.assertIsNone(rekey_req)
        self.ike_sa1.rekey_ike_sa_at = time.time()
        rekey_req = self.ike_sa1.check_rekey_ike_sa_timer()
        rekey_res = self.ike_sa2.process_message(rekey_req)
        delete_req = self.ike_sa1.process_message(rekey_res)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        rekey_request = self.ike_sa1.new_ike_sa.process_expire(self.ike_sa1.new_ike_sa.child_sas[0].inbound_spi)
        rekey_response = self.ike_sa2.new_ike_sa.process_message(rekey_request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DEL_AFTER_REKEY_IKE_SA_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.REKEYED)
        self.assertIsNotNone(rekey_req)
        self.assertIsNotNone(delete_req)

    @patch('xfrm.Xfrm')
    def test_rekey_ike_sa_rejected(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.rekey_ike_sa_at = time.time()
        rekey_req = self.ike_sa1.check_rekey_ike_sa_timer()
        rekey_res = self.ike_sa2.process_message(rekey_req)
        message = Message.parse(rekey_res, crypto=self.ike_sa2.my_crypto)
        message.encrypted_payloads = [
            PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.NO_ADDITIONAL_SAS, b'', b'')]
        rekey_res = message.to_bytes()
        delete_req = self.ike_sa1.process_message(rekey_res)
        self.assertIsNotNone(delete_req)
        self.assertEqual(len(self.ike_sa1.child_sas), 1)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DEL_IKE_SA_REQ_SENT)

    @patch('xfrm.Xfrm')
    def test_rekey_ike_sa_from_responder(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa2.rekey_ike_sa_at = time.time()
        rekey_req = self.ike_sa2.check_rekey_ike_sa_timer()
        rekey_res = self.ike_sa1.process_message(rekey_req)
        delete_req = self.ike_sa2.process_message(rekey_res)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        rekey_request = self.ike_sa2.new_ike_sa.process_expire(self.ike_sa2.new_ike_sa.child_sas[0].inbound_spi)
        rekey_response = self.ike_sa1.new_ike_sa.process_message(rekey_request)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DEL_AFTER_REKEY_IKE_SA_REQ_SENT)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.REKEYED)
        self.assertIsNotNone(rekey_req)

    @patch('xfrm.Xfrm')
    def test_simultaneous_rekey_ike_sa(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.rekey_ike_sa_at = time.time()
        self.ike_sa2.rekey_ike_sa_at = time.time()
        rekey_req_alice = self.ike_sa1.check_rekey_ike_sa_timer()
        rekey_req_bob = self.ike_sa2.check_rekey_ike_sa_timer()
        rekey_res_alice = self.ike_sa1.process_message(rekey_req_bob)
        rekey_res_bob = self.ike_sa2.process_message(rekey_req_alice)
        self.assertMessageHasNotification(rekey_res_alice, self.ike_sa1, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        self.assertMessageHasNotification(rekey_res_bob, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        delete_req_alice = self.ike_sa1.process_message(rekey_res_bob)
        delete_req_bob = self.ike_sa2.process_message(rekey_res_alice)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertIsNone(delete_req_alice)
        self.assertIsNone(delete_req_bob)

    @patch('xfrm.Xfrm')
    def test_simultaneous_rekey_ike_sa_rekey_child(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.rekey_ike_sa_at = time.time()
        rekey_ike_sa_req = self.ike_sa1.check_rekey_ike_sa_timer()
        rekey_child_sa_req = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi, hard=False)
        rekey_ike_sa_res = self.ike_sa2.process_message(rekey_ike_sa_req)
        rekey_child_sa_res = self.ike_sa1.process_message(rekey_child_sa_req)
        self.assertMessageHasNotification(rekey_child_sa_res, self.ike_sa1, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        self.assertMessageHasNotification(rekey_ike_sa_res, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        delete_ike_sa_req = self.ike_sa1.process_message(rekey_ike_sa_res)
        delete_child_sa_req = self.ike_sa2.process_message(rekey_child_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertIsNone(delete_child_sa_req)
        self.assertIsNone(delete_ike_sa_req)

    @patch('xfrm.Xfrm')
    def test_simultaneous_rekey_ike_sa_create_child(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        self.ike_sa1.rekey_ike_sa_at = time.time()
        rekey_ike_sa_req = self.ike_sa1.check_rekey_ike_sa_timer()
        create_child_sa_req = self.ike_sa2.process_acquire(small_tsr, small_tsi, 2)
        rekey_ike_sa_res = self.ike_sa2.process_message(rekey_ike_sa_req)
        create_child_sa_res = self.ike_sa1.process_message(create_child_sa_req)
        self.assertMessageHasNotification(create_child_sa_res, self.ike_sa1, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        self.assertMessageHasNotification(rekey_ike_sa_res, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        delete_ike_sa_req = self.ike_sa1.process_message(rekey_ike_sa_res)
        delete_child_sa_req = self.ike_sa2.process_message(create_child_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertIsNone(delete_child_sa_req)
        self.assertIsNone(delete_ike_sa_req)

    @patch('xfrm.Xfrm')
    def test_simultaneous_del_ike_sa_create_child(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        self.ike_sa1.delete_ike_sa_at = time.time()
        del_ike_sa_req = self.ike_sa1.check_rekey_ike_sa_timer()
        create_child_sa_req = self.ike_sa2.process_acquire(small_tsr, small_tsi, 2)
        del_ike_sa_res = self.ike_sa2.process_message(del_ike_sa_req)
        create_child_sa_res = self.ike_sa1.process_message(create_child_sa_req)
        self.assertMessageHasNotification(create_child_sa_res, self.ike_sa1, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        request_alice = self.ike_sa1.process_message(del_ike_sa_res)
        request_bob = self.ike_sa2.process_message(create_child_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertIsNone(request_alice)
        self.assertIsNone(request_bob)

    @patch('xfrm.Xfrm')
    def test_simultaneous_del_ike_sa_rekey_child(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.delete_ike_sa_at = time.time()
        del_ike_sa_req = self.ike_sa1.check_rekey_ike_sa_timer()
        rekey_child_sa_req = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi, hard=False)
        del_ike_sa_res = self.ike_sa2.process_message(del_ike_sa_req)
        rekey_child_sa_res = self.ike_sa1.process_message(rekey_child_sa_req)
        self.assertMessageHasNotification(rekey_child_sa_res, self.ike_sa1, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        request_alice = self.ike_sa1.process_message(del_ike_sa_res)
        request_bob = self.ike_sa2.process_message(rekey_child_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertIsNone(request_alice)
        self.assertIsNone(request_bob)

    @patch('xfrm.Xfrm')
    def test_simultaneous_del_ike_sa_del_child(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.delete_ike_sa_at = time.time()
        del_ike_sa_req = self.ike_sa1.check_rekey_ike_sa_timer()
        del_child_sa_req = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi, hard=True)
        del_ike_sa_res = self.ike_sa2.process_message(del_ike_sa_req)
        del_child_sa_res = self.ike_sa1.process_message(del_child_sa_req)
        request_alice = self.ike_sa1.process_message(del_ike_sa_res)
        request_bob = self.ike_sa2.process_message(del_child_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertIsNone(request_alice)
        self.assertIsNone(request_bob)

    @patch('xfrm.Xfrm')
    def test_simultaneous_del_ike_sa_del_ike_sa(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.delete_ike_sa_at = time.time()
        self.ike_sa2.delete_ike_sa_at = time.time()
        del_ike_sa_req_alice = self.ike_sa1.check_rekey_ike_sa_timer()
        del_ike_sa_req_bob = self.ike_sa2.check_rekey_ike_sa_timer()
        del_ike_sa_res_alice = self.ike_sa1.process_message(del_ike_sa_req_bob)
        del_ike_sa_res_bob = self.ike_sa2.process_message(del_ike_sa_req_alice)
        request_alice = self.ike_sa1.process_message(del_ike_sa_res_bob)
        request_bob = self.ike_sa2.process_message(del_ike_sa_res_alice)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertIsNone(request_alice)
        self.assertIsNone(request_bob)

    @patch('xfrm.Xfrm')
    def test_simultaneous_rekey_ike_sa_del_ike_sa(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.rekey_ike_sa_at = time.time()
        self.ike_sa2.delete_ike_sa_at = time.time()
        rekey_ike_sa_req = self.ike_sa1.check_rekey_ike_sa_timer()
        del_ike_sa_req = self.ike_sa2.check_rekey_ike_sa_timer()
        rekey_ike_sa_res = self.ike_sa2.process_message(rekey_ike_sa_req)
        del_ike_sa_res = self.ike_sa1.process_message(del_ike_sa_req)
        self.assertMessageHasNotification(rekey_ike_sa_res, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        request_alice = self.ike_sa1.process_message(rekey_ike_sa_res)
        request_bob = self.ike_sa2.process_message(del_ike_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DELETED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.DELETED)
        self.assertIsNone(request_alice)
        self.assertIsNone(request_bob)

    @patch('xfrm.Xfrm')
    def test_simultaneous_rekey_ike_sa_del_child_sa(self, mockclass):
        self.test_initial_exchanges_transport()
        self.ike_sa1.rekey_ike_sa_at = time.time()
        rekey_ike_sa_req = self.ike_sa1.check_rekey_ike_sa_timer()
        del_child_sa_req = self.ike_sa2.process_expire(self.ike_sa2.child_sas[0].inbound_spi, hard=True)
        rekey_ike_sa_res = self.ike_sa2.process_message(rekey_ike_sa_req)
        del_child_sa_res = self.ike_sa1.process_message(del_child_sa_req)
        self.assertMessageHasNotification(rekey_ike_sa_res, self.ike_sa2, PayloadNOTIFY.Type.TEMPORARY_FAILURE)
        request_alice = self.ike_sa1.process_message(rekey_ike_sa_res)
        request_bob = self.ike_sa2.process_message(del_child_sa_res)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 0)
        self.assertEqual(len(self.ike_sa2.child_sas), 0)
        self.assertIsNone(request_alice)
        self.assertIsNone(request_bob)

    @patch('xfrm.Xfrm')
    def test_queues(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_req_1 = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        create_child_req_2 = self.ike_sa1.process_acquire(small_tsi, small_tsr, 1)
        delete_request = self.ike_sa1.process_expire(self.ike_sa1.child_sas[0].inbound_spi, hard=True)
        self.assertIsNone(create_child_req_2)
        self.assertIsNone(delete_request)
        create_child_res = self.ike_sa2.process_message(create_child_req_1)
        create_child_req_2 = self.ike_sa1.process_message(create_child_res)
        self.assertIsNotNone(create_child_req_2)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.NEW_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)
        create_child_res_2 = self.ike_sa2.process_message(create_child_req_2)
        delete_request = self.ike_sa1.process_message(create_child_res_2)
        self.assertIsNotNone(delete_request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.DEL_CHILD_REQ_SENT)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 3)
        self.assertEqual(len(self.ike_sa2.child_sas), 3)
        delete_res = self.ike_sa2.process_message(delete_request)
        request = self.ike_sa1.process_message(delete_res)
        self.assertIsNone(request)
        self.assertEqual(self.ike_sa1.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(self.ike_sa2.state, IkeSa.State.ESTABLISHED)
        self.assertEqual(len(self.ike_sa1.child_sas), 2)
        self.assertEqual(len(self.ike_sa2.child_sas), 2)

    @patch('xfrm.Xfrm')
    def test_wrong_initiator_flag(self, mockclass):
        self.test_initial_exchanges_transport()
        message = self.ike_sa1.generate_delete_ike_sa_request()
        message.is_initiator = False
        response = self.ike_sa2.process_message(message.to_bytes())
        self.assertIsNone(response)

    @patch('xfrm.Xfrm')
    def test_acquire_from_unknown_policy(self, mockclass):
        self.test_initial_exchanges_transport()
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        create_child_req_1 = self.ike_sa1.process_acquire(small_tsi, small_tsr, 9)
        self.assertIsNone(create_child_req_1)


if __name__ == '__main__':
    unittest.main()
