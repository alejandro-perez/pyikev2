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

from configuration import Configuration
from message import TrafficSelector, Message, PayloadNOTIFY
from protocol import IkeSaController
from xfrm import XfrmUserAcquire, XfrmId, XfrmAddress, XfrmSelector, XfrmUserPolicyInfo, XfrmUserExpire, \
    XfrmUserSaInfo, create_byte_array

logging.indent = 2
logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


class TestIkeSaController(TestCase):
    @patch('xfrm.Xfrm')
    def setUp(self, mockclass):
        self.ip1 = ip_address("192.168.0.1")
        self.ip2 = ip_address("192.168.0.2")
        self.addr1 = (self.ip1, 500)
        self.addr2 = (self.ip2, 500)
        self.configuration1 = Configuration(
            self.ip1,
            {
                "192.168.0.2": {
                    "id": "alice@openikev2",
                    "psk": "testing",
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
                }
            })
        self.configuration2 = Configuration(
            self.ip2,
            {
                "192.168.0.1": {
                    "id": "bob@openikev2",
                    "psk": "testing",
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
            })
        self.ikesacontroller1 = IkeSaController(my_addr=self.ip1, configuration=self.configuration1)
        self.ikesacontroller2 = IkeSaController(my_addr=self.ip2, configuration=self.configuration2)

    @patch('xfrm.Xfrm')
    def test_initial_exchanges(self, mockclass):
        # initial exchanges
        acquire = XfrmUserAcquire(id=XfrmId(daddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.2"))),
                                  saddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.1")),
                                  sel=XfrmSelector(saddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.1")),
                                                   sport=8765,
                                                   daddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.2")),
                                                   dport=23,
                                                   proto=TrafficSelector.IpProtocol.TCP),
                                  policy=XfrmUserPolicyInfo(index=1 << 3))
        ike_sa_init_req, peer_addr = self.ikesacontroller1.process_acquire(acquire)
        ike_sa_init_res = self.ikesacontroller2.dispatch_message(ike_sa_init_req, self.addr2, self.addr1)
        ike_auth_req = self.ikesacontroller1.dispatch_message(ike_sa_init_res, self.addr1, self.addr2)
        ike_auth_res = self.ikesacontroller2.dispatch_message(ike_auth_req, self.addr2, self.addr1)
        request = self.ikesacontroller1.dispatch_message(ike_auth_res, self.addr1, self.addr2)
        self.assertEqual(len(self.ikesacontroller1.ike_sas), 1)
        self.assertEqual(len(self.ikesacontroller1.ike_sas), 1)
        self.assertIsNone(request)

    @patch('xfrm.Xfrm')
    def test_expire(self, mockclass):
        # initial exchanges
        self.test_initial_exchanges()

        expire = XfrmUserExpire(
            state=XfrmUserSaInfo(
                id=XfrmId(spi=create_byte_array(self.ikesacontroller1.ike_sas[0].child_sas[0].inbound_spi))),
            hard=False)
        rekey_child_sa_req, peer_addr = self.ikesacontroller1.process_expire(expire)
        self.assertIsNotNone(rekey_child_sa_req)

    @patch('xfrm.Xfrm')
    def test_expire_invalid_spi(self, mockclass):
        # initial exchanges
        self.test_initial_exchanges()

        expire = XfrmUserExpire(
            state=XfrmUserSaInfo(
                id=XfrmId(spi=create_byte_array(b'1234'))),
            hard=False)
        rekey_child_sa_req, peer_addr = self.ikesacontroller1.process_expire(expire)
        self.assertIsNone(rekey_child_sa_req)

    @patch('xfrm.Xfrm')
    def test_invalid_spi(self, mockclass):
        # initial exchanges
        self.test_initial_exchanges()

        expire = XfrmUserExpire(
            state=XfrmUserSaInfo(
                id=XfrmId(spi=create_byte_array(self.ikesacontroller1.ike_sas[0].child_sas[0].inbound_spi))),
            hard=False)
        rekey_child_sa_req, peer_addr = self.ikesacontroller1.process_expire(expire)
        message = Message.parse(rekey_child_sa_req, crypto=self.ikesacontroller1.ike_sas[0].my_crypto)
        message.spi_r = b'12345678'
        rekey_child_sa_req = message.to_bytes()
        response = self.ikesacontroller2.dispatch_message(rekey_child_sa_req, self.addr2, self.addr1)
        self.assertIsNone(response)

    @patch('xfrm.Xfrm')
    def test_ike_sa_rekey(self, mockclass):
        self.test_initial_exchanges()
        self.ikesacontroller1.ike_sas[0].rekey_ike_sa_at = time.time()
        rekey_req = self.ikesacontroller1.ike_sas[0].check_rekey_ike_sa_timer()
        rekey_res = self.ikesacontroller2.dispatch_message(rekey_req, self.addr2, self.addr1)
        delete_req = self.ikesacontroller1.dispatch_message(rekey_res, self.addr1, self.addr2)
        self.assertEqual(len(self.ikesacontroller1.ike_sas), 2)
        self.assertEqual(len(self.ikesacontroller2.ike_sas), 2)
        delete_res = self.ikesacontroller2.dispatch_message(delete_req, self.addr2, self.addr1)
        request = self.ikesacontroller1.dispatch_message(delete_res, self.addr1, self.addr2)
        self.assertEqual(len(self.ikesacontroller1.ike_sas), 1)
        self.assertEqual(len(self.ikesacontroller2.ike_sas), 1)

    @patch('xfrm.Xfrm')
    def test_cookie(self, mockclass):
        # initial exchanges
        self.ikesacontroller2.cookie_threshold = 0
        acquire = XfrmUserAcquire(id=XfrmId(daddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.2"))),
                                  saddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.1")),
                                  sel=XfrmSelector(saddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.1")),
                                                   sport=8765,
                                                   daddr=XfrmAddress.from_ipaddr(ip_address("192.168.0.2")),
                                                   dport=23,
                                                   proto=TrafficSelector.IpProtocol.TCP),
                                  policy=XfrmUserPolicyInfo(index=1 << 3))
        ike_sa_init_req, peer_addr = self.ikesacontroller1.process_acquire(acquire)
        ike_sa_init_res = self.ikesacontroller2.dispatch_message(ike_sa_init_req, self.addr2, self.addr1)
        message = Message.parse(ike_sa_init_res)
        self.assertTrue(message.get_notifies(PayloadNOTIFY.Type.COOKIE))


if __name__ == '__main__':
    unittest.main()
