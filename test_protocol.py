#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for protocol messages.
"""

__author__ = 'Alejandro Perez <alex@um.es>'

import logging
from ipaddress import ip_address, ip_network
from unittest import TestCase
from unittest.mock import patch

from configuration import Configuration
from message import TrafficSelector, Transform
from protocol import IkeSa, Acquire

logging.indent = 2
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-6s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


class TestIkeSa(TestCase):
    @patch('xfrm.Xfrm')
    def setUp(self, MockClass1):
        self.configuration1 = Configuration(
            ip_address("192.168.0.1"),
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
            ip_address("192.168.0.2"),
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
                        configuration=self.configuration1.get_ike_configuration(ip_address("192.168.0.2")),
                        my_addr=ip_address("192.168.0.1"), peer_addr=ip_address("192.168.0.2"))
        self.ike_sa2 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi,
                        configuration=self.configuration2.get_ike_configuration(ip_address("192.168.0.1")),
                        my_addr=ip_address("192.168.0.2"), peer_addr=ip_address("192.168.0.1"))

    @patch('xfrm.Xfrm')
    def test_ok_transport(self, MockClass1):
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        msg_data = self.ike_sa1.process_acquire(acquire)
        msg_data = self.ike_sa2.process_message(msg_data, None)
        msg_data = self.ike_sa1.process_message(msg_data, None)
        msg_data = self.ike_sa2.process_message(msg_data, None)
        self.assertIsNone(self.ike_sa1.process_message(msg_data, None))

    @patch('xfrm.Xfrm')
    def test_ike_sa_init_no_proposal_chosen(self, MockClass1):
        self.ike_sa1.configuration['dh'][0].id = Transform.DhId.DH_1
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        msg_data = self.ike_sa1.process_acquire(acquire)
        msg_data = self.ike_sa2.process_message(msg_data, None)
        self.assertIsNone(self.ike_sa1.process_message(msg_data, None))

    @patch('xfrm.Xfrm')
    def test_ike_sa_init_invalid_ke(self, MockClass1):
        self.ike_sa1.configuration['dh'].insert(0, Transform(Transform.Type.DH, Transform.DhId.DH_1))
        small_tsi = TrafficSelector.from_network(ip_network("192.168.0.1/32"), 8765, TrafficSelector.IpProtocol.TCP)
        small_tsr = TrafficSelector.from_network(ip_network("192.168.0.2/32"), 23, TrafficSelector.IpProtocol.TCP)
        acquire = Acquire(small_tsi, small_tsr, 1)
        msg_data = self.ike_sa1.process_acquire(acquire)
        msg_data = self.ike_sa2.process_message(msg_data, None)
        msg_data = self.ike_sa1.process_message(msg_data, None)

        ike_sa3 = IkeSa(is_initiator=False, peer_spi=self.ike_sa1.my_spi,
                        configuration=self.configuration2.get_ike_configuration(ip_address("192.168.0.1")),
                        my_addr=ip_address("192.168.0.2"), peer_addr=ip_address("192.168.0.1"))
        msg_data = ike_sa3.process_message(msg_data, None)
