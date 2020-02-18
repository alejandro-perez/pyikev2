#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the xfrm module
"""
import socket
import subprocess
import unittest
from ipaddress import ip_address

from configuration import Configuration
from message import TrafficSelector, Proposal, Transform
from xfrm import Xfrm, Mode, XfrmAddress

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class TestXfrm(unittest.TestCase):
    def setUp(self):
        Xfrm.flush_policies()
        Xfrm.flush_sas()

    def test_ipv6(self):
        xfrmaddr = XfrmAddress.from_ipaddr(ip_address('2001::0'))
        addr = xfrmaddr.to_ipaddr(socket.AF_INET6)
        self.assertEqual(str(addr), '2001::')

    def test_ipv4(self):
        xfrmaddr = XfrmAddress.from_ipaddr(ip_address('192.168.0.1'))
        addr = xfrmaddr.to_ipaddr(socket.AF_INET)
        self.assertEqual(str(addr), '192.168.0.1')

    def test_create_transport_policy(self):
        conf = Configuration(
            [ip_address('192.168.1.1')],
            {
                "testconn": {
                    "my_addr": '192.168.1.1',
                    "peer_addr": '192.168.2.1',
                    "my_auth": {"id": "alice@openikev2", "psk": "testing"},
                    "peer_auth": {"id": "bob@openikev2", "psk": "testing2"},
                    "protect": [{
                        "index": 1,
                        "ip_proto": "tcp",
                        "mode": "transport",
                        "lifetime": 5,
                        "peer_port": 0,
                        "ipsec_proto": "ah",
                    }]
                },
            })
        Xfrm.create_policies(conf.get_ike_configuration(ip_address('192.168.2.1')))

    def test_create_transport_policy_ipv6(self):
        conf = Configuration(
            [ip_address('2001::1')],
            {
                "testconn": {
                    "my_addr": '2001::1',
                    "peer_addr": '2001::2',
                    "my_auth": {"id": "alice@openikev2", "psk": "testing"},
                    "peer_auth": {"id": "bob@openikev2", "psk": "testing2"},
                    "protect": [{
                        "index": 1,
                        "ip_proto": "tcp",
                        "mode": "transport",
                        "lifetime": 5,
                        "peer_port": 0,
                        "ipsec_proto": "ah",
                    }]
                },
            })
        Xfrm.create_policies(conf.get_ike_configuration(ip_address('2001::2')))

    def test_create_tunnel_policy(self):
        conf = Configuration(
            [ip_address('192.168.1.1')],
            {
                "testconn": {
                    "my_addr": '192.168.1.1',
                    "peer_addr": '192.168.2.1',
                    "my_auth": {"id": "alice@openikev2", "psk": "testing"},
                    "peer_auth": {"id": "bob@openikev2", "psk": "testing2"},
                    "protect": [{
                        "my_subnet": "10.0.0.0/24",
                        "peer_subnet": "10.0.1.0/24",
                        "index": 1,
                        "ip_proto": "tcp",
                        "mode": "tunnel",
                        "lifetime": 5,
                        "peer_port": 0,
                        "ipsec_proto": "ah",
                    }]
                },
            })
        Xfrm.create_policies(conf.get_ike_configuration(ip_address('192.168.2.1')))

    def test_create_tunnel_policy_ipv6(self):
        conf = Configuration(
            [ip_address('2001::1')],
            {
                "testconn": {
                    "my_addr": '2001::1',
                    "peer_addr": '2001::2',
                    "my_auth": {"id": "alice@openikev2", "psk": "testing"},
                    "peer_auth": {"id": "bob@openikev2", "psk": "testing2"},
                    "protect": [{
                        "my_subnet": "2008::/64",
                        "peer_subnet": "2009::/64",
                        "index": 1,
                        "ip_proto": "tcp",
                        "mode": "tunnel",
                        "lifetime": 5,
                        "peer_port": 0,
                        "ipsec_proto": "ah",
                    }]
                },
            })
        Xfrm.create_policies(conf.get_ike_configuration(ip_address('2001::2')))

    def test_create_transport_ipsec_sa(self):
        Xfrm.create_sa(ip_address('192.168.1.1'), ip_address('192.168.1.2'),
                       TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                       TrafficSelector.IpProtocol.TCP, 0, 0,
                                       ip_address('192.168.1.1'),
                                       ip_address('192.168.1.1')),
                       TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                       TrafficSelector.IpProtocol.TCP, 0, 0,
                                       ip_address('192.168.1.2'),
                                       ip_address('192.168.1.2')),
                       Proposal.Protocol.ESP, b'1234',
                       Transform.EncrId.ENCR_AES_CBC, b'1' * 16,
                       Transform.IntegId.AUTH_HMAC_MD5_96, b'1' * 16, Mode.TRANSPORT)

    def test_create_tunnel_ipsec_sa(self):
        Xfrm.create_sa(ip_address('192.168.1.1'), ip_address('192.168.1.2'),
                       TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                       TrafficSelector.IpProtocol.TCP, 0, 0,
                                       ip_address('192.168.1.1'),
                                       ip_address('192.168.1.1')),
                       TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                       TrafficSelector.IpProtocol.TCP, 0, 0,
                                       ip_address('192.168.1.2'),
                                       ip_address('192.168.1.2')),
                       Proposal.Protocol.ESP, b'1234',
                       Transform.EncrId.ENCR_AES_CBC, b'1' * 16,
                       Transform.IntegId.AUTH_HMAC_MD5_96, b'1' * 16, Mode.TUNNEL)
    def test_delete_ipsec_sa(self):
        self.test_create_tunnel_ipsec_sa()
        Xfrm.delete_sa(ip_address('192.168.1.2'), Proposal.Protocol.ESP, b'1234')

    def tearDown(self):
        subprocess.call('ip xfrm policy', shell=True)
        subprocess.call('ip xfrm state', shell=True)
        Xfrm.flush_policies()
        Xfrm.flush_sas()


if __name__ == '__main__':
    unittest.main()
