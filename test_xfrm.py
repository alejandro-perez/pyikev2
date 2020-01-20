#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the xfrm module
"""
import socket
import unittest
from ipaddress import ip_address, ip_network

from configuration import IkeConfiguration, IpsecConfiguration
from xfrm import Xfrm, Mode, XfrmAddress
from message import TrafficSelector, Proposal, Transform

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class TestXfrm(unittest.TestCase):
    def setUp(self):
        self.xfrm = Xfrm()
        self.xfrm.flush_policies()
        self.xfrm.flush_sas()

    def test_ipv6(self):
        xfrmaddr = XfrmAddress.from_ipaddr(ip_address('2001::0'))
        addr = xfrmaddr.to_ipaddr(socket.AF_INET6)
        self.assertEqual(str(addr), '2001::')

    def test_ipv4(self):
        xfrmaddr = XfrmAddress.from_ipaddr(ip_address('192.168.0.1'))
        addr = xfrmaddr.to_ipaddr(socket.AF_INET)
        self.assertEqual(str(addr), '192.168.0.1')

    def test_create_transport_policy(self):
        ipsec_conf = IpsecConfiguration(my_port=0, peer_port=80, ip_proto=TrafficSelector.IpProtocol.TCP,
                                        ipsec_proto=Proposal.Protocol.AH, mode=Mode.TRANSPORT, index=0)
        ike_conf = IkeConfiguration(protect=[ipsec_conf])
        self.xfrm.create_policies(ip_address('192.168.1.1'), ip_address('192.168.1.2'), ike_conf)

    def test_create_transport_policy_ipv6(self):
        ipsec_conf = IpsecConfiguration(my_port=0, peer_port=80, ip_proto=TrafficSelector.IpProtocol.TCP,
                                        ipsec_proto=Proposal.Protocol.AH, mode=Mode.TRANSPORT, index=0)
        ike_conf = IkeConfiguration(protect=[ipsec_conf])
        self.xfrm.create_policies(ip_address('2001::1'), ip_address('2001::2'), ike_conf)

    def test_create_tunnel_policy(self):
        ipsec_conf = IpsecConfiguration(my_subnet=ip_network('192.168.1.0/24'), peer_subnet=ip_network('10.0.0.0/8'),
                                        my_port=0, peer_port=80, ip_proto=TrafficSelector.IpProtocol.TCP,
                                        ipsec_proto=Proposal.Protocol.AH, mode=Mode.TUNNEL, index=1)
        ike_conf = IkeConfiguration(protect=[ipsec_conf])
        self.xfrm.create_policies(ip_address('192.168.1.1'), ip_address('192.168.1.2'), ike_conf)

    def test_create_tunnel_policy_ipv6(self):
        ipsec_conf = IpsecConfiguration(my_subnet=ip_network('2002::0/64'), peer_subnet=ip_network('2003::0/64'),
                                        my_port=0, peer_port=80, ip_proto=TrafficSelector.IpProtocol.TCP,
                                        ipsec_proto=Proposal.Protocol.AH, mode=Mode.TUNNEL, index=1)
        ike_conf = IkeConfiguration(protect=[ipsec_conf])
        self.xfrm.create_policies(ip_address('2001::1'), ip_address('2001::2'), ike_conf)

    def test_create_transport_ipsec_sa(self):
        self.xfrm.create_sa(ip_address('192.168.1.1'), ip_address('192.168.1.2'),
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
        self.xfrm.create_sa(ip_address('192.168.1.1'), ip_address('192.168.1.2'),
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
        self.xfrm.delete_sa(ip_address('192.168.1.2'), Proposal.Protocol.ESP, b'1234')

    def test_get_policies(self):
        self.test_create_transport_policy()
        policies = self.xfrm._get_policies()
        for header, payload, attributes in policies:
            payload.to_dict()

    def tearDown(self):
        self.xfrm.flush_policies()
        self.xfrm.flush_sas()


if __name__ == '__main__':
    unittest.main()
