#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the xfrm module
"""
import socket
import subprocess
import unittest
from ipaddress import ip_address, ip_network

from xfrm import Xfrm, Mode, XfrmAddress, XFRM_POLICY_OUT, XFRM_MODE_TRANSPORT, XFRM_MODE_TUNNEL

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
        Xfrm.create_policy(ip_network('192.168.1.1/32'), ip_network('192.168.2.1/32'), 0, 0, socket.IPPROTO_TCP,
                           XFRM_POLICY_OUT, socket.IPPROTO_AH, XFRM_MODE_TRANSPORT, ip_address('192.168.1.1'),
                           ip_address('192.168.1.2'), index=1)

    def test_create_transport_policy_ipv6(self):
        Xfrm.create_policy(ip_network('2001::1/128'), ip_network('2001::2/128'), 0, 0, socket.IPPROTO_TCP,
                           XFRM_POLICY_OUT, socket.IPPROTO_AH, XFRM_MODE_TRANSPORT, ip_address('2001::1'),
                           ip_address('2001::2'), index=1)

    def test_create_tunnel_policy(self):
        Xfrm.create_policy(ip_network('10.0.0.0/24'), ip_network('10.0.1.0/24'), 0, 0, socket.IPPROTO_TCP,
                           XFRM_POLICY_OUT, socket.IPPROTO_AH, XFRM_MODE_TUNNEL, ip_address('192.168.1.1'),
                           ip_address('192.168.1.2'), index=1)

    def test_create_tunnel_policy_ipv6(self):
        Xfrm.create_policy(ip_network('2009::0/64'), ip_network('2009::0/64'), 0, 0, socket.IPPROTO_TCP,
                           XFRM_POLICY_OUT, socket.IPPROTO_AH, XFRM_MODE_TRANSPORT, ip_address('2001::1'),
                           ip_address('2001::2'), index=1)

    def test_create_transport_ipsec_sa(self):
        Xfrm.create_sa(ip_network('192.168.1.1/32'), ip_network('192.168.1.2/32'), 0, 0, b'1234', socket.IPPROTO_TCP,
                       socket.IPPROTO_ESP, Mode.TRANSPORT, ip_address('192.168.1.1'), ip_address('192.168.1.2'),
                       b'cbc(aes)', b'1' * 16, b'hmac(md5)', b'1' * 16)

    def test_create_tunnel_ipsec_sa(self):
        Xfrm.create_sa(ip_network('192.168.1.1/32'), ip_network('192.168.1.2/32'), 0, 0, b'1234', socket.IPPROTO_TCP,
                       socket.IPPROTO_ESP, Mode.TUNNEL, ip_address('192.168.1.1'), ip_address('192.168.1.2'),
                       b'cbc(aes)', b'1' * 16, b'hmac(md5)', b'1' * 16)

    def test_delete_ipsec_sa(self):
        self.test_create_tunnel_ipsec_sa()
        Xfrm.delete_sa(ip_address('192.168.1.2'), socket.IPPROTO_ESP, b'1234')

    def tearDown(self):
        subprocess.call('ip xfrm policy', shell=True)
        subprocess.call('ip xfrm state', shell=True)
        Xfrm.flush_policies()
        Xfrm.flush_sas()


if __name__ == '__main__':
    unittest.main()
