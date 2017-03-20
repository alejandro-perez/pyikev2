#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the IPsec module
"""
import unittest
import ipsec
from message import TrafficSelector, Proposal
import subprocess
from crypto import Cipher, Integrity

class TestIpsec(unittest.TestCase):
    def setUp(self):
        ipsec.flush_policies()
        ipsec.flush_ipsec_sa()

    def test_create_transport_policy(self):
        policy = Policy('192.168.1.0/24', 0, '10.0.0.0/8', 80,
            TrafficSelector.IpProtocol.TCP, Proposal.Protocol.AH,
            Policy.Mode.TRANSPORT)
        ipsec.create_policy(policy)
        text_pol = subprocess.check_output(['ip', 'xfrm', 'policy'])
        self.assertEqual(
            text_pol,
            b'src 10.0.0.0/8 dst 192.168.1.0/24 proto tcp sport 80 \n\tdir in '
            b'priority 0 \n\ttmpl src 0.0.0.0 dst 0.0.0.0\n\t\tproto ah reqid '
            b'0 mode transport\nsrc 192.168.1.0/24 dst 10.0.0.0/8 proto tcp dp'
            b'ort 80 \n\tdir out priority 0 \n\ttmpl src 0.0.0.0 dst 0.0.0.0\n'
            b'\t\tproto ah reqid 0 mode transport\n')

    def test_create_tunnel_policy(self):
        policy = Policy('192.168.1.0/24', 0, '10.0.0.0/8', 80,
            TrafficSelector.IpProtocol.TCP, Proposal.Protocol.AH,
            Policy.Mode.TUNNEL, '155.54.1.1', '155.54.1.2')
        ipsec.create_policy(policy)
        text_pol = subprocess.check_output(['ip', 'xfrm', 'policy'])
        self.assertEqual(
            text_pol,
            b'src 10.0.0.0/8 dst 192.168.1.0/24 proto tcp sport 80 \n\tdir in '
            b'priority 0 \n\ttmpl src 155.54.1.2 dst 155.54.1.1\n\t\tproto ah '
            b'reqid 0 mode tunnel\nsrc 192.168.1.0/24 dst 10.0.0.0/8 proto tcp'
            b' dport 80 \n\tdir out priority 0 \n\ttmpl src 155.54.1.1 dst 155'
            b'.54.1.2\n\t\tproto ah reqid 0 mode tunnel\n')

    def test_create_transport_ipsec_sa(self):
        ipsec.create_child_sa('192.168.1.1', '192.168.1.2', Proposal.Protocol.ESP,
            b'1234', Cipher.Id.ENCR_AES_CBC, b'1'*16, Integrity.Id.AUTH_HMAC_MD5_96,
            b'1'*16, Policy.Mode.TRANSPORT)
        text_state = subprocess.check_output(['ip', 'xfrm', 'state'])
        self.assertEqual(
            text_state,
            b'src 192.168.1.1 dst 192.168.1.2\n\tproto esp spi 0x31323334 '
            b'reqid 0 mode transport\n\treplay-window 0 \n\tauth-trunc '
            b'hmac(md5) 0x31313131313131313131313131313131 96\n\tenc cbc(aes) '
            b'0x31313131313131313131313131313131\n\tanti-replay context: seq '
            b'0x0, oseq 0x0, bitmap 0x00000000\n\tsel src 0.0.0.0/0 dst '
            b'0.0.0.0/0 \n')

    def test_create_tunnel_ipsec_sa(self):
        ipsec.create_child_sa('192.168.1.1', '192.168.1.3', Proposal.Protocol.ESP,
            b'1234', Cipher.Id.ENCR_AES_CBC, b'1'*16, Integrity.Id.AUTH_HMAC_MD5_96,
            b'1'*16, ipsec.Mode.TUNNEL)
        text_state = subprocess.check_output(['ip', 'xfrm', 'state'])
        self.assertEqual(
            text_state,
            b'src 192.168.1.1 dst 192.168.1.3\n\tproto esp spi 0x31323334 '
            b'reqid 0 mode tunnel\n\treplay-window 0 \n\tauth-trunc hmac(md5) '
            b'0x31313131313131313131313131313131 96\n\tenc cbc(aes) '
            b'0x31313131313131313131313131313131\n\tanti-replay context: seq '
            b'0x0, oseq 0x0, bitmap 0x00000000\n\tsel src 0.0.0.0/0 dst '
            b'0.0.0.0/0 \n')

    def tearDown(self):
        ipsec.flush_policies()
        ipsec.flush_ipsec_sa()

if __name__ == '__main__':
    unittest.main()
