#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the IPsec module
"""
import unittest
import ipsec
from message import TrafficSelector, Proposal
import subprocess
from crypto import Cipher, Integrity
from ipaddress import ip_address, ip_network

class TestIpsec(unittest.TestCase):
    def setUp(self):
        ipsec.flush_policies()
        ipsec.flush_sas()

    def test_create_transport_policy(self):
        ike_conf = {
            'protect': [
                {
                    # 'my_subnet': ip_network('192.168.1.0/24'),
                    # 'peer_subnet': ip_network('10.0.0.0/8'),
                    'my_port': 0,
                    'peer_port': 80,
                    'ip_proto': TrafficSelector.IpProtocol.TCP,
                    'ipsec_proto': Proposal.Protocol.AH,
                    'mode': ipsec.Mode.TRANSPORT
                }
            ]
        }
        ipsec.create_policies(ip_address('192.168.1.1'),
                              ip_address('192.168.1.2'),
                              ike_conf)

        text_pol = subprocess.check_output(['ip', 'xfrm', 'policy'])
        self.assertEqual(
            text_pol,
            b'src 192.168.1.2/32 dst 192.168.1.1/32 proto tcp sport 80 \n\tdir'
            b' fwd priority 0 \n\ttmpl src 192.168.1.2 dst 192.168.1.1\n\t\tpr'
            b'oto ah reqid 0 mode transport\nsrc 192.168.1.2/32 dst 192.168.1.'
            b'1/32 proto tcp sport 80 \n\tdir in priority 0 \n\ttmpl src 192.1'
            b'68.1.2 dst 192.168.1.1\n\t\tproto ah reqid 0 mode transport\nsrc'
            b' 192.168.1.1/32 dst 192.168.1.2/32 proto tcp dport 80 \n\tdir ou'
            b't priority 0 \n\ttmpl src 192.168.1.1 dst 192.168.1.2\n\t\tproto'
            b' ah reqid 0 mode transport\n')

    def test_create_tunnel_policy(self):
        ike_conf = {
            'protect': [
                {
                    'my_subnet': ip_network('192.168.1.0/24'),
                    'peer_subnet': ip_network('10.0.0.0/8'),
                    'my_port': 0,
                    'peer_port': 80,
                    'ip_proto': TrafficSelector.IpProtocol.TCP,
                    'ipsec_proto': Proposal.Protocol.AH,
                    'mode': ipsec.Mode.TUNNEL
                }
            ]
        }
        ipsec.create_policies(ip_address('192.168.1.1'),
                              ip_address('192.168.1.2'),
                              ike_conf)
        text_pol = subprocess.check_output(['ip', 'xfrm', 'policy'])
        self.assertEqual(
            text_pol,
            b'src 10.0.0.0/8 dst 192.168.1.0/24 proto tcp sport 80 \n\tdir fwd'
            b' priority 0 \n\ttmpl src 192.168.1.2 dst 192.168.1.1\n\t\tproto '
            b'ah reqid 0 mode tunnel\nsrc 10.0.0.0/8 dst 192.168.1.0/24 proto '
            b'tcp sport 80 \n\tdir in priority 0 \n\ttmpl src 192.168.1.2 dst '
            b'192.168.1.1\n\t\tproto ah reqid 0 mode tunnel\nsrc 192.168.1.0/2'
            b'4 dst 10.0.0.0/8 proto tcp dport 80 \n\tdir out priority 0 \n\tt'
            b'mpl src 192.168.1.1 dst 192.168.1.2\n\t\tproto ah reqid 0 mode t'
            b'unnel\n')

    def test_create_transport_ipsec_sa(self):
        ipsec.create_sa(ip_address('192.168.1.1'), ip_address('192.168.1.2'),
                        TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                        TrafficSelector.IpProtocol.TCP, 0, 0,
                                        ip_address('192.168.1.1'),
                                        ip_address('192.168.1.1')),
                        TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                        TrafficSelector.IpProtocol.TCP, 0, 0,
                                        ip_address('192.168.1.2'),
                                        ip_address('192.168.1.2')),
                        Proposal.Protocol.ESP, b'1234', Cipher.Id.ENCR_AES_CBC,
                        b'1'*16, Integrity.Id.AUTH_HMAC_MD5_96, b'1'*16,
                        ipsec.Mode.TRANSPORT)
        # text_state = subprocess.check_output(['ip', 'xfrm', 'state'])
        # self.assertEqual(
        #     text_state,
        #     b'src 192.168.1.1 dst 192.168.1.2\n\tproto esp spi 0x31323334 '
        #     b'reqid 0 mode transport\n\treplay-window 0 \n\tauth-trunc '
        #     b'hmac(md5) 0x31313131313131313131313131313131 96\n\tenc cbc(aes) '
        #     b'0x31313131313131313131313131313131\n\tanti-replay context: seq '
        #     b'0x0, oseq 0x0, bitmap 0x00000000\n\tsel src 0.0.0.0/0 dst '
        #     b'0.0.0.0/0 \n')

    def test_create_tunnel_ipsec_sa(self):
        ipsec.create_sa(ip_address('192.168.1.1'), ip_address('192.168.1.2'),
                        TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                        TrafficSelector.IpProtocol.TCP, 0, 0,
                                        ip_address('192.168.1.1'),
                                        ip_address('192.168.1.1')),
                        TrafficSelector(TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
                                        TrafficSelector.IpProtocol.TCP, 0, 0,
                                        ip_address('192.168.1.2'),
                                        ip_address('192.168.1.2')),
                        Proposal.Protocol.ESP, b'1234', Cipher.Id.ENCR_AES_CBC,
                        b'1'*16, Integrity.Id.AUTH_HMAC_MD5_96, b'1'*16,
                        ipsec.Mode.TUNNEL)
        # text_state = subprocess.check_output(['ip', 'xfrm', 'state'])
        # self.assertEqual(
        #     text_state,
        #     b'src 192.168.1.1 dst 192.168.1.3\n\tproto esp spi 0x31323334 '
        #     b'reqid 0 mode tunnel\n\treplay-window 0 \n\tauth-trunc hmac(md5) '
        #     b'0x31313131313131313131313131313131 96\n\tenc cbc(aes) '
        #     b'0x31313131313131313131313131313131\n\tanti-replay context: seq '
        #     b'0x0, oseq 0x0, bitmap 0x00000000\n\tsel src 0.0.0.0/0 dst '
        #     b'0.0.0.0/0 \n')

    def tearDown(self):
        ipsec.flush_policies()
        ipsec.flush_sas()

if __name__ == '__main__':
    unittest.main()
