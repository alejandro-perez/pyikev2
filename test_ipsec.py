#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the IPsec module
"""
import unittest
import ipsec
from protocol import Policy
from message import TrafficSelector, Proposal
import subprocess

class TestIpsec(unittest.TestCase):
    def setUp(self):
        subprocess.call(['ip', 'xfrm', 'policy', 'flush'])

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
        print(text_pol)
        self.assertEqual(
            text_pol,
            b'src 10.0.0.0/8 dst 192.168.1.0/24 proto tcp sport 80 \n\tdir in '
            b'priority 0 \n\ttmpl src 155.54.1.2 dst 155.54.1.1\n\t\tproto ah '
            b'reqid 0 mode tunnel\nsrc 192.168.1.0/24 dst 10.0.0.0/8 proto tcp'
            b' dport 80 \n\tdir out priority 0 \n\ttmpl src 155.54.1.1 dst 155'
            b'.54.1.2\n\t\tproto ah reqid 0 mode tunnel\n')

    def tearDown(self):
        subprocess.call(['ip', 'xfrm', 'policy', 'flush'])

if __name__ == '__main__':
    unittest.main()
