#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for protocol messages.
"""
__author__ = 'Alejandro Perez <alex@um.es>'

import unittest
from protocol import Policy
from message import Proposal, TrafficSelector
import json

class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.policy_transport = Policy('192.168.1.0/24', 0, '10.0.0.0/8', 80,
            TrafficSelector.IpProtocol.TCP, Proposal.Protocol.AH,
            Policy.Mode.TRANSPORT)

        self.policy_tunnel = Policy('192.168.1.0/24', 0, '10.0.0.0/8', 80,
            TrafficSelector.IpProtocol.TCP, Proposal.Protocol.AH,
            Policy.Mode.TUNNEL, '100.0.0.1', '100.0.0.2')

    def test_to_dict(self):
        d = self.policy_transport.to_dict()
        self.policy_tunnel.to_dict()
        print(json.dumps(d, indent=2))

    def test_get_tsi(self):
        tsi = self.policy_transport.get_tsi()
        tsr = self.policy_transport.get_tsr()

if __name__ == '__main__':
    unittest.main()
