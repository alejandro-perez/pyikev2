#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test configuration system
"""
__author__ = 'Alejandro Perez <alex@um.es>'

import unittest
from ipaddress import ip_network, ip_address
from configuration import (
    Configuration, ConfigurationError, ConfigurationNotFound)

class TestConfiguration(unittest.TestCase):
    def test_empty(self):
        conf = Configuration({})

    def test_no_ip(self):
        with self.assertRaises(ConfigurationError):
            conf = Configuration({'a': {}})

    def test_ip(self):
        conf = Configuration({
            '192.168.1.1': {
                'psk': 'aa',
                'email': 'alex@um.es'
            }
        })

    def test_valid(self):
        conf = Configuration({
            '192.168.1.1': {
                'psk': 'aa',
                'email': 'alex@um.es',
                'encr': ['aes128'],
            }
        })

    def test_found(self):
        conf = Configuration({
            '192.168.1.5': {
                'psk': 'aa',
                'email': 'alex@um.es'
            }
        })
        ike_conf = conf.get_ike_configuration('192.168.1.5')

    def test_not_found(self):
        conf = Configuration({
            '192.168.1.5': {
                'psk': 'aa',
                'email': 'alex@um.es'
            }
        })
        with self.assertRaises(ConfigurationNotFound):
            ike_conf = conf.get_ike_configuration('192.168.2.5')

    def test_invalid_dh(self):
        with self.assertRaises(ConfigurationError):
            conf = Configuration({
                '192.168.1.1': {
                    'psk': 'aa',
                    'email': 'alex@um.es',
                    'encr': ['aes128'],
                    'dh': ['dh1', 'dh2', 'dh3']
                }
            })

if __name__ == '__main__':
    unittest.main()
