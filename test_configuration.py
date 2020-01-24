#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test configuration system
"""
import unittest
from ipaddress import ip_address

from configuration import (
    Configuration, ConfigurationError, ConfigurationNotFound)

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class TestConfiguration(unittest.TestCase):
    def setUp(self):
        self.my_addr = ip_address('192.168.1.1')

    def test_empty(self):
        Configuration({})

    def test_no_ip(self):
        with self.assertRaises(ConfigurationError):
            Configuration({'a': {}})

    def test_valid(self):
        return Configuration({
            'testconn': {
                'my_addr': '192.168.1.1',
                'peer_addr': '192.168.1.2',
                'my_auth': {
                    'psk': 'aa',
                    'id': 'alex@um.es',
                },
                'peer_auth': {
                    'psk': 'aa',
                    'id': 'alex@um.es',
                },
                'encr': ['aes128'],
                'protect': [{
                    'src_selector': '192.168.1.1'
                }]
            }
        })

    def test_found(self):
        conf = self.test_valid()
        conf.get_ike_configuration(ip_address('192.168.1.2'))

    def test_not_found(self):
        conf = self.test_valid()
        with self.assertRaises(ConfigurationNotFound):
            conf.get_ike_configuration('192.168.2.5')

    def test_invalid_dh(self):
        with self.assertRaises(ConfigurationError):
            Configuration({
                'testconn': {
                    'my_addr': '192.168.1.1',
                    'peer_addr': '192.168.1.2',
                    'my_auth': {
                        'psk': 'aa',
                        'id': 'alex@um.es',
                    },
                    'peer_auth': {
                        'psk': 'aa',
                        'id': 'alex@um.es',
                    },
                    'dh': [90],
                    'protect': [{
                        'src_selector': '192.168.1.1'
                    }]
                }
            })


if __name__ == '__main__':
    unittest.main()
