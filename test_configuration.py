#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test configuration system
"""
import unittest
from ipaddress import ip_address

from configuration import (
    Configuration, ConfigurationError, ConfigurationNotFound)

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'

from message import PayloadID


class TestConfiguration(unittest.TestCase):
    def setUp(self):
        self.my_addrs = [ip_address('192.168.1.1')]
        self.confdict = {
            'testconn': {
                'my_addr': '192.168.1.1',
                'peer_addr': '192.168.1.2',
                'my_auth': {'psk': 'aa',
                            'id': 'alex@um.es'},
                'peer_auth': {'psk': 'aa',
                              'id': 'alex@um.es'},
                'encr': ['aes128'],
                'protect': [{'my_subnet': '192.168.1.1'}]
            }}

    def test_empty(self):
        Configuration(self.my_addrs, {})

    def test_missing_data(self):
        with self.assertRaises(ConfigurationError):
            Configuration(self.my_addrs, {'a': {}})

    def test_invalid_ip_address(self):
        self.confdict['testconn']['my_addr'] = '192.168.10.1.12'
        with self.assertRaises(ConfigurationError):
            Configuration(self.my_addrs, self.confdict)

    def test_hostname(self):
        self.confdict['testconn']['peer_addr'] = 'www.google.es'
        Configuration(self.my_addrs, self.confdict)

    def test_valid(self):
        return Configuration(self.my_addrs, self.confdict)

    def test_invalid_my_addr(self):
        self.confdict['testconn']['my_addr'] = '192.168.10.1'
        with self.assertRaises(ConfigurationError):
            Configuration(self.my_addrs, self.confdict)

    def test_invalid_network(self):
        self.confdict['testconn']['protect'][0]['my_subnet'] = 'whatever'
        with self.assertRaises(ConfigurationError):
            Configuration(self.my_addrs, self.confdict)

    def test_found(self):
        conf = Configuration(self.my_addrs, self.confdict)
        conf.get_ike_configuration(ip_address('192.168.1.2'))

    def test_not_found(self):
        conf = Configuration(self.my_addrs, self.confdict)
        with self.assertRaises(ConfigurationNotFound):
            conf.get_ike_configuration('192.168.2.5')

    def test_id_type(self):
        conf = Configuration(self.my_addrs, self.confdict)
        self.confdict['testconn']['peer_auth']['id'] = 'test.org'
        conf = Configuration(self.my_addrs, self.confdict)
        self.assertEqual(conf.ike_configurations[0].my_auth.id.id_type, PayloadID.Type.ID_RFC822_ADDR)
        self.assertEqual(conf.ike_configurations[0].peer_auth.id.id_type, PayloadID.Type.ID_FQDN)

        self.confdict['testconn']['my_auth']['id'] = '192.168.1.1'
        self.confdict['testconn']['peer_auth']['id'] = '2001::1'
        conf = Configuration(self.my_addrs, self.confdict)

        self.assertEqual(conf.ike_configurations[0].my_auth.id.id_type, PayloadID.Type.ID_IPV4_ADDR)
        self.assertEqual(conf.ike_configurations[0].peer_auth.id.id_type, PayloadID.Type.ID_IPV6_ADDR)

    def test_invalid_dh(self):
        with self.assertRaises(ConfigurationError):
            Configuration(self.my_addrs, {
                'testconn': {
                    'my_addr': '192.168.1.1',
                    'peer_addr': '192.168.1.2',
                    'my_auth': {'psk': 'aa',
                                'id': 'alex@um.es'},
                    'peer_auth': {'psk': 'aa',
                                  'id': 'alex@um.es'},
                    'dh': [90],
                    'protect': [{'my_subnet': '192.168.1.1'}]
                }
            })


if __name__ == '__main__':
    unittest.main()
