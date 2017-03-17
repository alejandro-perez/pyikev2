#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test configuration system
"""
__author__ = 'Alejandro Perez <alex@um.es>'

import unittest
from configuration import Configuration, ConfigurationError


class TestConfiguration(unittest.TestCase):
    def test_empty(self):
        conf = Configuration({})

    def test_no_range(self):
        with self.assertRaises(ConfigurationError):
            conf = Configuration({'a': 123})

    def test_ip(self):
        conf = Configuration({'192.168.1.1': 123})

    def test_valid(self):
        conf = Configuration({'192.168.1.1/32': 123})
        print(conf._ike_configurations)

if __name__ == '__main__':
    unittest.main()
