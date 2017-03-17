#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
from ipaddress import ip_network

class ConfigurationError(Exception):
    pass

class Configuration(object):
    """ Represents the daemon configuration
        Basically, a collection of IkeConfigurations
    """ 
    def __init__(self, conf_dict):
        """ Loads configuration from a dict object
        """
        self._ike_configurations = {}
        for ip_range, ike_conf_dict in conf_dict.items():
            try:
                ip_range = ip_network(ip_range)
                self._ike_configurations[ip_range] = ike_conf_dict
            except ValueError as ex:
                raise ConfigurationError(str(ex))

    def get_ike_configuration(self, addr):
        return self._ike_configurations[str(addr)]