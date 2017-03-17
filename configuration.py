#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
from ipaddress import ip_network, ip_address

class ConfigurationError(Exception):
    pass

class ConfigurationNotFound(ConfigurationError):
    pass


class IkeConfiguration(object):
    """ Represents the configuration applicable to an individual IKE SA
    """
    def __init__(self, key, conf_dict):
        """ Creates a new IkeConfiguration object from a textual dict 
            (e.g. comming fron JSON or YAML)
        """
        try:
            self.psk = conf_dict['psk']
            self.id = conf_dict['email']
        except KeyError as ex:
            raise ConfigurationError(
                'Required parameter "{}" missing for IKE configuration "{}"'.format(
                    ex.args[0], key))

class Configuration(object):
    """ Represents the daemon configuration
        Basically, a collection of IkeConfigurations
    """ 
    def __init__(self, conf_dict):
        """ Creates a new Configuration object from a textual dict 
            (e.g. comming fron JSON or YAML)
        """
        self._ike_configurations = {}
        for ip_range, ike_conf_dict in conf_dict.items():
            try:
                ip_range = ip_network(ip_range)
                self._ike_configurations[ip_range] = IkeConfiguration(
                    ip_range, ike_conf_dict)
            except ValueError as ex:
                raise ConfigurationError(str(ex))

    def get_ike_configuration(self, addr):
        addr = ip_address(addr)
        try:
            found = next(key for key in self._ike_configurations if addr in key)
        except StopIteration:
            raise ConfigurationNotFound
        return self._ike_configurations[found]