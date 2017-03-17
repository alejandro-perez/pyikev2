#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
from ipaddress import ip_network, ip_address
from message import Transform
from crypto import Cipher, DiffieHellman, Integrity, Prf

class ConfigurationError(Exception):
    pass

class ConfigurationNotFound(ConfigurationError):
    pass

_encr_name_to_transform = {
    'aes128': Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 128),
    'aes256': Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 256),
}

_integ_name_to_transform = {
    'sha1': Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96),
    'md5': Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_MD5_96),
}

_prf_name_to_transform = {
    'sha1': Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1),
    'md5': Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_MD5),
}

_dh_name_to_transform = {
    '1': Transform(Transform.Type.DH, DiffieHellman.Id.DH_1),
    '2': Transform(Transform.Type.DH, DiffieHellman.Id.DH_2),
    '5': Transform(Transform.Type.DH, DiffieHellman.Id.DH_5),
    '14': Transform(Transform.Type.DH, DiffieHellman.Id.DH_14),
    '15': Transform(Transform.Type.DH, DiffieHellman.Id.DH_15),
    '16': Transform(Transform.Type.DH, DiffieHellman.Id.DH_16),
    '17': Transform(Transform.Type.DH, DiffieHellman.Id.DH_17),
    '18': Transform(Transform.Type.DH, DiffieHellman.Id.DH_18),
}

class IkeConfiguration(object):
    """ Represents the configuration applicable to an individual IKE SA
    """
    def __init__(self, key, conf_dict):
        """ Creates a new IkeConfiguration object from a textual dict
            (e.g. comming fron JSON or YAML)
        """
        self.psk = conf_dict.get('psk', 'whatever').encode()
        self.id = conf_dict.get('email', 'pyikev2').encode()

        self.encr_transforms = self.load_crypto_algs('encr',
            conf_dict.get('encr', ['aes256']), _encr_name_to_transform)
        self.integ_transforms = self.load_crypto_algs('integ',
            conf_dict.get('integ', ['sha1']), _integ_name_to_transform)
        self.prf_transforms = self.load_crypto_algs('prf',
            conf_dict.get('prf', ['sha1']), _prf_name_to_transform)
        self.dh_transforms = self.load_crypto_algs('dh',
            conf_dict.get('dh', ['5']), _dh_name_to_transform)

    def load_crypto_algs(self, type, names, name_to_transform):
        transforms = []
        for x in names:
            try:
                transforms.append(name_to_transform[x])
            except KeyError:
                raise ConfigurationError(
                    '{} algorithm "{}" not supported'.format(type, x))
        return transforms

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

