#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
from ipaddress import ip_network, ip_address
from message import Transform, PayloadID
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

class Configuration(object):
    """ Represents the daemon configuration
        Basically, a collection of IkeConfigurations
    """
    def __init__(self, my_addr, conf_dict):
        """ Creates a new Configuration object from a textual dict
            (e.g. comming fron JSON or YAML)
        """
        self._configuration = {}
        self.my_addr = my_addr
        for key, value in conf_dict.items():
            try:
                ip = ip_address(key)
            except ValueError as ex:
                raise ConfigurationError(str(ex))
            self._configuration[ip] = self._load_ike_conf(value)

    def _load_ike_conf(self, conf_dict):
        result = {}
        result['psk'] = conf_dict.get('psk', 'whatever').encode()
        result['id'] = PayloadID(PayloadID.Type.ID_RFC822_ADDR, 
                                 conf_dict.get('id', 'pyikev2').encode())
        result['peer_id'] = PayloadID(PayloadID.Type.ID_RFC822_ADDR, 
                                      conf_dict.get('id', 'pyikev2').encode())
        result['encr'] = self._load_crypto_algs(
            'encr', conf_dict.get('encr', ['aes256']), _encr_name_to_transform)
        result['integ'] = self._load_crypto_algs(
            'integ', conf_dict.get('integ', ['sha1']), _integ_name_to_transform)
        result['prf'] = self._load_crypto_algs(
            'prf', conf_dict.get('prf', ['sha1']), _prf_name_to_transform)
        result['dh'] = self._load_crypto_algs(
            'dh', conf_dict.get('dh', ['2']), _dh_name_to_transform)

        if 'protect' in conf_dict:
            ipsec_confs = []
            for ipsec_conf in conf_dict['protect']:
                ipsec_confs.append(self._load_ipsec_conf(ipsec_conf))
            result['protect'] = ipsec_confs
        return result

    def _load_ipsec_conf(self, conf_dict):
        result = {}
        return result




    def get_ike_configuration(self, addr):
        addr = ip_address(addr)
        try:
            found = next(key for key in self._configuration if addr == key)
        except StopIteration:
            raise ConfigurationNotFound
        return self._configuration[found]

    def _load_crypto_algs(self, key, names, name_to_transform):
        transforms = []
        if type(names) is not list:
            raise ConfigurationError('{} should be a list.'.format(key))
        for x in names:
            try:
                transforms.append(name_to_transform[x])
            except KeyError:
                raise ConfigurationError(
                    '{} algorithm "{}" not supported'.format(key, x))
        return transforms