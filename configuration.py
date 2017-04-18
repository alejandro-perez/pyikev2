#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
from ipaddress import ip_address, ip_network

from crypto import Cipher, DiffieHellman, Integrity, Prf

import ipsec

from message import PayloadID, Proposal, TrafficSelector, Transform


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


_ip_proto_name_to_enum = {
    'tcp': TrafficSelector.IpProtocol.TCP,
    'any': TrafficSelector.IpProtocol.ANY,
    'udp': TrafficSelector.IpProtocol.UDP,
    'icmp': TrafficSelector.IpProtocol.ICMP,
}


_mode_name_to_enum = {
    'transport': ipsec.Mode.TRANSPORT,
    'tunnel': ipsec.Mode.TUNNEL,
}


_ipsec_proto_name_to_enum = {
    'esp': Proposal.Protocol.ESP,
    'ah': Proposal.Protocol.AH,
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
        self.my_addr = self._load_ip_address(my_addr)
        for key, value in conf_dict.items():
            try:
                ip = ip_address(key)
            except ValueError as ex:
                raise ConfigurationError(str(ex))
            self._configuration[ip] = self._load_ike_conf(ip, value)

    def items(self):
        return self._configuration.items()

    def _load_ike_conf(self, peer_ip, conf_dict):
        result = {}
        default_id = 'https://github.com/alejandro-perez/pyikev2'
        result['psk'] = conf_dict.get('psk', 'whatever').encode()
        result['id'] = PayloadID(PayloadID.Type.ID_FQDN,
                                 conf_dict.get('id', default_id).encode())
        result['peer_id'] = PayloadID(PayloadID.Type.ID_FQDN,
                                      conf_dict.get('id', default_id).encode())
        result['encr'] = self._load_crypto_algs(
            'encr', conf_dict.get('encr', ['aes256']), _encr_name_to_transform)
        result['integ'] = self._load_crypto_algs(
            'integ', conf_dict.get('integ', ['sha1']),
            _integ_name_to_transform)
        result['prf'] = self._load_crypto_algs(
            'prf', conf_dict.get('prf', ['sha1']), _prf_name_to_transform)
        result['dh'] = self._load_crypto_algs(
            'dh', conf_dict.get('dh', ['2']), _dh_name_to_transform)

        ipsec_confs = []
        for ipsec_conf in conf_dict.get('protect', [{}]):
            ipsec_confs.append(self._load_ipsec_conf(peer_ip, ipsec_conf))
        result['protect'] = ipsec_confs
        return result

    def _load_ip_network(self, value):
        try:
            return ip_network(value)
        except ValueError as ex:
            raise ConfigurationError(str(ex))

    def _load_ip_address(self, value):
        try:
            return ip_address(value)
        except ValueError as ex:
            raise ConfigurationError(str(ex))

    def _load_ipsec_conf(self, peer_ip, conf_dict):
        result = {}
        result['my_subnet'] = self._load_ip_network(
            conf_dict.get('my_subnet', self.my_addr))
        result['peer_subnet'] = self._load_ip_network(
            conf_dict.get('peer_subnet', peer_ip))
        result['my_port'] = int(conf_dict.get('my_port', 0))
        result['peer_port'] = int(conf_dict.get('peer_port', 0))
        result['ip_proto'] = self._load_from_dict(
            conf_dict.get('ip_proto', 'any'), _ip_proto_name_to_enum)
        result['mode'] = self._load_from_dict(
            conf_dict.get('mode', 'transport'), _mode_name_to_enum)
        result['ipsec_proto'] = self._load_from_dict(
            conf_dict.get('ipsec_proto', 'esp'), _ipsec_proto_name_to_enum)
        result['encr'] = self._load_crypto_algs(
            'encr', conf_dict.get('encr', ['aes256']), _encr_name_to_transform)
        result['integ'] = self._load_crypto_algs(
            'integ', conf_dict.get('integ', ['sha1']),
            _integ_name_to_transform)
        return result

    def get_ike_configuration(self, addr):
        addr = ip_address(addr)
        try:
            found = next(key for key in self._configuration if addr == key)
        except StopIteration:
            raise ConfigurationNotFound
        return self._configuration[found]

    def _load_from_dict(self, key, dict):
        try:
            return dict[key]
        except KeyError:
            raise ConfigurationError(
                '{} not supported'.format(key))

    def _load_crypto_algs(self, key, names, name_to_transform):
        transforms = []
        if type(names) is not list:
            raise ConfigurationError('{} should be a list.'.format(key))
        for x in names:
            transform = self._load_from_dict(str(x), name_to_transform)
            transforms.append(transform)
        return transforms
