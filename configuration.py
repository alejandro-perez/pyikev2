#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import random
import socket
from collections import namedtuple
from ipaddress import ip_address, ip_network

import xfrm
from crypto import RsaPrivateKey, RsaPublicKey
from message import PayloadID, Proposal, TrafficSelector, Transform

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class ConfigurationError(Exception):
    pass


class ConfigurationNotFound(ConfigurationError):
    pass


_encr_name_to_transform = {
    'aes128': Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 128),
    'aes256': Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 256),
}

_integ_name_to_transform = {
    'sha256': Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA2_256_128),
    'sha512': Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA2_512_256),
    'sha1': Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA1_96),
}

_prf_name_to_transform = {
    'sha1': Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1),
    'sha256': Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA2_256),
    'sha512': Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA2_512),
}

_dh_name_to_transform = {
    '14': Transform(Transform.Type.DH, Transform.DhId.DH_14),
    '15': Transform(Transform.Type.DH, Transform.DhId.DH_15),
    '16': Transform(Transform.Type.DH, Transform.DhId.DH_16),
    '17': Transform(Transform.Type.DH, Transform.DhId.DH_17),
    '18': Transform(Transform.Type.DH, Transform.DhId.DH_18),
    '19': Transform(Transform.Type.DH, Transform.DhId.DH_19),
    '20': Transform(Transform.Type.DH, Transform.DhId.DH_20),
    '21': Transform(Transform.Type.DH, Transform.DhId.DH_21),
    'modp2048': Transform(Transform.Type.DH, Transform.DhId.DH_14),
    'modp3072': Transform(Transform.Type.DH, Transform.DhId.DH_15),
    'modp4096': Transform(Transform.Type.DH, Transform.DhId.DH_16),
    'modp6144': Transform(Transform.Type.DH, Transform.DhId.DH_17),
    'modp8192': Transform(Transform.Type.DH, Transform.DhId.DH_18),
    'ecp256': Transform(Transform.Type.DH, Transform.DhId.DH_19),
    'ecp384': Transform(Transform.Type.DH, Transform.DhId.DH_20),
    'ecp521': Transform(Transform.Type.DH, Transform.DhId.DH_21),
}

_ip_proto_name_to_enum = {
    'tcp': TrafficSelector.IpProtocol.TCP,
    'any': TrafficSelector.IpProtocol.ANY,
    'udp': TrafficSelector.IpProtocol.UDP,
    'icmp': TrafficSelector.IpProtocol.ICMP,
}

_mode_name_to_enum = {
    'transport': xfrm.Mode.TRANSPORT,
    'tunnel': xfrm.Mode.TUNNEL,
}

_ipsec_proto_name_to_enum = {
    'esp': Proposal.Protocol.ESP,
    'ah': Proposal.Protocol.AH,
}

IkeConfiguration = namedtuple('IkeConfiguration',
                              ['name', 'my_addr', 'peer_addr', 'my_auth', 'peer_auth', 'lifetime', 'dpd', 'proposal',
                               'protect'])

AuthConfiguration = namedtuple('AuthConfiguration', ['psk', 'id', 'privkey', 'pubkey'])

IpsecConfiguration = namedtuple('IpsecConfiguration', ['my_ts', 'index', 'peer_ts', 'lifetime', 'mode', 'proposal'])


class Configuration(object):
    def __init__(self, my_addresses, conf_dict):
        """ Creates a new Configuration object from a textual dict
        """
        self.ike_configurations = {}
        for connection_name, ikeconfdict in conf_dict.items():
            try:
                ikeconf = self._load_ike_conf(connection_name, ikeconfdict, my_addresses)
                self.ike_configurations[(ikeconf.my_addr, ikeconf.peer_addr)] = ikeconf
            except KeyError as ex:
                raise ConfigurationError(f'Mandatory parameter {ex} missing for connection "{connection_name}"')

    def _load_ike_conf(self, name, conf_dict, my_addresses):
        encr = self._load_crypto_algs('encr', conf_dict.get('encr', ['aes256']), _encr_name_to_transform)
        integ = self._load_crypto_algs('integ', conf_dict.get('integ', ['sha256']), _integ_name_to_transform)
        prf = self._load_crypto_algs('prf', conf_dict.get('prf', ['sha256']), _prf_name_to_transform)
        dh = self._load_crypto_algs('dh', conf_dict.get('dh', ['14']), _dh_name_to_transform)
        ikeconf = IkeConfiguration(
            name=name,
            my_addr=self._load_ip_address(conf_dict['my_addr']),
            peer_addr=self._load_ip_address(conf_dict['peer_addr']),
            my_auth=self._load_auth_conf(conf_dict['my_auth']),
            peer_auth=self._load_auth_conf(conf_dict['peer_auth']),
            lifetime=int(conf_dict.get('lifetime', 15 * 60)),
            dpd=int(conf_dict.get('dpd', 60)),
            proposal=Proposal(1, Proposal.Protocol.IKE, b'', encr + integ + prf + dh),
            protect=[]
        )
        if ikeconf.my_addr not in my_addresses:
            raise ConfigurationError(
                f'Connection {name} has invalid "my_addr" {ikeconf.my_addr}. You need to listen from it')

        for ipsecconf_dict in conf_dict['protect']:
            ikeconf.protect.append(self._load_ipsec_conf(ikeconf, ipsecconf_dict))
        return ikeconf

    @staticmethod
    def _load_ip_network(value):
        try:
            return ip_network(value)
        except ValueError as ex:
            raise ConfigurationError(f'Could not parse {ex} as an IP network')

    @staticmethod
    def _get_payload_id(value):
        try:
            addr = ip_address(value)
            type = PayloadID.Type.ID_IPV4_ADDR if addr.version == 4 else PayloadID.Type.ID_IPV6_ADDR
            return PayloadID(type, addr.packed)
        except ValueError:
            pass
        if '@' in value:
            type = PayloadID.Type.ID_RFC822_ADDR
        else:
            type = PayloadID.Type.ID_FQDN
        return PayloadID(type, value.encode())

    @staticmethod
    def _load_ip_address(hostname):
        try:
            addr = ip_address(socket.getaddrinfo(hostname, None)[0][4][0])
            return ip_address(addr)
        except (ValueError, socket.gaierror) as ex:
            raise ConfigurationError(f'Could not resolve {hostname} into an IP address: {ex}')

    def _load_auth_conf(self, conf_dict):
        id_text = conf_dict.get('id', 'https://github.com/alejandro-perez/pyikev2')
        return AuthConfiguration(
            psk=conf_dict['psk'].encode() if 'psk' in conf_dict else None,
            id=self._get_payload_id(id_text),
            pubkey=RsaPublicKey(conf_dict.get('pubkey').encode()) if 'pubkey' in conf_dict else None,
            privkey=RsaPrivateKey(conf_dict.get('privkey').encode()) if 'privkey' in conf_dict else None,
        )

    def _load_ipsec_conf(self, ikeconf, conf_dict):
        no_esn = [Transform(Transform.Type.ESN, Transform.EsnId.NO_ESN)]
        ipsec_proto = self._load_from_dict(conf_dict.get('ipsec_proto', 'esp'), _ipsec_proto_name_to_enum)
        encr = self._load_crypto_algs('encr', conf_dict.get('encr', ['aes256']), _encr_name_to_transform)
        integ = self._load_crypto_algs('integ', conf_dict.get('integ', ['sha256']), _integ_name_to_transform)
        dh = self._load_crypto_algs('dh', conf_dict.get('dh', []), _dh_name_to_transform)
        if ipsec_proto == Proposal.Protocol.AH:
            encr = []

        ip_proto = self._load_from_dict(conf_dict.get('ip_proto', 'any'), _ip_proto_name_to_enum)
        my_subnet = self._load_ip_network(conf_dict.get('my_subnet', ikeconf.my_addr))
        my_port = int(conf_dict.get('my_port', 0))
        peer_subnet = self._load_ip_network(conf_dict.get('peer_subnet', ikeconf.peer_addr))
        peer_port = int(conf_dict.get('peer_port', 0))

        return IpsecConfiguration(
            index=int(conf_dict.get('index', random.randint(0, 2 ** 20))),
            my_ts=TrafficSelector.from_network(my_subnet, my_port, ip_proto),
            peer_ts=TrafficSelector.from_network(peer_subnet, peer_port, ip_proto),
            lifetime=int(conf_dict.get('lifetime', 5 * 60)),
            mode=self._load_from_dict(conf_dict.get('mode', 'tunnel'), _mode_name_to_enum),
            proposal=Proposal(1, ipsec_proto, b'', encr + integ + dh + no_esn),
        )

    def get_ike_configuration(self, src_addr, peer_addr):
        try:
            return self.ike_configurations[(src_addr, peer_addr)]
        except KeyError:
            raise ConfigurationNotFound(f'Could not find a configuration for "{src_addr}, {peer_addr}"')

    @staticmethod
    def _load_from_dict(key, cnf_dict):
        try:
            return cnf_dict[key]
        except KeyError:
            raise ConfigurationError(f'I could not understand {key} configuration value')

    def _load_crypto_algs(self, key, names, name_to_transform):
        transforms = []
        if type(names) is not list:
            raise ConfigurationError(f'{key} should be a list.')
        for x in names:
            transform = self._load_from_dict(str(x), name_to_transform)
            transforms.append(transform)
        return transforms
