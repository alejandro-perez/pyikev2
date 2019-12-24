#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module implements the Xfrm netlink protocol and provides a simple
    API to access to the IPsec features of the kernel
"""
import logging
import socket
from ctypes import (c_ubyte, c_uint16, c_uint32, c_uint64, BigEndianStructure)
from ipaddress import ip_address, ip_network
from random import SystemRandom

from helpers import SafeIntEnum, hexstring
from message import Proposal, Transform
from netlink import (NetlinkStructure, NetlinkProtocol, NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP,
                     NetlinkError)

__author__ = 'Alejandro Perez <alex@um.es>'

# XFRM payload types
XFRM_MSG_NEWSA = 0x10
XFRM_MSG_DELSA = 0x11
XFRM_MSG_GETSA = 0x12
XFRM_MSG_NEWPOLICY = 0x13
XFRM_MSG_DELPOLICY = 0x14
XFRM_MSG_GETPOLICY = 0x15
XFRM_MSG_ALLOCSPI = 0x16
XFRM_MSG_ACQUIRE = 0x17
XFRM_MSG_EXPIRE = 0x18
XFRM_MSG_UPDPOLICY = 0x19
XFRM_MSG_UPDSA = 0x1A
XFRM_MSG_POLEXPIRE = 0x1B
XFRM_MSG_FLUSHSA = 0x1C
XFRM_MSG_FLUSHPOLICY = 0x1D

# XFRM attributes
XFRMA_UNSPEC = 0
XFRMA_ALG_AUTH = 1
XFRMA_ALG_CRYPT = 2
XFRMA_ALG_COMP = 3
XFRMA_ENCAP = 4
XFRMA_TMPL = 5
XFRMA_SA = 6
XFRMA_POLICY = 7
XFRMA_SEC_CTX = 8
XFRMA_LTIME_VAL = 9
XFRMA_REPLAY_VAL = 10
XFRMA_REPLAY_THRESH = 11
XFRMA_ETIMER_THRESH = 12
XFRMA_SRCADDR = 13
XFRMA_COADDR = 14
XFRMA_LASTUSED = 15
XFRMA_POLICY_TYPE = 16
XFRMA_MIGRATE = 17
XFRMA_ALG_AEAD = 18
XFRMA_KMADDRESS = 19
XFRMA_ALG_AUTH_TRUNC = 20
XFRMA_MARK = 21
XFRMA_TFCPAD = 22
XFRMA_REPLAY_ESN_VAL = 23
XFRMA_SA_EXTRA_FLAGS = 24
XFRMA_PROTO = 25
XFRMA_ADDRESS_FILTER = 26
XFRMA_PAD = 27

# XFRM policy dir
XFRM_POLICY_IN = 0
XFRM_POLICY_OUT = 1
XFRM_POLICY_FWD = 2
XFRM_POLICY_MASK = 3

# XFRM modes
XFRM_MODE_TRANSPORT = 0
XFRM_MODE_TUNNEL = 1

# XFRM groups
XFRMGRP_ACQUIRE = 1
XFRMGRP_EXPIRE = 2
XFRMGRP_SA = 4
XFRMGRP_POLICY = 8

# XFRM policy types
XFRM_POLICY_ALLOW = 0
XFRM_POLICY_BLOCK = 1


# Helper function to create a c_ubyte_Array from a byte object
def create_byte_array(data, size=None):
    if size is None:
        size = len(data)
    return (c_ubyte * size)(*data)


class Mode(SafeIntEnum):
    TRANSPORT = XFRM_MODE_TRANSPORT
    TUNNEL = XFRM_MODE_TUNNEL


# TODO: This needs to support IPv6 in the future
class XfrmAddress(NetlinkStructure, BigEndianStructure):
    _fields_ = (('addr', c_uint32 * 4),)

    @classmethod
    def from_ipaddr(cls, ip_addr):
        result = XfrmAddress()
        result.addr[0] = int(ip_addr)
        return result

    def to_ipaddr(self):
        return ip_address(self.addr[0])


class XfrmSelector(NetlinkStructure):
    _fields_ = (('daddr', XfrmAddress),
                ('saddr', XfrmAddress),
                ('dport', c_uint16.__ctype_be__),
                ('dport_mask', c_uint16),
                ('sport', c_uint16.__ctype_be__),
                ('sport_mask', c_uint16),
                ('family', c_uint16),
                ('prefixlen_d', c_ubyte),
                ('prefixlen_s', c_ubyte),
                ('proto', c_ubyte),
                ('ifindex', c_uint32),
                ('user', c_uint32))


class XfrmUserPolicyId(NetlinkStructure):
    _fields_ = (('selector', XfrmSelector),
                ('index', c_uint32),
                ('dir', c_ubyte))


class XfrmLifetimeCfg(NetlinkStructure):
    _fields_ = (('soft_byte_limit', c_uint64),
                ('hard_byte_limit', c_uint64),
                ('soft_packed_limit', c_uint64),
                ('hard_packet_limit', c_uint64),
                ('soft_add_expires_seconds', c_uint64),
                ('hard_add_expires_seconds', c_uint64),
                ('soft_use_expires_seconds', c_uint64),
                ('hard_use_expires_seconds', c_uint64))

    @classmethod
    def infinite(cls):
        return XfrmLifetimeCfg(soft_byte_limit=0xFFFFFFFFFFFFFFFF,
                               hard_byte_limit=0xFFFFFFFFFFFFFFFF,
                               soft_packed_limit=0xFFFFFFFFFFFFFFFF,
                               hard_packet_limit=0xFFFFFFFFFFFFFFFF,
                               soft_add_expires_seconds=0,
                               hard_add_expires_seconds=0,
                               soft_use_expires_seconds=0,
                               hard_use_expires_seconds=0)


class XfrmLifetimeCur(NetlinkStructure):
    _fields_ = (('bytes', c_uint64),
                ('packets', c_uint64),
                ('add_time', c_uint64),
                ('use_time', c_uint64))


class XfrmUserPolicyInfo(NetlinkStructure):
    _fields_ = (('sel', XfrmSelector),
                ('lft', XfrmLifetimeCfg),
                ('curlft', XfrmLifetimeCur),
                ('priority', c_uint32),
                ('index', c_uint32),
                ('dir', c_ubyte),
                ('action', c_ubyte),
                ('flags', c_ubyte),
                ('share', c_ubyte))


class XfrmUserSaFlush(NetlinkStructure):
    _fields_ = (('proto', c_ubyte),)


class XfrmId(NetlinkStructure):
    _fields_ = (('daddr', XfrmAddress),
                ('spi', c_ubyte * 4),
                ('proto', c_ubyte))


class XfrmUserTmpl(NetlinkStructure):
    _fields_ = (('id', XfrmId),
                ('family', c_uint16),
                ('saddr', XfrmAddress),
                ('reqid', c_uint32),
                ('mode', c_ubyte),
                ('share', c_ubyte),
                ('optional', c_ubyte),
                ('aalgos', c_uint32),
                ('ealgos', c_uint32),
                ('calgos', c_uint32))


class XfrmStats(NetlinkStructure):
    _fields_ = (('replay_window', c_uint32),
                ('replay', c_uint32),
                ('integrity_failed', c_uint32))


class XfrmUserSaInfo(NetlinkStructure):
    _fields_ = (('sel', XfrmSelector),
                ('id', XfrmId),
                ('saddr', XfrmAddress),
                ('lft', XfrmLifetimeCfg),
                ('cur', XfrmLifetimeCur),
                ('stats', XfrmStats),
                ('seq', c_uint32),
                ('reqid', c_uint32),
                ('family', c_uint16),
                ('mode', c_ubyte),
                ('replay_window', c_ubyte),
                ('flags', c_ubyte))


class XfrmAlgo(NetlinkStructure):
    _fields_ = (('alg_name', c_ubyte * 64),
                ('alg_key_len', c_uint32),
                ('key', c_ubyte * 64))

    @classmethod
    def build(cls, alg_name, key):
        return XfrmAlgo(alg_name=create_byte_array(alg_name, 64), alg_key_len=len(key) * 8,
                        key=create_byte_array(key, 64))


class XfrmUserSaId(NetlinkStructure):
    _fields_ = (('daddr', XfrmAddress),
                ('spi', c_ubyte * 4),
                ('family', c_uint16),
                ('proto', c_ubyte))


class XfrmUserAcquire(NetlinkStructure):
    _fields_ = (('id', XfrmId),
                ('saddr', XfrmAddress),
                ('sel', XfrmSelector),
                ('policy', XfrmUserPolicyInfo),
                ('aalgos', c_uint32),
                ('ealgos', c_uint32),
                ('calgos', c_uint32),
                ('seq', c_uint32))


class XfrmUserExpire(NetlinkStructure):
    _fields_ = (('state', XfrmUserSaInfo),
                ('hard', c_ubyte))


class Xfrm(NetlinkProtocol):
    attribute_types = {
        XFRMA_TMPL: XfrmUserTmpl,
    }

    payload_types = _msg_to_struct = {
        XFRM_MSG_ACQUIRE: XfrmUserAcquire,
        XFRM_MSG_EXPIRE: XfrmUserExpire,
        XFRM_MSG_NEWPOLICY: XfrmUserPolicyInfo,
    }

    _cipher_names = {
        None: b'none',
        Transform.EncrId.ENCR_AES_CBC: b'aes',
    }

    _auth_names = {
        Transform.IntegId.AUTH_HMAC_MD5_96: b'md5',
        Transform.IntegId.AUTH_HMAC_SHA1_96: b'sha1',
    }

    netlink_family = socket.NETLINK_XFRM

    def _create_sa(self, src_selector, dst_selector, src_port, dst_port, spi, ip_proto,
                   ipsec_proto, mode, src, dst, enc_algorith, sk_e, auth_algorithm, sk_a):
        usersa = XfrmUserSaInfo(
            sel=XfrmSelector(family=socket.AF_INET,
                             daddr=XfrmAddress.from_ipaddr(dst_selector[0]),
                             saddr=XfrmAddress.from_ipaddr(src_selector[0]),
                             dport=dst_port,
                             sport=src_port,
                             dport_mask=0 if dst_port == 0 else 0xFFFF,
                             sport_mask=0 if src_port == 0 else 0xFFFF,
                             prefixlen_d=dst_selector.prefixlen,
                             prefixlen_s=src_selector.prefixlen,
                             proto=ip_proto),
            id=XfrmId(daddr=XfrmAddress.from_ipaddr(dst),
                      proto=(socket.IPPROTO_ESP
                             if ipsec_proto == Proposal.Protocol.ESP else socket.IPPROTO_AH),
                      spi=create_byte_array(spi)),
            family=socket.AF_INET,
            saddr=XfrmAddress.from_ipaddr(src),
            mode=mode,
            lft=XfrmLifetimeCfg.infinite(),
        )

        attributes = {}
        if ipsec_proto == Proposal.Protocol.ESP:
            attributes[XFRMA_ALG_CRYPT] = XfrmAlgo.build(alg_name=self._cipher_names[enc_algorith],
                                                         key=sk_e)
        attributes[XFRMA_ALG_AUTH] = XfrmAlgo.build(alg_name=self._auth_names[auth_algorithm],
                                                    key=sk_a)
        self.send_recv(XFRM_MSG_NEWSA, (NLM_F_REQUEST | NLM_F_ACK), usersa, attributes)

    def flush_policies(self):
        usersaflush = XfrmUserSaFlush(proto=0)
        self.send_recv(XFRM_MSG_FLUSHPOLICY, (NLM_F_REQUEST | NLM_F_ACK), usersaflush)

    def flush_sas(self):
        usersaflush = XfrmUserSaFlush(proto=0)
        self.send_recv(XFRM_MSG_FLUSHSA, (NLM_F_REQUEST | NLM_F_ACK), usersaflush)

    def _create_policy(self, src_selector, dst_selector, src_port, dst_port, ip_proto, direction,
                       ipsec_proto, mode, src, dst, index=0):
        policy = XfrmUserPolicyInfo(
            sel=XfrmSelector(family=socket.AF_INET,
                             daddr=XfrmAddress.from_ipaddr(dst_selector[0]),
                             saddr=XfrmAddress.from_ipaddr(src_selector[0]),
                             dport=dst_port,
                             sport=src_port,
                             dport_mask=0 if dst_port == 0 else 0xFFFF,
                             sport_mask=0 if src_port == 0 else 0xFFFF,
                             prefixlen_d=dst_selector.prefixlen,
                             prefixlen_s=src_selector.prefixlen,
                             proto=ip_proto),
            dir=direction,
            index=index,
            action=XFRM_POLICY_ALLOW,
            lft=XfrmLifetimeCfg.infinite(),
        )
        template = XfrmUserTmpl(
            id=XfrmId(daddr=XfrmAddress.from_ipaddr(dst),
                      proto=(socket.IPPROTO_ESP
                             if ipsec_proto == Proposal.Protocol.ESP else socket.IPPROTO_AH)),
            family=socket.AF_INET,
            saddr=XfrmAddress.from_ipaddr(src),
            aalgos=0xFFFFFFFF,
            ealgos=0xFFFFFFFF,
            calgos=0xFFFFFFFF,
            mode=mode)
        self.send_recv(XFRM_MSG_NEWPOLICY, (NLM_F_REQUEST | NLM_F_ACK), policy,
                       {XFRMA_TMPL: template})

    def delete_sa(self, daddr, proto, spi):
        xfrm_id = XfrmUserSaId(
            daddr=XfrmAddress.from_ipaddr(daddr),
            family=socket.AF_INET,
            proto=socket.IPPROTO_ESP if proto == Proposal.Protocol.ESP else socket.IPPROTO_AH,
            spi=create_byte_array(spi))
        try:
            self.send_recv(XFRM_MSG_DELSA, (NLM_F_REQUEST | NLM_F_ACK), xfrm_id)
        except NetlinkError as ex:
            logging.error('Could not delete IPsec SA with SPI: {}. {}'.format(hexstring(spi), ex))

    def create_policies(self, my_addr, peer_addr, ike_conf):
        for ipsec_conf in ike_conf['protect']:
            if ipsec_conf['mode'] == Mode.TUNNEL:
                src_selector = ipsec_conf['my_subnet']
                dst_selector = ipsec_conf['peer_subnet']
            else:
                src_selector = ip_network(my_addr)
                dst_selector = ip_network(peer_addr)

            # generate an index for outbound policies
            index = SystemRandom().randint(0, 2**20) << 3 | XFRM_POLICY_OUT
            ipsec_conf['index'] = index

            self._create_policy(src_selector, dst_selector, ipsec_conf['my_port'],
                                ipsec_conf['peer_port'], ipsec_conf['ip_proto'], XFRM_POLICY_OUT,
                                ipsec_conf['ipsec_proto'], ipsec_conf['mode'], my_addr, peer_addr,
                                index=index)
            self._create_policy(dst_selector, src_selector, ipsec_conf['peer_port'],
                                ipsec_conf['my_port'], ipsec_conf['ip_proto'], XFRM_POLICY_IN,
                                ipsec_conf['ipsec_proto'], ipsec_conf['mode'], peer_addr, my_addr)
            self._create_policy(dst_selector, src_selector,
                                ipsec_conf['peer_port'], ipsec_conf['my_port'],
                                ipsec_conf['ip_proto'], XFRM_POLICY_FWD, ipsec_conf['ipsec_proto'],
                                ipsec_conf['mode'], peer_addr, my_addr)

    def create_sa(self, src, dst, src_sel, dst_sel, ipsec_protocol, spi, enc_algorith, sk_e,
                  auth_algorithm, sk_a, mode):
        self._create_sa(src_sel.get_network(), dst_sel.get_network(), src_sel.get_port(),
                        dst_sel.get_port(), spi, src_sel.ip_proto, ipsec_protocol, mode, src,
                        dst, enc_algorith, sk_e, auth_algorithm, sk_a)

    def _get_policies(self):
        policy_id = XfrmUserPolicyId()
        return self.send_recv(XFRM_MSG_GETPOLICY, (NLM_F_REQUEST | NLM_F_DUMP), policy_id)

    def get_socket(self):
        return self._get_socket(XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE)
