#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module implements the Xfrm netlink protocol and provides a simple
    API to access to the IPsec features of the kernel
"""
import logging
import random
import socket
from ctypes import (c_ubyte, c_uint16, c_uint32, c_uint64, BigEndianStructure)
from enum import Enum
from ipaddress import ip_address
from struct import unpack_from

from message import Proposal, Transform
from netlink import (NetlinkStructure, NetlinkProtocol, NLM_F_REQUEST, NLM_F_ACK, NetlinkError)

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'

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


class Mode(int, Enum):
    TRANSPORT = XFRM_MODE_TRANSPORT
    TUNNEL = XFRM_MODE_TUNNEL


class XfrmAddress(NetlinkStructure, BigEndianStructure):
    _fields_ = (('addr', c_uint32 * 4),)

    @classmethod
    def from_ipaddr(cls, ip_addr):
        result = XfrmAddress()
        data = ip_addr.packed
        result.addr[0], = unpack_from('>I', data)
        if ip_addr.version == 6:
            result.addr[1], result.addr[2], result.addr[3] = unpack_from('>III', data, 4)
        return result

    def to_ipaddr(self, family):
        data = bytes(self.addr)
        if family == socket.AF_INET:
            data = data[:4]
        return ip_address(data)


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

    payload_types = NetlinkProtocol.payload_types
    payload_types.update({
        XFRM_MSG_ACQUIRE: XfrmUserAcquire,
        XFRM_MSG_EXPIRE: XfrmUserExpire,
        XFRM_MSG_NEWPOLICY: XfrmUserPolicyInfo,
    })

    netlink_family = socket.NETLINK_XFRM

    @classmethod
    def _create_sa(cls, src_selector, dst_selector, src_port, dst_port, spi, ip_proto, ipsec_proto, mode, src, dst,
                   enc_algorithm, sk_e, auth_algorithm, sk_a, lifetime=-1):
        usersa = XfrmUserSaInfo(
            sel=XfrmSelector(family=socket.AF_INET if src_selector[0].version == 4 else socket.AF_INET6,
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
                      proto=ipsec_proto,
                      spi=create_byte_array(spi)),
            family=socket.AF_INET if src.version == 4 else socket.AF_INET6,
            saddr=XfrmAddress.from_ipaddr(src),
            mode=mode,
            lft=XfrmLifetimeCfg.infinite() if lifetime < 0 else XfrmLifetimeCfg(soft_byte_limit=0xFFFFFFFFFFFFFFFF,
                                                                                hard_byte_limit=0xFFFFFFFFFFFFFFFF,
                                                                                soft_packed_limit=0xFFFFFFFFFFFFFFFF,
                                                                                hard_packet_limit=0xFFFFFFFFFFFFFFFF,
                                                                                soft_add_expires_seconds=lifetime,
                                                                                hard_add_expires_seconds=lifetime + 10,
                                                                                soft_use_expires_seconds=0,
                                                                                hard_use_expires_seconds=0),
        )
        attributes = {}
        if ipsec_proto == socket.IPPROTO_ESP:
            attributes[XFRMA_ALG_CRYPT] = XfrmAlgo.build(alg_name=enc_algorithm, key=sk_e)
        attributes[XFRMA_ALG_AUTH] = XfrmAlgo.build(alg_name=auth_algorithm, key=sk_a)
        cls.send_recv(XFRM_MSG_NEWSA, (NLM_F_REQUEST | NLM_F_ACK), usersa, attributes)

    @classmethod
    def flush_policies(cls):
        usersaflush = XfrmUserSaFlush(proto=0)
        cls.send_recv(XFRM_MSG_FLUSHPOLICY, (NLM_F_REQUEST | NLM_F_ACK), usersaflush)

    @classmethod
    def flush_sas(cls):
        usersaflush = XfrmUserSaFlush(proto=0)
        cls.send_recv(XFRM_MSG_FLUSHSA, (NLM_F_REQUEST | NLM_F_ACK), usersaflush)

    @classmethod
    def _create_policy(cls, src_selector, dst_selector, src_port, dst_port, ip_proto, direction,
                       ipsec_proto, mode, src, dst, index=0):
        policy = XfrmUserPolicyInfo(
            sel=XfrmSelector(family=socket.AF_INET if src_selector[0].version == 4 else socket.AF_INET6,
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
                      proto=ipsec_proto),
            family=socket.AF_INET if src.version == 4 else socket.AF_INET6,
            saddr=XfrmAddress.from_ipaddr(src),
            aalgos=0xFFFFFFFF,
            ealgos=0xFFFFFFFF,
            calgos=0xFFFFFFFF,
            mode=mode)
        cls.send_recv(XFRM_MSG_NEWPOLICY, (NLM_F_REQUEST | NLM_F_ACK), policy, {XFRMA_TMPL: template})

    @classmethod
    def _delete_sa(cls, daddr, proto, spi):
        xfrm_id = XfrmUserSaId(
            daddr=XfrmAddress.from_ipaddr(daddr),
            family=socket.AF_INET if daddr.version == 4 else socket.AF_INET6,
            proto=proto,
            spi=create_byte_array(spi))
        try:
            cls.send_recv(XFRM_MSG_DELSA, (NLM_F_REQUEST | NLM_F_ACK), xfrm_id)
        except NetlinkError as ex:
            logging.warning(f'Could not delete IPsec SA with SPI: {spi.hex()}. {ex}')

    # ***** NO IKE ENUMS BEFORE THIS POINT *******

    _cipher_names = {
        None: b'none',
        Transform.EncrId.ENCR_AES_CBC: b'cbc(aes)',
    }

    _auth_names = {
        Transform.IntegId.AUTH_HMAC_MD5_96: b'hmac(md5)',
        Transform.IntegId.AUTH_HMAC_SHA1_96: b'hmac(sha1)',
        Transform.IntegId.AUTH_HMAC_SHA2_256_128: b'hmac(sha256)',
        Transform.IntegId.AUTH_HMAC_SHA2_512_256: b'hmac(sha512)',
    }

    @classmethod
    def delete_sa(cls, daddr, proto, spi):
        ipsec_protocol = (socket.IPPROTO_ESP if proto == Proposal.Protocol.ESP
                          else socket.IPPROTO_AH)
        cls._delete_sa(daddr, ipsec_protocol, spi)

    @classmethod
    def delete_child_sa(cls, ike_sa, child_sa):
        ipsec_protocol = (socket.IPPROTO_ESP if child_sa.proposal.protocol_id == Proposal.Protocol.ESP
                          else socket.IPPROTO_AH)
        cls._delete_sa(ike_sa.peer_addr, ipsec_protocol, child_sa.outbound_spi)
        cls._delete_sa(ike_sa.my_addr, ipsec_protocol, child_sa.inbound_spi)

    @classmethod
    def create_policies(cls, ike_conf):
        for ipsec_conf in ike_conf.protect:
            src_selector = ipsec_conf.my_ts.get_network()
            dst_selector = ipsec_conf.peer_ts.get_network()
            src_port = ipsec_conf.my_ts.get_port()
            dst_port = ipsec_conf.peer_ts.get_port()
            ip_proto = ipsec_conf.my_ts.ip_proto
            ipsec_proto = (socket.IPPROTO_ESP if ipsec_conf.proposal.protocol_id == Proposal.Protocol.ESP
                           else socket.IPPROTO_AH)

            # generate an index for outbound policies
            index = ipsec_conf.index << 3 | XFRM_POLICY_OUT
            cls._create_policy(src_selector, dst_selector, src_port, dst_port, ip_proto, XFRM_POLICY_OUT, ipsec_proto,
                               ipsec_conf.mode, ike_conf.my_addr, ike_conf.peer_addr, index=index)
            cls._create_policy(dst_selector, src_selector, dst_port, src_port, ip_proto, XFRM_POLICY_IN, ipsec_proto,
                               ipsec_conf.mode, ike_conf.peer_addr, ike_conf.my_addr)
            cls._create_policy(dst_selector, src_selector, dst_port, src_port, ip_proto, XFRM_POLICY_FWD, ipsec_proto,
                               ipsec_conf.mode, ike_conf.peer_addr, ike_conf.my_addr)

    @classmethod
    def create_sa(cls, src, dst, src_sel, dst_sel, ipsec_protocol, spi, enc_algorith, sk_e,
                  auth_algorithm, sk_a, mode, lifetime=-1):
        ipsec_protocol = (socket.IPPROTO_ESP if ipsec_protocol == Proposal.Protocol.ESP
                          else socket.IPPROTO_AH)
        enc_algorith = cls._cipher_names[enc_algorith]
        auth_algorithm = cls._auth_names[auth_algorithm]
        cls._create_sa(src_sel.get_network(), dst_sel.get_network(), src_sel.get_port(),
                       dst_sel.get_port(), spi, src_sel.ip_proto, ipsec_protocol, mode, src,
                       dst, enc_algorith, sk_e, auth_algorithm, sk_a, lifetime)

    @classmethod
    def create_child_sa(cls, ike_sa, child_sa, keyring, is_initiator):
        src_selector = child_sa.tsi.get_network()
        dst_selector = child_sa.tsr.get_network()
        src_port = child_sa.tsi.get_port()
        dst_port = child_sa.tsr.get_port()
        ip_proto = child_sa.tsi.ip_proto
        ipsec_proto = (socket.IPPROTO_ESP if child_sa.proposal.protocol_id == Proposal.Protocol.ESP
                       else socket.IPPROTO_AH)

        encr_alg = (cls._cipher_names[child_sa.proposal.get_transform(Transform.Type.ENCR).id]
                    if ipsec_proto == socket.IPPROTO_ESP else None)
        integ_alg = cls._auth_names[child_sa.proposal.get_transform(Transform.Type.INTEG).id]
        lifetime = child_sa.lifetime + random.randint(0, 5) if child_sa.lifetime != -1 else -1

        # if we are responders, swap the keys for the purpose (since TS are swapped as well)
        if is_initiator:
            sk_ei, sk_er, sk_ai, sk_ar = keyring.sk_ei, keyring.sk_er, keyring.sk_ai, keyring.sk_ar
        else:
            sk_ei, sk_er, sk_ai, sk_ar = keyring.sk_er, keyring.sk_ei, keyring.sk_ar, keyring.sk_ai

        cls._create_sa(src_selector, dst_selector, src_port, dst_port, child_sa.outbound_spi, ip_proto, ipsec_proto,
                       child_sa.mode, ike_sa.my_addr, ike_sa.peer_addr, encr_alg, sk_ei, integ_alg, sk_ai, lifetime)
        cls._create_sa(dst_selector, src_selector, dst_port, src_port, child_sa.inbound_spi, ip_proto, ipsec_proto,
                       child_sa.mode, ike_sa.peer_addr, ike_sa.my_addr, encr_alg, sk_er, integ_alg, sk_ar, lifetime)

    @classmethod
    def get_socket(cls):
        return cls._get_socket(XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE)
