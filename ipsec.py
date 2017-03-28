#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines a simple SPI to access to IPsec features of the kernel
"""
from message import TrafficSelector, Proposal, Transform
from crypto import Cipher, Integrity
from helpers import hexstring, SafeIntEnum
from ipaddress import ip_address, ip_network
import logging
import socket
from ctypes import *
from struct import pack, unpack_from
import time
import os
from collections import defaultdict

# netlink flags
NLM_F_REQUEST    = 0x0001
NLM_F_MULTI      = 0x0002
NLM_F_ACK        = 0x0004
NLM_F_ROOT       = 0x0100
NLM_F_MATCH      = 0x0200
NLM_F_ATOMIC     = 0x0400
NLM_F_DUMP       = (NLM_F_REQUEST|NLM_F_ROOT|NLM_F_MATCH)

# netlink/protocol payload type
NLMSG_ERROR         = 0x02
NLMSG_DONE          = 0x03
XFRM_MSG_NEWSA      = 0x10
XFRM_MSG_DELSA      = 0x11
XFRM_MSG_GETSA      = 0x12
XFRM_MSG_NEWPOLICY  = 0x13
XFRM_MSG_DELPOLICY  = 0x14
XFRM_MSG_GETPOLICY  = 0x15
XFRM_MSG_ALLOCSPI   = 0x16
XFRM_MSG_ACQUIRE    = 0x17
XFRM_MSG_EXPIRE     = 0x18
XFRM_MSG_UPDPOLICY  = 0x19
XFRM_MSG_UPDSA      = 0x1A
XFRM_MSG_POLEXPIRE  = 0x1B
XFRM_MSG_FLUSHSA    = 0x1C
XFRM_MSG_FLUSHPOLICY= 0x1D

# XFRM attributes
XFRMA_UNSPEC        = 0
XFRMA_ALG_AUTH      = 1
XFRMA_ALG_CRYPT     = 2
XFRMA_ALG_COMP      = 3
XFRMA_ENCAP         = 4
XFRMA_TMPL          = 5
XFRMA_SA            = 6
XFRMA_POLICY        = 7
XFRMA_SEC_CTX       = 8
XFRMA_LTIME_VAL     = 9
XFRMA_REPLAY_VAL    = 10
XFRMA_REPLAY_THRESH = 11
XFRMA_ETIMER_THRESH = 12
XFRMA_SRCADDR       = 13
XFRMA_COADDR        = 14
XFRMA_LASTUSED      = 15
XFRMA_POLICY_TYPE   = 16
XFRMA_MIGRATE       = 17
XFRMA_ALG_AEAD      = 18
XFRMA_KMADDRESS     = 19
XFRMA_ALG_AUTH_TRUNC= 20
XFRMA_MARK          = 21
XFRMA_TFCPAD        = 22
XFRMA_REPLAY_ESN_VAL= 23
XFRMA_SA_EXTRA_FLAGS= 24
XFRMA_PROTO         = 25
XFRMA_ADDRESS_FILTER= 26
XFRMA_PAD           = 27

XFRM_POLICY_IN  = 0
XFRM_POLICY_OUT = 1
XFRM_POLICY_FWD = 2
XFRM_POLICY_MASK = 3

XFRM_MODE_TRANSPORT = 0
XFRM_MODE_TUNNEL = 1

# XFRM mode
class Mode(SafeIntEnum):
    TRANSPORT = XFRM_MODE_TRANSPORT
    TUNNEL = XFRM_MODE_TUNNEL

# XFRM groups
XFRMGRP_ACQUIRE     = 1
XFRMGRP_EXPIRE      = 2
XFRMGRP_SA          = 4
XFRMGRP_POLICY      = 8

XFRM_POLICY_ALLOW  = 0
XFRM_POLICY_BLOCK  = 1

class NetlinkError(Exception):
    pass

class NetlinkStructure(Structure):
    @classmethod
    def parse(cls, bytes):
        result = cls()
        memmove(addressof(result), bytes, sizeof(cls))
        return result

class NetlinkHeader(NetlinkStructure):
    _fields_ = (
        ('length', c_uint32),
        ('type', c_uint16),
        ('flags', c_uint16),
        ('seq', c_uint32),
        ('pid', c_uint32),
    )

class NetlinkErrorMsg(NetlinkStructure):
    _fields_ = (
        ('error', c_int),
        ('msg', NetlinkHeader),
    )

class XfrmAddress(Structure):
    _fields_ = (
        ('addr', c_uint32.__ctype_be__ * 4),
    )
    @classmethod
    def from_ipaddr(cls, ip_addr):
        result = XfrmAddress()
        result.addr[0] = int(ip_addr)
        return result

class XfrmSelector(Structure):
    _fields_ = (
        ('daddr', XfrmAddress),
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
        ('user', c_uint32),
    )

class XfrmUserPolicyId(Structure):
    _fields_ = (
        ('selector', XfrmSelector),
        ('index', c_uint32),
        ('dir', c_ubyte),
    )

class XfrmLifetimeCfg(Structure):
    _fields_ = (
        ('soft_byte_limit', c_uint64),
        ('hard_byte_limit', c_uint64),
        ('soft_packed_limit', c_uint64),
        ('hard_packet_limit', c_uint64),
        ('soft_add_expires_seconds', c_uint64),
        ('hard_add_expires_seconds', c_uint64),
        ('soft_use_expires_seconds', c_uint64),
        ('hard_use_expires_seconds', c_uint64),
    )

class XfrmLifetimeCur(Structure):
    _fields_ = (
        ('bytes', c_uint64),
        ('packets', c_uint64),
        ('add_time', c_uint64),
        ('use_time', c_uint64),
    )

class XfrmUserPolicyInfo(Structure):
    _fields_ = (
        ('sel', XfrmSelector),
        ('lft', XfrmLifetimeCfg),
        ('curlft', XfrmLifetimeCur),
        ('priority', c_uint32),
        ('index', c_uint32),
        ('dir', c_ubyte),
        ('action', c_ubyte),
        ('flags', c_ubyte),
        ('share', c_ubyte),
    )

class XfrmUserSaFlush(Structure):
    _fields_ = (
        ('proto', c_ubyte),
    )

class XfrmId(Structure):
    _fields_ = (
        ('daddr', XfrmAddress),
        ('spi', c_ubyte * 4),
        ('proto', c_ubyte),
    )
class XfrmUserTmpl(Structure):
    _fields_ = (
        ('id', XfrmId),
        ('family', c_uint16),
        ('saddr', XfrmAddress),
        ('reqid', c_uint32),
        ('mode', c_ubyte),
        ('share', c_ubyte),
        ('optional', c_ubyte),
        ('aalgos', c_uint32),
        ('ealgos', c_uint32),
        ('calgos', c_uint32),
    )

class XfrmStats(Structure):
    _fields_ = (
        ('replay_window', c_uint32),
        ('replay', c_uint32),
        ('integrity_failed', c_uint32),
    )

class XfrmUserSaInfo(Structure):
    _fields_ = (
        ('sel', XfrmSelector),
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
        ('flags', c_ubyte),
    )

class XfrmAlgo(Structure):
    _fields_ = (
        ('alg_name', c_ubyte * 64),
        ('alg_key_len', c_uint32),
        ('key', c_ubyte * 64)
    )

class XfrmUserSaId(Structure):
    _fields_ = (
        ('daddr', XfrmAddress),
        ('spi', c_ubyte * 4),
        ('family', c_uint16),
        ('proto', c_ubyte),
    )

_cipher_names = {
    None: b'none',
    Cipher.Id.ENCR_AES_CBC: b'aes'
}
_auth_names = {
    Integrity.Id.AUTH_HMAC_MD5_96: b'md5',
    Integrity.Id.AUTH_HMAC_SHA1_96: b'sha1'
}

def parse_attributes(data):
    attributes = defaultdict(list)
    while len(data) > 0:
        length, type = unpack_from('HH', data)
        attributes[type].append(data[4:length])
        data = data[length:]
    return attributes

def xfrm_send(command, flags, data):
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                         socket.NETLINK_XFRM)
    sock.bind((0, 0),)
    header = NetlinkHeader(length=sizeof(NetlinkHeader) + len(data),
                           type=command, seq=int(time.time()), pid=os.getpid(),
                           flags=flags)
    sock.send(bytes(header) + data)
    data = sock.recv(4096)
    result = defaultdict(list)
    while len(data) > 0:
        header = NetlinkHeader.parse(data)
        if header.type == NLMSG_ERROR:
            error_msg = NetlinkErrorMsg.parse(data[16:])
            if error_msg.error != 0:
                sock.close()
                raise NetlinkError(
                    'Received error header!: {}'.format(error_msg.error))
        result[header.type].append(data[sizeof(header):header.length])
        data = data[header.length:]
    sock.close()
    return result

def flush_policies():
    usersaflush = XfrmUserSaFlush(proto=0)
    payloads = xfrm_send(XFRM_MSG_FLUSHPOLICY, (NLM_F_REQUEST | NLM_F_ACK),
                         bytes(usersaflush))

def flush_sas():
    usersaflush = XfrmUserSaFlush(proto=0)
    payloads = xfrm_send(XFRM_MSG_FLUSHSA, (NLM_F_REQUEST | NLM_F_ACK),
                         bytes(usersaflush))

def create_byte_array(bytes, size=None):
    if size is None:
        size = len(bytes)
    fmt = c_ubyte * size
    return fmt(*bytes)

def Attribute(code, structure):
    class _internal(Structure):
        _fields_ = (
            ('len', c_uint16),
            ('code', c_uint16),
            ('data', type(structure))
        )
    return _internal(code=code, len=sizeof(_internal), data=structure)

def xfrm_create_policy(src_selector, dst_selector, src_port, dst_port,
                       ip_proto, dir, ipsec_proto, mode, src, dst):
    policy = XfrmUserPolicyInfo(
        sel = XfrmSelector(
            family = socket.AF_INET,
            daddr = XfrmAddress.from_ipaddr(dst_selector[0]),
            saddr = XfrmAddress.from_ipaddr(src_selector[0]),
            dport = dst_port,
            sport = src_port,
            dport_mask = 0 if dst_port == 0 else 0xFFFF,
            sport_mask = 0 if src_port == 0 else 0xFFFF,
            prefixlen_d = dst_selector.prefixlen,
            prefixlen_s = src_selector.prefixlen,
            proto = ip_proto),
        dir = dir,
        action = XFRM_POLICY_ALLOW,
        lft = XfrmLifetimeCfg(
            soft_byte_limit = 0xFFFFFFFFFFFFFFFF,
            hard_byte_limit = 0xFFFFFFFFFFFFFFFF,
            soft_packed_limit = 0xFFFFFFFFFFFFFFFF,
            hard_packet_limit = 0xFFFFFFFFFFFFFFFF,
            soft_add_expires_seconds = 2000,
            hard_add_expires_seconds = 2000,
            soft_use_expires_seconds = 2000,
            hard_use_expires_seconds = 2000),
    )
    tmpl = Attribute(
        XFRMA_TMPL,
        XfrmUserTmpl(
            id = XfrmId(
                daddr = XfrmAddress.from_ipaddr(dst),
                proto = (socket.IPPROTO_ESP if ipsec_proto == Proposal.Protocol.ESP
                         else socket.IPPROTO_AH)),
            family = socket.AF_INET,
            saddr = XfrmAddress.from_ipaddr(src),
            aalgos = 0xFFFFFFFF,
            ealgos = 0xFFFFFFFF,
            calgos = 0xFFFFFFFF,
            mode = mode))
    xfrm_send(XFRM_MSG_NEWPOLICY, (NLM_F_REQUEST | NLM_F_ACK),
              bytes(policy) + bytes(tmpl))

def xfrm_create_ipsec_sa(src_selector, dst_selector, src_port, dst_port, spi,
                         ip_proto, ipsec_proto, mode, src, dst, enc_algorith,
                         sk_e, auth_algorithm, sk_a):
    usersa = XfrmUserSaInfo(
        sel = XfrmSelector(
            family = socket.AF_INET,
            daddr = XfrmAddress.from_ipaddr(dst_selector[0]),
            saddr = XfrmAddress.from_ipaddr(src_selector[0]),
            dport = dst_port,
            sport = src_port,
            dport_mask = 0 if dst_port == 0 else 0xFFFF,
            sport_mask = 0 if src_port == 0 else 0xFFFF,
            prefixlen_d = dst_selector.prefixlen,
            prefixlen_s = src_selector.prefixlen,
            proto = ip_proto),
        id = XfrmId(
            daddr = XfrmAddress.from_ipaddr(dst),
            proto = (socket.IPPROTO_ESP if ipsec_proto == Proposal.Protocol.ESP
                     else socket.IPPROTO_AH),
            spi = create_byte_array(spi)),
        family = socket.AF_INET,
        saddr = XfrmAddress.from_ipaddr(src),
        mode = mode,
        lft = XfrmLifetimeCfg(
            soft_byte_limit = 0xFFFFFFFFFFFFFFFF,
            hard_byte_limit = 0xFFFFFFFFFFFFFFFF,
            soft_packed_limit = 0xFFFFFFFFFFFFFFFF,
            hard_packet_limit = 0xFFFFFFFFFFFFFFFF,
            soft_add_expires_seconds = 0,
            hard_add_expires_seconds = 0,
            soft_use_expires_seconds = 0,
            hard_use_expires_seconds = 0),
    )

    attribute_data = bytes()
    if ipsec_proto == Proposal.Protocol.ESP:
        enc_attr =  Attribute(
            XFRMA_ALG_CRYPT,
            XfrmAlgo(alg_name=create_byte_array(_cipher_names[enc_algorith], 64),
                     alg_key_len=len(sk_e) * 8,
                     key=create_byte_array(sk_e, 64)))
        attribute_data += enc_attr

    attribute = Attribute(
        XFRMA_ALG_AUTH,
        XfrmAlgo(
            alg_name=create_byte_array(_auth_names[auth_algorithm], 64),
            alg_key_len=len(sk_a) * 8,
            key=create_byte_array(sk_a, 64)))
    attribute_data += attribute

    xfrm_send(XFRM_MSG_NEWSA,
         (NLM_F_REQUEST | NLM_F_ACK),
         bytes(usersa) + attribute_data)

def delete_sa(daddr, proto, spi):
    xfrm_id = XfrmUserSaId(
        daddr = XfrmAddress.from_ipaddr(daddr),
        family = socket.AF_INET,
        proto = (socket.IPPROTO_ESP if proto == Proposal.Protocol.ESP
                 else socket.IPPROTO_AH),
        spi = create_byte_array(spi))
    try:
        xfrm_send(XFRM_MSG_DELSA, (NLM_F_REQUEST | NLM_F_ACK), bytes(xfrm_id))
    except NetlinkError as ex:
        logging.error('Could not delete IPsec SA with SPI: {}. {}'
                      ''.format(hexstring(spi), ex))

def create_policies(my_addr, peer_addr, ike_conf):
    for ipsec_conf in ike_conf['protect']:
        if ipsec_conf['mode'] == Mode.TUNNEL:
            src_selector = ipsec_conf['my_subnet']
            dst_selector = ipsec_conf['peer_subnet']
        else:
            src_selector = ip_network(my_addr)
            dst_selector = ip_network(peer_addr)

        xfrm_create_policy(src_selector, dst_selector, ipsec_conf['my_port'],
                           ipsec_conf['peer_port'], ipsec_conf['ip_proto'],
                           XFRM_POLICY_OUT, ipsec_conf['ipsec_proto'],
                           ipsec_conf['mode'], my_addr, peer_addr)
        xfrm_create_policy(dst_selector, src_selector, ipsec_conf['peer_port'],
                           ipsec_conf['my_port'], ipsec_conf['ip_proto'],
                           XFRM_POLICY_IN, ipsec_conf['ipsec_proto'],
                           ipsec_conf['mode'], peer_addr, my_addr)
        xfrm_create_policy(dst_selector, src_selector, ipsec_conf['peer_port'],
                           ipsec_conf['my_port'], ipsec_conf['ip_proto'],
                           XFRM_POLICY_FWD, ipsec_conf['ipsec_proto'],
                           ipsec_conf['mode'], peer_addr, my_addr)

def create_sa(src, dst, src_sel, dst_sel, ipsec_protocol, spi,
                    enc_algorith, sk_e, auth_algorithm, sk_a, mode):
    xfrm_create_ipsec_sa(src_sel.get_network(), dst_sel.get_network(),
                         src_sel.get_port(), dst_sel.get_port(), spi,
                         src_sel.ip_proto, ipsec_protocol, mode, src, dst,
                         enc_algorith, sk_e, auth_algorithm, sk_a)
