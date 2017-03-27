#!/usr/bin/python

# list policies

import socket
from ipaddress import ip_address, ip_network
from struct import pack, unpack, unpack_from, calcsize
import time
import os
from collections import defaultdict
from message import Proposal
from crypto import Cipher, Integrity

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

# XFRM mode
XFRM_MODE_TRANSPORT = 0
XFRM_MODE_TUNNEL = 1

# XFRM groups
XFRMGRP_ACQUIRE     = 1
XFRMGRP_EXPIRE      = 2
XFRMGRP_SA          = 4
XFRMGRP_POLICY      = 8

XFRM_POLICY_ALLOW  = 0
XFRM_POLICY_BLOCK  = 1

class NetlinkError(Exception):
    pass

class NetlinkObject(object):
    """ Generic object representing a NetworkObject
    """
    def __init__(self, **kwargs):
        self._attributes = kwargs

    def to_bytes(self):
        result = bytes()
        for name, format_, default in self._members:
            if type(format_) is str:
                result += pack(format_, self._attributes.get(name, default))
            else:
                result += self._attributes.get(name, default).to_bytes()
        pad =  len(result) % 4
        if pad > 0:
            result += b'\0' * (4 - pad)
        return result

    @classmethod
    def parse(cls, data):
        args = {}
        offset = 0
        for name, format_, default in cls._members:
            if type(format_) is str:
                args[name] = unpack_from(format_, data, offset)[0]
                offset += calcsize(format_)
            else:
                args[name] = format_.parse(data[offset:])
                offset += format_.SIZEOF()
        return cls(**args)

    @classmethod
    def SIZEOF(cls):
        count = 0
        for name, format_, default in cls._members:
            if type(format_) is str:
                count += calcsize(format_)
            else:
                count += format_.SIZEOF()
        if count % 4 > 0:
            count += 4 - count % 4
        return count

    def __getattr__(self, key):
        return self._attributes[key]

    def to_dict(self):
        result = {}
        for name, format_, default in self._members:
            if type(format_) is str:
                result[name] = self._attributes.get(name, default)
            else:
                result[name] = self._attributes.get(name, default).to_dict()
        return result

    def to_attr_bytes(self, attribute_type):
        data = self.to_bytes()
        return pack('HH', len(data) + 4, attribute_type) + data

class NetlinkHeader(NetlinkObject):
    _members = (
        ('length', 'I', 0),
        ('type', 'H', 0),
        ('flags', 'H', 0),
        ('seq', 'I', 0),
        ('pid', 'I', 0),
    )

class NetlinkErrorMsg(NetlinkObject):
    _members = (
        ('error', 'i', 0),
        ('msg', NetlinkHeader, NetlinkHeader()),
    )

class XfrmAddress(NetlinkObject):
    _members = (
        ('addr', '16s', b''),
    )

class XfrmSelector(NetlinkObject):
    _members = (
        ('daddr', XfrmAddress, XfrmAddress()),
        ('saddr', XfrmAddress, XfrmAddress()),
        ('dport', '>H', 0),
        ('dport_mask', '>H', 0),
        ('sport', '>H', 0),
        ('sport_mask', '>H', 0),
        ('family', 'H', 0),
        ('prefixlen_d', 'B', 0),
        ('prefixlen_s', 'B', 0),
        ('proto', 'B', 0),
        ('ifindex', 'I', 0),
        ('user', 'I', 0),
    )

class XfrmUserPolicyId(NetlinkObject):
    _members = (
        ('selector', XfrmSelector, XfrmSelector()),
        ('index', 'I', 0),
        ('dir', 'B', 0),
    )

class XfrmLifetimeCfg(NetlinkObject):
    _members = (
        ('soft_byte_limit', 'Q', 0xFFFFFFFFFFFFFFFF),
        ('hard_byte_limit', 'Q', 0xFFFFFFFFFFFFFFFF),
        ('soft_packed_limit', 'Q', 0xFFFFFFFFFFFFFFFF),
        ('hard_packet_limit', 'Q', 0xFFFFFFFFFFFFFFFF),
        ('soft_add_expires_seconds', 'Q', 0),
        ('hard_add_expires_seconds', 'Q', 0),
        ('soft_use_expires_seconds', 'Q', 0),
        ('hard_use_expires_seconds', 'Q', 0),
    )

class XfrmLifetimeCur(NetlinkObject):
    _members = (
        ('bytes', 'Q', 0),
        ('packets', 'Q', 0),
        ('add_time', 'Q', 0),
        ('use_time', 'Q', 0),
    )

class XfrmUserPolicyInfo(NetlinkObject):
    _members = (
        ('sel', XfrmSelector, XfrmSelector()),
        ('lft', XfrmLifetimeCfg, XfrmLifetimeCfg()),
        ('curlft', XfrmLifetimeCur, XfrmLifetimeCur()),
        ('priority', 'I', 0),
        ('index', 'I', 0),
        ('dir', 'B', 0),
        ('action', 'B', 0),
        ('flags', 'B', 0),
        ('share', 'B', 0),
    )

class XfrmUserSaFlush(NetlinkObject):
    _members = (
        ('proto', 'B', 255),
    )

class XfrmId(NetlinkObject):
    _members = (
        ('daddr', XfrmAddress, XfrmAddress()),
        ('spi', '>4s', b''),
        ('proto', 'B', 0),
    )
class XfrmUserTmpl(NetlinkObject):
    _members = (
        ('id', XfrmId, XfrmId()),
        ('family', 'H', 0),
        ('saddr', XfrmAddress, XfrmAddress()),
        ('reqid', 'I', 0),
        ('mode', 'B', 0),
        ('share', 'B', 0),
        ('optional', 'B', 0),
        ('aalgos', 'I', 0),
        ('ealgos', 'I', 0),
        ('calgos', 'I', 0),
    )

class XfrmStats(NetlinkObject):
    _members = (
        ('replay_window', 'I', 0),
        ('replay', 'I', 0),
        ('integrity_failed', 'I', 0),
    )

class XfrmUserSaInfo(NetlinkObject):
    _members = (
        ('sel', XfrmSelector, XfrmSelector()),
        ('id', XfrmId, XfrmId()),
        ('saddr', XfrmAddress, XfrmAddress()),
        ('lft', XfrmLifetimeCfg, XfrmLifetimeCfg()),
        ('cur', XfrmLifetimeCur, XfrmLifetimeCur()),
        ('stats', XfrmStats, XfrmStats()),
        ('seq', 'I', 0),
        ('reqid', 'I', 0),
        ('family', 'H', 0),
        ('mode', 'B', 0),
        ('replay_window', 'B', 0),
        ('flags', 'B', 0),
    )

class XfrmAlgo(NetlinkObject):
    _members = (
        ('alg_name', '64s', b''),
        ('alg_key_len', 'I', 0),
        ('key', '64s', b'')
    )

class XfrmUserSaId(NetlinkObject):
    _members = (
        ('daddr', XfrmAddress, XfrmAddress()),
        ('spi', '>4s', b''),
        ('family', 'H', 0),
        ('proto', 'B', 0),
    )

def parse_attributes(data):
    attributes = defaultdict(list)
    while len(data) > 0:
        length, type = unpack_from('HH', data)
        # if 0,0, jump this one
        if length == 0 and type == 0:
            data = data[4:]
            continue
        attributes[type].append(data[4:length])
        data = data[length:]
    return attributes

def xfrm_send(command, flags, data):
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                         socket.NETLINK_XFRM)
    sock.bind((0, 0),)
    header = NetlinkHeader(length=NetlinkHeader.SIZEOF() + len(data),
                           type=command, seq=int(time.time()), pid=os.getpid(),
                           flags=flags)

    sock.send(header.to_bytes() + data)
    data = sock.recv(4096)
    result = defaultdict(list)
    while len(data) > 0:
        header = NetlinkHeader.parse(data[:header.SIZEOF()])
        if header.type == NLMSG_ERROR:
            error_msg = NetlinkErrorMsg.parse(data[16:])
            if error_msg.error != 0:
                sock.close()
                raise NetlinkError(
                    'Received error header!: {}'.format(error_msg.error))
        result[header.type].append(data[header.SIZEOF():header.length])
        data = data[header.length:]
    sock.close()
    return result

def xfrm_flush_policies():
    usersaflush = XfrmUserSaFlush(proto=0)
    payloads = xfrm_send(XFRM_MSG_FLUSHPOLICY, (NLM_F_REQUEST | NLM_F_ACK),
                         usersaflush.to_bytes())

def xfrm_flush_sa():
    usersaflush = XfrmUserSaFlush(proto=0)
    payloads = xfrm_send(XFRM_MSG_FLUSHSA, (NLM_F_REQUEST | NLM_F_ACK),
                         usersaflush.to_bytes())

def xfrm_create_policy(src_selector, dst_selector, src_port, dst_port,
                       ip_proto, dir, ipsec_proto, mode, src, dst):
    policy = XfrmUserPolicyInfo(
        sel = XfrmSelector(
            family = socket.AF_INET,
            daddr = XfrmAddress(addr=dst_selector[0].packed),
            saddr = XfrmAddress(addr=src_selector[0].packed),
            dport = dst_port,
            sport = src_port,
            dport_mask = 0 if dst_port else 255,
            sport_mask = 0 if src_port else 255,
            prefixlen_d = dst_selector.prefixlen,
            prefixlen_s = src_selector.prefixlen,
            proto = ip_proto
        ),
        dir = dir,
        action = XFRM_POLICY_ALLOW,
    )

    tmpl = XfrmUserTmpl(
        id = XfrmId(
            daddr = XfrmAddress(addr=dst.packed),
            proto = (socket.IPPROTO_ESP if ipsec_proto == Proposal.Protocol.ESP
                     else socket.IPPROTO_AH)
        ),
        family = socket.AF_INET,
        saddr = XfrmAddress(addr=src.packed),
        mode = mode,
    )

    xfrm_send(XFRM_MSG_NEWPOLICY,
             (NLM_F_REQUEST | NLM_F_ACK),
             policy.to_bytes()
                + pack('HH', 0, 0)
                + tmpl.to_attr_bytes(XFRMA_TMPL))

_cipher_names = {
    None: b'none',
    Cipher.Id.ENCR_AES_CBC: b'aes'
}
_auth_names = {
    Integrity.Id.AUTH_HMAC_MD5_96: b'md5',
    Integrity.Id.AUTH_HMAC_SHA1_96: b'sha1'
}

def xfrm_create_ipsec_sa(src_selector, dst_selector, src_port, dst_port, spi,
                         ip_proto, ipsec_proto, mode, src, dst, enc_algorith,
                         sk_e, auth_algorithm, sk_a):
    state = XfrmUserSaInfo(
        sel = XfrmSelector(
            family = socket.AF_INET,
            daddr = XfrmAddress(addr=dst_selector[0].packed),
            saddr = XfrmAddress(addr=src_selector[0].packed),
            dport = dst_port,
            sport = src_port,
            dmask = 0 if dst_port else 255,
            smask = 0 if src_port else 255,
            prefixlen_d = dst_selector.prefixlen,
            prefixlen_s = src_selector.prefixlen,
            proto = ip_proto
        ),
        id = XfrmId(
            daddr = XfrmAddress(addr=dst.packed),
            proto = (socket.IPPROTO_ESP if ipsec_proto == Proposal.Protocol.ESP
                     else socket.IPPROTO_AH),
            spi = spi
        ),
        family = socket.AF_INET,
        saddr = XfrmAddress(addr=src.packed),
        mode = mode,
    )

    attribute_data = bytes()

    if ipsec_proto == Proposal.Protocol.ESP:
        attribute_data += XfrmAlgo(
                alg_name=_cipher_names[enc_algorith],
                alg_key_len=len(sk_e) * 8, key=sk_e
           ).to_attr_bytes(XFRMA_ALG_CRYPT)

    attribute_data += XfrmAlgo(
            alg_name=_auth_names[auth_algorithm],
            alg_key_len=len(sk_a) * 8, key=sk_a
        ).to_attr_bytes(XFRMA_ALG_AUTH)


    print(state.SIZEOF())
    xfrm_send(XFRM_MSG_NEWSA,
         (NLM_F_REQUEST | NLM_F_ACK),
         (state.to_bytes()
            + pack('HH', 0, 0)
            + attribute_data))


xfrm_create_ipsec_sa(
    src_selector=ip_network('192.168.1.0/24'),
    dst_selector=ip_network('10.0.0.0/24'),
    src_port=100,
    dst_port=0,
    spi=b'1234',
    ip_proto=socket.IPPROTO_TCP,
    ipsec_proto=Proposal.Protocol.AH,
    mode=XFRM_MODE_TRANSPORT,
    src=ip_address('19.1.1.1'),
    dst=ip_address('20.1.2.3'),
    enc_algorith=Cipher.Id.ENCR_AES_CBC,
    sk_e=b'1' * 16,
    auth_algorithm=Integrity.Id.AUTH_HMAC_SHA1_96,
    sk_a=b'2' * 16
)
