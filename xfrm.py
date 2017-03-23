#!/usr/bin/python

# list policies

import socket
from ipaddress import ip_address
from struct import pack, unpack, unpack_from, calcsize
from helpers import hexstring
import time
import pprint
import os
from collections import defaultdict

NLM_F_REQUEST    = 0x0001
NLM_F_MULTI      = 0x0002
NLM_F_ACK        = 0x0004
NLM_F_ROOT       = 0x0100
NLM_F_MATCH      = 0x0200
NLM_F_ATOMIC     = 0x0400

NLM_F_DUMP       = (NLM_F_REQUEST|NLM_F_ROOT|NLM_F_MATCH)

NLMSG_ERROR      = 0x0002
NLMSG_DONE       = 0x0003

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

XFRM_POLICY_TYPE_MAIN   = 0
XFRM_POLICY_TYPE_SUB    = 1
XFRM_POLICY_TYPE_MAX    = 2
XFRM_POLICY_TYPE_ANY    = 255

XFRM_MODE_TRANSPORT = 0
XFRM_MODE_TUNNEL = 1

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
                offset += format_.size()
        return cls(**args)

    @classmethod
    def size(cls):
        count = 0
        for name, format_, default in cls._members:
            if type(format_) is str:
                count += calcsize(format_)
            else:
                count += format_.size()
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
        ('soft_byte_limit', 'L', 2000),
        ('hard_byte_limit', 'L', 2000),
        ('soft_packed_limit', 'L', 2000),
        ('hard_packet_limit', 'L', 2000),
        ('soft_add_expires_seconds', 'L', 2000),
        ('hard_add_expires_seconds', 'L', 2000),
        ('soft_use_expires_seconds', 'L', 2000),
        ('hard_use_expires_seconds', 'L', 2000),
    )

class XfrmLifetimeCur(NetlinkObject):
    _members = (
        ('bytes', 'L', 0),
        ('packets', 'L', 0),
        ('add_time', 'L', 0),
        ('use_time', 'L', 0),
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

class XfrmUserPolicyType(NetlinkObject):
    _members = (
        ('type', 'B', 0),
        ('reserved1', 'I', 0),
        ('reserved2', 'B', 0),
    )

class XfrmUserSaFlush(NetlinkObject):
    _members = (
        ('proto', 'B', 255),
    )

class XfrmId(NetlinkObject):
    _members = (
        ('daddr', XfrmAddress, XfrmAddress()),
        ('spi', '>I', 0),
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

def xfrm_send(command, flags, attribute_data):
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_XFRM)
    sock.bind((0, 0),)
    seq = int(time.time())
    header = NetlinkHeader(length=16 + len(attribute_data),
                       type=command, seq=seq, pid=os.getpid(), flags=flags)
    sock.send(header.to_bytes() + attribute_data)
    data = sock.recv(4096)
    response_attribute_data = defaultdict(list)
    while len(data) > 0:
        header = NetlinkHeader.parse(data)
        if header.type == NLMSG_ERROR:
            error_msg = NetlinkErrorMsg.parse(data[16:])
            if error_msg.error == 0:
                break
            raise NetlinkError(
                'Received error header!: {}'.format(error_msg.error))
        elif header.type == NLMSG_DONE:
            break
        response_attribute_data[header.type].append(data[16:header.length])
        data = data[header.length:]
    sock.close()
    return response_attribute_data

def xfrm_flush_policies():
    xfrm_send(command=XFRM_MSG_FLUSHPOLICY, flags=NLM_F_REQUEST | NLM_F_ACK,
                attribute_data=XfrmUserSaFlush(proto=255).to_bytes())

def xfrm_print_policies():
    response = xfrm_send(command=XFRM_MSG_GETPOLICY, flags=(NLM_F_REQUEST | NLM_F_DUMP),
                           attribute_data=XfrmUserPolicyId().to_bytes())
    # read policies
    for policy_data in response[XFRM_MSG_NEWPOLICY]:
        print("DATA", len(policy_data), "ASSUMED", XfrmUserPolicyInfo.size())
        policy = XfrmUserPolicyInfo.parse(policy_data)
        pprint.pprint(policy.to_dict())
        offset = XfrmUserPolicyInfo.size()
        while offset < len(policy_data):
            l, t = unpack_from('HH', policy_data, offset)
            print("T:", t, "L:", l)
            if l == 0 and t == 0:
                print("AA")
                offset += 4
                continue
            tmpl = XfrmUserTmpl.parse(policy_data[offset+4:offset+l])
            pprint.pprint(tmpl.to_dict())
            print(ip_address(tmpl.id.daddr.addr[:4]))
            print(ip_address(policy.sel.saddr.addr[:4]))
            break
            offset += l


xfrm_print_policies()

# policy = XfrmUserPolicyInfo(
#     sel = XfrmSelector(
#         daddr=XfrmAddress(addr=ip_address('192.168.1.1').packed + b'0'*12),
#         saddr=XfrmAddress(addr=ip_address('192.168.1.2').packed + b'0'*12),
#         family=socket.AF_INET, prefixlen_s=32, prefixlen_d=32),
# )


# data = XfrmUserPolicyInfo().to_bytes() + XfrmUserPolicyType().to_bytes()
# xfrm_send(command=XFRM_MSG_NEWPOLICY, flags=NLM_F_REQUEST | NLM_F_ACK,
#                 attribute_data=data)

