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

NLM_F_REQUEST    = 1
NLM_F_MULTI      = 2
NLM_F_ACK        = 4

NLM_F_ROOT       = 0x0100
NLM_F_MATCH      = 0x0200
NLM_F_ATOMIC     = 0x0400
NLM_F_DUMP       = (NLM_F_ROOT|NLM_F_MATCH)

NLMSG_ERROR      = 0x0002
NLMSG_DONE       = 0x0003

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
        ('error', 'I', 0),
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
        ('soft_byte_limit', 'L', 0),
        ('hard_byte_limit', 'L', 0),
        ('soft_packed_limit', 'L', 0),
        ('hard_packet_limit', 'L', 0),
        ('soft_add_expires_seconds', 'L', 0),
        ('hard_add_expires_seconds', 'L', 0),
        ('soft_use_expires_seconds', 'L', 0),
        ('hard_use_expires_seconds', 'L', 0),
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


class XfrmUserSaFlush(NetlinkObject):
    _members = (
        ('proto', 'B', 255),
    )


def nl_sendrecv(command, flags, attribute_data):
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
            raise NetlinkError('Received error header!')
        elif header.type == NLMSG_DONE:
            break
        response_attribute_data[header.type].append(data[16:])
        data = data[header.length:]
    sock.close()
    return response_attribute_data


response = nl_sendrecv(command=XFRM_MSG_GETPOLICY, flags=(NLM_F_REQUEST | NLM_F_DUMP),
                       attribute_data=XfrmUserPolicyId().to_bytes())

# read policies
for policy_data in response[XFRM_MSG_NEWPOLICY]:
    policy = XfrmUserPolicyInfo.parse(policy_data)
    pprint.pprint(policy.to_dict())

response = nl_sendrecv(command=XFRM_MSG_FLUSHPOLICY, flags=NLM_F_REQUEST | NLM_F_ACK,
                        attribute_data=XfrmUserSaFlush(proto=255).to_bytes())


# print("BB")
# pprint.pprint(response)
# sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_XFRM)
# sock.bind((0, 0),)

# header = NetlinkHeader(length=NetlinkHeader.size() + XfrmUserPolicyId.size(),
#                        type=XFRM_MSG_GETPOLICY, seq=100, pid=0,
#                        flags=(NLM_F_REQUEST | NLM_F_DUMP))

# nlmsg = header.to_bytes() + XfrmUserPolicyId().to_bytes()
# sock.send(nlmsg)
# data = sock.recv(4096)
# done = False
# print("AAA", len(nlmsg))
# while not done and len(data) > 0:
#     header = NetlinkHeader.parse(data)
#     if header.type == NLMSG_ERROR:
#         print("ERROR")
#     elif header.type == XFRM_MSG_NEWPOLICY:
#         print("POLICY")
#         policy = XfrmUserPolicyInfo.parse(data[header.size():])
#         pprint.pprint(policy.to_dict())
#     else:
#         print("UNKNOWN HEADER")
#     if len(data) - header.length <= 0 or header.type in (NLMSG_DONE, NLMSG_ERROR):
#         done = True
#     else:
#         data = data[header.length:]



# print(response)


# response = nl_sendrecv(command=XFRM_MSG_FLUSHPOLICY, flags=NLM_F_REQUEST,
#                        attribute_data=XfrmUserSaFlush(proto=255).to_bytes())





# responses = []
# response = cstruct_unpack(NLMSGHDR, sfd.read(ctypes.sizeof(NLMSGHDR)))
# while response.type != NLMSG_DONE:
#     if response.type == NLMSG_ERROR:
#         break
#     response_data = sfd.read(response.len - 16)
#     responses.append(response_data)
#     response = cstruct_unpack(NLMSGHDR, sfd.read(ctypes.sizeof(NLMSGHDR)))
# sfd.close()
# sock.close()
# return responses
