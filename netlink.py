#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines a simplistic Netlink framework
"""
import os
import socket
import time
from ctypes import memmove, Structure, sizeof, addressof, Array, c_uint32, c_uint16, c_int
from struct import unpack_from

# Flags
import logging

NLM_F_REQUEST = 0x0001
NLM_F_MULTI = 0x0002
NLM_F_ACK = 0x0004
NLM_F_ROOT = 0x0100
NLM_F_MATCH = 0x0200
NLM_F_ATOMIC = 0x0400
NLM_F_DUMP = (NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH)

# netlink payload types
NLMSG_ERROR = 0x02
NLMSG_DONE = 0x03


class NetlinkError(Exception):
    pass


class NetlinkStructure(Structure):
    @classmethod
    def parse(cls, data):
        result = cls()
        fit = min(len(data), sizeof(cls))
        memmove(addressof(result), data, fit)
        return result

    def to_dict(self):
        result = {}
        for name, _ in self._fields_:
            obj = getattr(self, name)
            if hasattr(obj, 'to_dict'):
                result[name] = obj.to_dict()
            elif isinstance(obj, Array):
                result[name] = str(list(obj))
            else:
                result[name] = getattr(self, name)
        return result


class NetlinkHeader(NetlinkStructure):
    _fields_ = (('length', c_uint32),
                ('type', c_uint16),
                ('flags', c_uint16),
                ('seq', c_uint32),
                ('pid', c_uint32))


class NetlinkErrorMsg(NetlinkStructure):
    _fields_ = (('error', c_int),
                ('msg', NetlinkHeader))


class NetlinkProtocol(object):
    attribute_types = {}
    payload_types = {NLMSG_ERROR: NetlinkErrorMsg}
    netlink_family = None

    @classmethod
    def _get_socket(cls, bind_groups):
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, cls.netlink_family)
        sock.bind((0, bind_groups))
        return sock

    @staticmethod
    def _attribute_factory(code, data):
        class _Internal(NetlinkStructure):
            _fields_ = (
                ('len', c_uint16),
                ('code', c_uint16),
                ('data', type(data)),
            )

        return _Internal(code=code, len=sizeof(_Internal), data=data)

    @classmethod
    def _parse_attributes(cls, data):
        attributes = {}
        while len(data) > 4:
            length, attr_type = unpack_from('HH', data)
            # sometimes we just receive a lot of 0s and need to ignore them
            if length == 0:
                break
            try:
                attributes[attr_type] = cls.attribute_types[attr_type].parse(data[4:length])
            except KeyError:
                pass
            data = data[length:]
        return attributes

    @classmethod
    def parse_message(cls, data):
        header = NetlinkHeader.parse(data)
        payload = None
        attributes = {}
        # NLMSG_DONE does not have payload nor attributes
        if header.type != NLMSG_DONE:
            try:
                payload = cls.payload_types[header.type].parse(data[sizeof(header):])
                attributes = cls._parse_attributes(data[sizeof(header) + sizeof(payload):header.length])
            except KeyError:
                logging.warning('Unknown Netlink payload type: {}'.format(header.type))
                pass

        return header, payload, attributes

    @classmethod
    def send_recv(cls, payload_type, flags, payload, attributes=None):
        data = bytearray(payload)
        if attributes:
            for attribute_type, attribute_value in attributes.items():
                attr = cls._attribute_factory(attribute_type, attribute_value)
                data += bytes(attr)
        header = NetlinkHeader(length=sizeof(NetlinkHeader) + len(data), type=payload_type,
                               seq=int(time.time()), pid=os.getpid(), flags=flags)
        sock = cls._get_socket(0)
        sock.send(bytes(header) + data)
        data = sock.recv(4096)
        sock.close()
        responses = []
        while len(data) > 0:
            header, payload, attributes = cls.parse_message(data)
            if header.type == NLMSG_ERROR and payload.error != 0:
                raise NetlinkError('Received error header!: {}'.format(os.strerror(-payload.error)))
            if header.type == NLMSG_DONE:
                break
            data = data[header.length:]
            responses.append((header, payload, attributes),)
        return responses
