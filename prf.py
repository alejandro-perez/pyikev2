#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines PRF primitives
"""
__author__ = 'Alejandro Perez <alex@um.es>'

from hmac import HMAC
import hashlib
from struct import pack
from helpers import SafeIntEnum


class Prf(object):
    class Id(SafeIntEnum):
        PRF_HMAC_MD5 = 1
        PRF_HMAC_SHA1 = 2
        PRF_HMAC_TIGER = 3

    _hasher_dict = {
        Id.PRF_HMAC_MD5: hashlib.md5,
        Id.PRF_HMAC_SHA1: hashlib.sha1
    }

    def __init__(self, transform_id):
        self.transform_id = transform_id
        self.hasher = self._hasher_dict[transform_id]

    def prf(self, key, data):
        m = HMAC(key, data, digestmod=self.hasher)
        return m.digest()

    def prfplus(key, data, n):
        result = bytes()
        prev = bytes()
        round = 1
        while len(result) < n:
            prev = prf(key, prev + data + pack("!B", round))
            result += prev
            round += 1
        return result[:n]
