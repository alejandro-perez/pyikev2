#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines PRF primitives
"""
__author__ = 'Alejandro Perez <alex@um.es>'

from hmac import HMAC
import hashlib
from helpers import SafeIntEnum


class Prf(object):
    class Id(SafeIntEnum):
        PRF_HMAC_MD5 = 1
        PRF_HMAC_SHA1 = 2
        PRF_HMAC_TIGER = 3

    _digestmod_dict = {
        Id.PRF_HMAC_MD5: hashlib.md5,
        Id.PRF_HMAC_SHA1: hashlib.sha1
    }

    def __init__(self, transform_id):
        self.hasher = self._digestmod_dict[transform_id]

    @property
    def key_size(self):
        return self.hash_size

    @property
    def hash_size(self):
        return self.hasher().digest_size

    def prf(self, key, data):
        m = HMAC(key, data, digestmod=self.hasher)
        return m.digest()

    def prfplus(self, key, seed, size):
        result = bytes()
        temp = bytes()
        i = 1
        while len(result) < size:
            temp = self.prf(key, temp + seed + i.to_bytes(1, 'big'))
            result += temp
            i += 1
        return result[:size]
