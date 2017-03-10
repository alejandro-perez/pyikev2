#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines INTEG primitives
"""

from hmac import HMAC
import hashlib
from helpers import SafeIntEnum

class Integrity:
    class Id(SafeIntEnum):
        INTEG_NONE = 0
        AUTH_HMAC_MD5_96 = 1
        AUTH_HMAC_SHA1_96 = 2
        AUTH_DES_MAC = 3
        AUTH_KPDK_MD5 = 4
        AUTH_AES_XCBC_96 = 5

    _digestmod_dict = {
        Id.AUTH_HMAC_MD5_96: hashlib.md5,
        Id.AUTH_HMAC_SHA1_96: hashlib.sha1
    }

    def __init__(self, transform_id):
        self.hasher = self._digestmod_dict[transform_id]

    @property
    def key_size(self):
        return self.hasher().digest_size

    @property
    def hash_size(self):
        # return self.hasher().digest_size
        # Hardcoded as we only support _96 algorithms
        return 96 // 8

    def compute(self, key, data):
        m = HMAC(key, data, digestmod=self.hasher)
        # Hardcoded as we only support _96 algorithms
        return m.digest()[:12]
