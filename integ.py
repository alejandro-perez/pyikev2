#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines INTEG primitives
"""

from helpers import SafeIntEnum

class Integrity:
    class Id(SafeIntEnum):
        INTEG_NONE = 0
        AUTH_HMAC_MD5_96 = 1
        AUTH_HMAC_SHA1_96 = 2
        AUTH_DES_MAC = 3
        AUTH_KPDK_MD5 = 4
        AUTH_AES_XCBC_96 = 5
