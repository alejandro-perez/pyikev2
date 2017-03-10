#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines ENC primitives
"""

from helpers import SafeIntEnum

class Cipher:
    class Id(SafeIntEnum):
        ENCR_DES_IV64 = 1
        ENCR_DES = 2
        ENCR_3DES = 3
        ENCR_RC5 = 4
        ENCR_IDEA = 5
        ENCR_CAST = 6
        ENCR_BLOWFISH = 7
        ENCR_3IDEA = 8
        ENCR_DES_IV32 = 9
        ENCR_NULL = 11
        ENCR_AES_CBC = 12
        ENCR_AES_CTR = 13
