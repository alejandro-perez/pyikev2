#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines ENC primitives
"""

from helpers import SafeIntEnum

import os
from cryptography.hazmat.primitives.ciphers import Cipher as cypher, algorithms, modes
import cryptography.hazmat.backends.openssl.backend

class EncrError(Exception):
    pass

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

    _algorithm_dict = {
        Id.ENCR_AES_CBC: algorithms.AES,
        Id.ENCR_3DES: algorithms.TripleDES,
    }

    _backend = cryptography.hazmat.backends.openssl.backend

    def __init__(self, transform_id, negotiated_keylen):
        self._algorithm = self._algorithm_dict[transform_id]
        self.negotiated_keylen = negotiated_keylen

    @property
    def block_size(self):
        return self._algorithm.block_size // 8

    @property
    def key_size(self):
        return (self.negotiated_keylen or self._algorithm.key_sizes[0]) // 8

    def encrypt(self, key, iv, data):
        if len(key) != self.key_size:
            raise EncrError('Key must be of the indicated size {}'.format(self.key_size))
        cyph = cypher(self._algorithm(key), modes.CBC(iv), backend=self._backend)
        encryptor = cyph.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, key, iv, data):
        if len(key) != self.key_size:
            raise EncrError('Key must be of the indicated size {}'.format(self.key_size))
        cyph = cypher(self._algorithm(key), modes.CBC(iv), backend=self._backend)
        decryptor = cyph.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def generate_iv(self):
        return os.urandom(self.block_size)
