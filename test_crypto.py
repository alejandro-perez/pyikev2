#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the crypto primitives.
"""
__author__ = 'Alejandro Perez <alex@um.es>'

import unittest
from prf import Prf
from encr import Cipher
from integ import Integrity
from dh import DiffieHellman
from helpers import hexstring

class TestCrypto(unittest.TestCase):
    def test_dh(self):
        dh1 = DiffieHellman(5)
        dh2 = DiffieHellman(5)
        dh1.compute_secret(dh2.public_key)
        dh2.compute_secret(dh1.public_key)
        self.assertEqual(dh1.shared_secret, dh2.shared_secret)

    def test_encr(self):
        cipher = Cipher(Cipher.Id.ENCR_AES_CBC, 256)
        iv = cipher.generate_iv()
        original = b'Hello this is a long message' * cipher.block_size
        ciphertext = cipher.encrypt(b'Mypassword121111'*2, iv, original)
        decrypted = cipher.decrypt(b'Mypassword121111'*2, iv, ciphertext)
        decrypted2 = cipher.decrypt(b'Mypassword121112'*2, iv, ciphertext)

        self.assertEqual(cipher.block_size, 16)
        self.assertEqual(cipher.key_size, 32)
        self.assertEqual(original, decrypted)
        self.assertNotEqual(ciphertext, decrypted)
        self.assertNotEqual(decrypted, decrypted2)

    def test_prf(self):
        prf = Prf(Prf.Id.PRF_HMAC_SHA1)
        digest = prf.prf(b'supersecret', b'This is a long message')
        prfplus = prf.prfplus(b'supersecret', b'This is a long message', 100)
        self.assertEqual(digest, b']e\xed\xc7\xa7\xa7\xc1\xc3\x11\xaa\x19\x1c]\xeb\xbc\xeb-\xad\xbc\xd6')
        self.assertEqual(prfplus, b"\xdbeb\x11F\xbf\xf2Y\xadC\xbd\xba\xc4\xe9\xdd\xf2\x10\x82\r\xd5\x85"
            b"\xa6h2l\xcf\x98\xc9$\xd6\xc2\xc7\x12BJ\x0bi\xfd.w\xa2\x11\\\xf0\x89\xd5\x06\xcd\xf4\x81PH\x01\xbf"
            b"\x95\xb0b\xe6J\x8cT\xab\x93L\xe5\x07\x86\xc0\xaa\x1a/\xb8J\xbfC\x85T\xb5\x1ddm{\x1cCqfx"
            b"\x0f[\xb1\xd3'\t\x92\\\xb9\xd7(SS")


if __name__ == '__main__':
    unittest.main()
