#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines test for the crypto primitives.
"""
import unittest

from crypto import Prf, Cipher, DiffieHellman, Integrity, RsaPrivateKey, RsaPublicKey
from message import Transform

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class TestCrypto(unittest.TestCase):
    def test_dh(self):
        dh1 = DiffieHellman(14)
        dh2 = DiffieHellman(14)
        dh1.compute_secret(dh2.public_key)
        dh2.compute_secret(dh1.public_key)
        self.assertEqual(dh1.shared_secret, dh2.shared_secret)

    def test_encr(self):
        transform = Transform(Transform.Type.ENCR, Transform.EncrId.ENCR_AES_CBC, 256)
        cipher = Cipher(transform)
        iv = cipher.generate_iv()
        original = b'Hello this is a long message' * cipher.block_size
        ciphertext = cipher.encrypt(b'Mypassword121111' * 2, iv, original)
        decrypted = cipher.decrypt(b'Mypassword121111' * 2, iv, ciphertext)
        decrypted2 = cipher.decrypt(b'Mypassword121112' * 2, iv, ciphertext)

        self.assertEqual(cipher.block_size, 16)
        self.assertEqual(cipher.key_size, 32)
        self.assertEqual(original, decrypted)
        self.assertNotEqual(ciphertext, decrypted)
        self.assertNotEqual(decrypted, decrypted2)

    def test_prf(self):
        prf = Prf(Transform(Transform.Type.PRF, Transform.PrfId.PRF_HMAC_SHA1))
        digest = prf.prf(b'supersecret', b'This is a long message')
        prfplus = prf.prfplus(b'supersecret', b'This is a long message', 100)
        self.assertEqual(digest,
                         b']e\xed\xc7\xa7\xa7\xc1\xc3\x11\xaa\x19\x1c]\xeb\xbc'
                         b'\xeb-\xad\xbc\xd6')
        self.assertEqual(prfplus,
                         b'\xdbeb\x11F\xbf\xf2Y\xadC\xbd\xba\xc4\xe9\xdd\xf2'
                         b'\x10\x82\r\xd5\x85\xa6h2l\xcf\x98\xc9$\xd6\xc2\xc7'
                         b'\x12BJ\x0bi\xfd.w\xa2\x11\\\xf0\x89\xd5\x06\xcd\xf4'
                         b'\x81PH\x01\xbf\x95\xb0b\xe6J\x8cT\xab\x93L\xe5\x07'
                         b'\x86\xc0\xaa\x1a/\xb8J\xbfC\x85T\xb5\x1ddm{\x1cCqfx'
                         b'\x0f[\xb1\xd3\'\t\x92\\\xb9\xd7(SS')

    def test_integrity(self):
        integrity = Integrity(Transform(Transform.Type.INTEG, Transform.IntegId.AUTH_HMAC_SHA2_512_256))
        checksum = integrity.compute(b'supersecret', b'This is a long message')
        self.assertEqual(checksum,
                         b'\x0e\xb2\x8a\xa0N\x14\x0b$\x9a\x8c/\x9d<\x83\xd2\xf8\x94\x12\x1a\xbc\xd4b~\xd5\xd0\xa5\x02-\x0f\x8fcC')


class TestRsa(unittest.TestCase):
    def test_sign(self):
        data = b'adfasdfskjfsldaf'
        private_key = RsaPrivateKey(b'''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDEkT4cscvAVzUjuK4rsCvETPixVfGGep/hUBcHnZyxN7XiFmaO
EdE+W4TZ9EZy06W83qPfSYJrKt9n++mlFNWYgFsRtFMsP0X9Z6c7QBTt684+NRZ6
Te4Jyv/VrKxN/mCSufdQ88s6Wa/KhV8JiWvYs1l+sEuNUHHDSswFehNOFQIDAQAB
AoGAQDmIhs2c2hJkXXCJD+M22aOgmiiPirXkKTUG4UkhGlIujlltVrwBlxNF/ASx
Q/FdNLG1703QW/2dExefBn4hL2jYObHAwFVGaiBLBEa0RzzkhHdQ0AE5Q0sPZL1w
MW6TbIvI7DkXlTb8A1TaVrgQLf3AAtBs/6VQj7SkvfctLV0CQQDu0+jYXPGxIXeM
QDCR2HzNu7IcvV0tyRqgToqFVf6tLFu60mX/kKgGPubcjU5qmU8D4Mqw3aEoJVs1
nDCZ8NarAkEA0rNyn7/Usf/yV+pyuzylUw++0tw5bGd+16R3xebdExj9tEARfGcQ
1KnmjeNGSbIN8se1lSYFqpjuu8R0BrNuPwJAaqDZ+J+mmPrkMQ4HoVYSgpgmcYZq
L6L17FSkq9s1FYQUgFiniW7AVemHkTjVpepEyOp4FHcfGJl1G35chJ5ueQJBAMv+
lxyZorkPf7eksp4bEkl/9hW6yBHvhfwMLTY61ZG24XMRkJxsQPxU3nZDM/sH279R
obmcjWHlHUZH5rnSIQsCQQCDGkbQJcDHS0bRSjVryAHZ8jQTTjTPBUAtHjzr4Xn0
IFf9L0pXd5MDpf5FhuOofyKzFYd08dMG1J/hm6DLFX0F
-----END RSA PRIVATE KEY-----''')
        signature = private_key.sign(data)

        public_key = RsaPublicKey(b'''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEkT4cscvAVzUjuK4rsCvETPix
VfGGep/hUBcHnZyxN7XiFmaOEdE+W4TZ9EZy06W83qPfSYJrKt9n++mlFNWYgFsR
tFMsP0X9Z6c7QBTt684+NRZ6Te4Jyv/VrKxN/mCSufdQ88s6Wa/KhV8JiWvYs1l+
sEuNUHHDSswFehNOFQIDAQAB
-----END PUBLIC KEY-----''')

        print(len(signature))
        self.assertTrue(public_key.verify(signature, data))


if __name__ == '__main__':
    unittest.main()
