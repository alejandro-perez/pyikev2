#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines cryptographic classes
"""

import hashlib
import os
from hmac import HMAC

import cryptography.hazmat.backends.openssl.backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes
from cryptography import x509

from message import Transform, InvalidSyntax

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class EncrError(Exception):
    pass


class Prf(object):
    _digestmod_dict = {
        Transform.PrfId.PRF_HMAC_SHA1: hashlib.sha1,
        Transform.PrfId.PRF_HMAC_SHA2_256: hashlib.sha256,
        Transform.PrfId.PRF_HMAC_SHA2_512: hashlib.sha512,
    }

    def __init__(self, transform):
        assert(transform.type == Transform.Type.PRF)
        self.hasher = self._digestmod_dict[transform.id]

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


class Cipher:
    _algorithm_dict = {
        Transform.EncrId.ENCR_AES_CBC: algorithms.AES,
    }

    _backend = cryptography.hazmat.backends.openssl.backend

    def __init__(self, transform):
        assert(transform.type == Transform.Type.ENCR)
        self._algorithm = self._algorithm_dict[transform.id]
        self._transform = transform
        # establish whether transform.keylen attribute is valid
        if self._transform.keylen is not None:
            if len(self._algorithm.key_sizes) == 1:
                raise InvalidSyntax(
                    f'Algorithm {self._algorithm.name} only accepts one keylen but KEY_LEN attribute is provided.')
            if transform.keylen not in self._algorithm.key_sizes:
                raise InvalidSyntax(f'Incorrect key length {transform.keylen} for algorithm {self._algorithm.name}. '
                                    f'Acceptable values are: {self._algorithm.key_sizes}')
        elif len(self._algorithm.key_sizes) > 1:
            raise('Algorithm {} requires a KEY_LEN attribute'.format(self._algorithm.name))

    @property
    def block_size(self):
        return self._algorithm.block_size // 8

    @property
    def key_size(self):
        # if no KEYLEN attribute is present, return the first possible one
        return (self._transform.keylen or self._algorithm.key_sizes[0]) // 8

    def encrypt(self, key, iv, data):
        if len(key) != self.key_size:
            raise EncrError('Key must be of the indicated size {}'.format(self.key_size))
        _cipher = _Cipher(self._algorithm(key), modes.CBC(iv), backend=self._backend)
        encryptor = _cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, key, iv, data):
        if len(key) != self.key_size:
            raise EncrError('Key must be of the indicated size {}'.format(self.key_size))
        _cipher = _Cipher(self._algorithm(key), modes.CBC(iv), backend=self._backend)
        decryptor = _cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def generate_iv(self):
        return os.urandom(self.block_size)


class MODPDH:
    _group_dict = {
        Transform.DhId.DH_1: # MODP768
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF',
        Transform.DhId.DH_2: # MODP1024
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF',
        Transform.DhId.DH_14: # MODP2048
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',

        Transform.DhId.DH_15: # MODP3072
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CB'
            'A64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA'
            '06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108'
            'E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',

        Transform.DhId.DH_16: # MODP4096
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CB'
            'A64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA'
            '06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108'
            'E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB'
            '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD'
            '0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF',

        Transform.DhId.DH_17: # MODP6144
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CB'
            'A64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA'
            '06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108'
            'E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB'
            '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD'
            '0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763D'
            'BA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7'
            'F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F4698'
            '0C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5'
            'ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C04'
            '68043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF',

        Transform.DhId.DH_18: # MODP8192
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
            '83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
            '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
            'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C'
            'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7'
            '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6'
            '287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9'
            '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD'
            'F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B'
            'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6'
            'D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA'
            'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C'
            'DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4'
            '38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568'
            '3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B'
            '4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36'
            '4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92'
            '4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71'
            '60C980DD98EDD3DFFFFFFFFFFFFFFFFF',
    }

    backend = cryptography.hazmat.backends.openssl.backend

    def __init__(self, group):
        self.group = group
        self.key_len = len(self._group_dict[group]) // 2
        module = int(self._group_dict[self.group], 16)
        self._pn = dh.DHParameterNumbers(module, 2)
        self._parameters = self._pn.parameters(self.backend)
        self.shared_secret = None
        self._private_key = self._parameters.generate_private_key()
        public_key_int = self._private_key.public_key().public_numbers().y
        self.public_key = public_key_int.to_bytes(self.key_len, 'big')

    def compute_secret(self, peer_public_key):
        peer_public_key_int = int.from_bytes(peer_public_key, 'big')
        peer_public_numbers = dh.DHPublicNumbers(peer_public_key_int, self._pn)
        peer_public_key = peer_public_numbers.public_key(self.backend)
        self.shared_secret = self._private_key.exchange(peer_public_key)


class ECDH:
    _ec_groups = {
        Transform.DhId.DH_19: ec.SECP256R1(),
        Transform.DhId.DH_20: ec.SECP384R1(),
        Transform.DhId.DH_21: ec.SECP521R1(),
    }

    backend = cryptography.hazmat.backends.openssl.backend

    def __init__(self, group):
        self.group = group
        self._private_key = ec.generate_private_key(self._ec_groups[group], backend=self.backend)
        # Trick to get the ceil of the division
        self.key_len = (self._private_key.key_size + 7) // 8
        self.shared_secret = None
        public_numbers = self._private_key.public_key().public_numbers()
        self.public_key = (public_numbers.x.to_bytes(self.key_len, 'big')
                           + public_numbers.y.to_bytes(self.key_len, 'big'))

    def compute_secret(self, peer_public_key):
        x = int.from_bytes(peer_public_key[:self.key_len], 'big')
        y = int.from_bytes(peer_public_key[self.key_len:], 'big')
        peer_public_numbers = ec.EllipticCurvePublicNumbers(x, y, self._ec_groups[self.group])
        peer_public_key = peer_public_numbers.public_key(self.backend)
        self.shared_secret = self._private_key.exchange(ec.ECDH(), peer_public_key)


class DiffieHellman:
    @classmethod
    def from_group(cls, group):
        try:
            return MODPDH(group)
        except KeyError:
            return ECDH(group)


class Integrity:
    _digestmod_dict = {
        Transform.IntegId.AUTH_HMAC_SHA1_96: (hashlib.sha1, 96),
        Transform.IntegId.AUTH_HMAC_SHA2_256_128: (hashlib.sha256, 128),
        Transform.IntegId.AUTH_HMAC_SHA2_512_256: (hashlib.sha512, 256),
    }

    def __init__(self, transform):
        assert(transform.type == Transform.Type.INTEG)
        self.hasher, self.keybits = self._digestmod_dict[transform.id]

    @property
    def key_size(self):
        return self.hasher().digest_size

    @property
    def hash_size(self):
        # Hardcoded as we only support _96 algorithms so far
        return self.keybits // 8

    def compute(self, key, data):
        m = HMAC(key, data, digestmod=self.hasher)
        return m.digest()[:self.hash_size]


class Crypto:
    def __init__(self, cipher, sk_e, integrity, sk_a, prf, sk_p):
        self.cipher = cipher
        self.sk_e = sk_e
        self.integrity = integrity
        self.sk_a = sk_a
        self.prf = prf
        self.sk_p = sk_p


class RsaPrivateKey:
    def __init__(self, pem):
        self.key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())

    def sign(self, data):
        return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())


class RsaPublicKey:
    def __init__(self, pem):
        self.key = serialization.load_pem_public_key(pem, backend=default_backend())

    def verify(self, signature, data, hasher = hashes.SHA256):
        if hasher == hashlib.sha1:
            hasher = hashes.SHA1
        elif hasher == hashlib.sha256:
            hasher = hashes.SHA256
        elif hasher == hashlib.sha512:
            hasher = hashes.SHA512

        try:
            self.key.verify(signature, data, padding.PKCS1v15(), hasher())
            return True
        except InvalidSignature:
            return False

class Certificate:
    def __init__(self, data):
         self.cert = cryptography.x509.load_der_x509_certificate(data)

    def verify(self, signature, data, hasher = hashes.SHA256):
        if hasher == hashlib.sha1:
            hasher = hashes.SHA1
        elif hasher == hashlib.sha256:
            hasher = hashes.SHA256
        elif hasher == hashlib.sha512:
            hasher = hashes.SHA512

        try:
            self.cert.public_key().verify(signature, data, padding.PKCS1v15(), hasher())
            return True
        except InvalidSignature:
            return False

    def fingerprint(self):
        return self.cert.fingerprint(hashes.SHA256()).hex()
