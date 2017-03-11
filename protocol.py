#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import logging
import os
from message import (Message, Payload, PayloadNonce, PayloadVendor, PayloadKE,
    Proposal, Transform)
from helpers import SafeEnum, SafeIntEnum, hexstring
from random import SystemRandom
from dh import DiffieHellman
from prf import Prf
from integ import Integrity
from encr import Cipher
from struct import pack, unpack
from collections import namedtuple

class Ikev2ProtocolError(Exception):
    pass

Keyring = namedtuple('Keyring',
    ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr']
)

class IkeSa:
    class State(SafeIntEnum):
        INITIAL = 0
        HALF_OPEN = 1


    """ This class controls the state machine of a IKE SA
        It is triggered with received Messages and/or IPsec events
    """
    def __init__(self):
        self.state = IkeSa.State.INITIAL
        self.msg_id_i = 0
        self.msg_id_r = 0

    def generate_ike_sa_key_material(self, proposal, nonce_i, nonce_r, shared_secret):
        """ Generates IKE_SA key material based on the proposal and DH
        """
        prf = Prf(proposal.get_transform(Transform.Type.PRF).id)
        integ = Integrity(proposal.get_transform(Transform.Type.INTEG).id)
        cipher = Cipher(
            proposal.get_transform(Transform.Type.ENCR).id,
            proposal.get_transform(Transform.Type.ENCR).keylen
        )

        SKEYSEED = prf.prf(nonce_i + nonce_r, shared_secret)
        logging.debug('Generated SKEYSEED: {}'.format(hexstring(SKEYSEED)))

        keymat = prf.prfplus(
            SKEYSEED,
            nonce_i + nonce_r + self.spi_i.to_bytes(8, 'big') + self.spi_r.to_bytes(8, 'big'),
            prf.key_size * 3 + integ.key_size * 2 + cipher.key_size * 2
        )

        self.ike_sa_keyring = Keyring._make(
            unpack(
                ('>' + '{}s' * 7).format(prf.key_size, integ.key_size, integ.key_size,
                    cipher.key_size, cipher.key_size, prf.key_size, prf.key_size),
                keymat
            )
        )

        logging.debug('Generated sk_d: {}'.format(hexstring(self.ike_sa_keyring.sk_d)))
        logging.debug('Generated sk_ai: {}'.format(hexstring(self.ike_sa_keyring.sk_ai)))
        logging.debug('Generated sk_ar: {}'.format(hexstring(self.ike_sa_keyring.sk_ar)))
        logging.debug('Generated sk_ei: {}'.format(hexstring(self.ike_sa_keyring.sk_ei)))
        logging.debug('Generated sk_er: {}'.format(hexstring(self.ike_sa_keyring.sk_er)))
        logging.debug('Generated sk_pi: {}'.format(hexstring(self.ike_sa_keyring.sk_pi)))
        logging.debug('Generated sk_pr: {}'.format(hexstring(self.ike_sa_keyring.sk_pr)))

    def process_ike_sa_init_request(self, request):
        """ Processes a IKE_SA_INIT message and returns a IKE_SA_INIT response
        """
        # check state
        if self.state != IkeSa.State.INITIAL:
            raise Ikev2ProtocolError(
                'IKE SA state cannot proccess IKE_SA_INIT message')

        # initialize IKE SA state
        self.spi_i = request.spi_i
        self.spi_r = SystemRandom().randint(0, 0xFFFFFFFFFFFFFFFF)
        self.is_initiator = False
        self.msg_id_i = request.message_id
        self.msg_id_r = 0
        self.nonce_i = request.get_payload(Payload.Type.NONCE)
        self.nonce_r = PayloadNonce()

        # generate DH shared secret
        peer_payload_ke = request.get_payload(Payload.Type.KE)
        dh = DiffieHellman(peer_payload_ke.dh_group, peer_payload_ke.ke_data)
        logging.debug('Generated DH shared secret: {}'.format(hexstring(dh.shared_secret)))

        peer_nonce = request.get_payload(Payload.Type.NONCE).nonce
        payload_nonce = PayloadNonce()
        self.generate_ike_sa_key_material(
            proposal=request.get_payload(Payload.Type.SA).proposals[0],
            nonce_i=request.get_payload(Payload.Type.NONCE).nonce,
            nonce_r=payload_nonce.nonce,
            shared_secret=dh.shared_secret
        )

        # generate the response payload SA. So far, we just copy theirs
        payload_sa = request.get_payload(Payload.Type.SA)

        # generate the response payload KE
        payload_ke = PayloadKE(dh.group, dh.public_key)

        # generate the response payload VENDOR.
        payload_vendor = PayloadVendor(b'pyikev2-0.1')

        # generate the message
        response = Message(
            spi_i=self.spi_i,
            spi_r=self.spi_r,
            major=2,
            minor=0,
            exchange_type=Message.Exchange.IKE_SA_INIT,
            is_response=True,
            can_use_higher_version=False,
            is_initiator=False,
            message_id=self.msg_id_r,
            payloads=[payload_sa, payload_ke, payload_nonce, payload_vendor]
        )

        # increase msg_id and transition
        self.msg_id_r = self.msg_id_r + 1
        self.state = IkeSa.State.HALF_OPEN

        return response

class IkeSaController:
    def __init__(self):
        self.ike_sas = {}

    def log_message(self, message, addr, data, send=True):
        logging.info('{} {} {} ({} bytes) {} {}'.format(
            'Sent' if send else 'Received',
            Message.Exchange.safe_name(message.exchange_type),
            'response' if message.is_response else 'request',
            len(data),
            'to' if send else 'from',
            addr))
        logging.debug(message)

    def dispatch_message(self, data, addr):
        header = Message.parse(data, header_only=True)

        # if IKE_SA_INIT request, then a new IkeSa must be created to handle it
        if (header.exchange_type == Message.Exchange.IKE_SA_INIT and
                header.is_request):
            request = Message.parse(data)
            logging.debug(
                'Received IKE_SA_INIT request: {}'.format(request))
            ike_sa = IkeSa()
            response = ike_sa.process_ike_sa_init_request(request)
            self.ike_sas[ike_sa.spi_r] = ike_sa
            logging.debug('Sending IKE_SA_INIT response: {}'.format(response))
            return response.to_bytes()

        elif (header.exchange_type == Message.Exchange.IKE_AUTH and
                header.is_request):
            request = Message.parse(data)
            logging.debug(
                'Received IKE_AUTH request: {}'.format(request))
            return None
        else:
            logging.debug('Received unexpected IKE message. Omitting: {}'.format(header))
            return None




