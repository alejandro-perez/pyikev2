#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import logging
import os
from message import (Message, Payload, PayloadNonce, PayloadVendor, PayloadKE,
    Proposal, Transform, NoProposalChosen, PayloadSA, InvalidKePayload)
from helpers import SafeEnum, SafeIntEnum, hexstring
from random import SystemRandom
from crypto import DiffieHellman, Prf, Integrity, Cipher
from struct import pack, unpack
from collections import namedtuple
import copy

class IkeSaError(Exception):
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
    def __init__(self, is_initiator):
        self.state = IkeSa.State.INITIAL
        self.my_spi = SystemRandom().randint(0, 0xFFFFFFFFFFFFFFFF)
        self.peer_spi = 0
        self.my_msg_id = 0
        self.peer_msg_id = 0
        self.is_initiator = is_initiator

    @property
    def spi_i(self):
        return self.my_spi if self.is_initiator else self.peer_spi

    @property
    def spi_r(self):
        return self.my_spi if self.is_initiator else self.peer_spi

    def generate_ike_sa_key_material(self, proposal, nonce_i, nonce_r,
                spi_i, spi_r, shared_secret):
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
            nonce_i + nonce_r + spi_i.to_bytes(8, 'big') + spi_r.to_bytes(8, 'big'),
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

    def select_best_ike_sa_proposal(self, payload_sa):
        """ Selects a received Payload SA wit our own suite
        """
        proposal = Proposal(
            1,
            Proposal.Protocol.IKE,
            b'',
            [
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 128),
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 256),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_MD5_96),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96),
                Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_MD5),
                Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1),
                Transform(Transform.Type.DH, DiffieHellman.Id.DH_5),
                Transform(Transform.Type.DH, DiffieHellman.Id.DH_2),
            ]
        )

        for peer_proposal in payload_sa.proposals:
            my_proposal = copy.deepcopy(proposal)
            for type in [Transform.Type.ENCR, Transform.Type.INTEG,
                         Transform.Type.PRF, Transform.Type.DH]:
                for my_transform in my_proposal.get_transforms(type):
                    if my_transform.id not in [x.id for x in peer_proposal.get_transforms(type)]:
                        my_proposal.transforms.remove(my_transform)
            try:
                return Proposal(
                    1,
                    Proposal.Protocol.IKE,
                    b'',
                    [
                        my_proposal.get_transform(Transform.Type.ENCR),
                        my_proposal.get_transform(Transform.Type.INTEG),
                        my_proposal.get_transform(Transform.Type.DH),
                        my_proposal.get_transform(Transform.Type.PRF),
                    ]
                )
            except StopIteration:
                pass
        raise NoProposalChosen

    def process_message(self, message):
        # (Exchange type, is_request): method
        _handler_dict = {
            (Message.Exchange.IKE_SA_INIT, True): self.process_ike_sa_init_request,
        }

        return _handler_dict[(message.exchange_type, message.is_request)](message)

    def process_ike_sa_init_request(self, request):
        """ Processes a IKE_SA_INIT message and returns a IKE_SA_INIT response
        """
        # check state
        if self.state != IkeSa.State.INITIAL:
            raise IkeSaError(
                'IKE SA state cannot proccess IKE_SA_INIT message')

        # initialize IKE SA state
        self.peer_spi = request.spi_i
        self.peer_msg_id = 0

        # get some relevant payloads from the message
        request_payload_sa = request.get_payload(Payload.Type.SA)
        request_payload_ke = request.get_payload(Payload.Type.KE)
        request_payload_nonce = request.get_payload(Payload.Type.NONCE)

        # generate the response payload SA with the chose proposal
        best_proposal = self.select_best_ike_sa_proposal(request_payload_sa)

        # check that DH groups match
        my_dh_group = best_proposal.get_transform(Transform.Type.DH).id
        if my_dh_group != request_payload_ke.dh_group:
            raise InvalidKePayload(my_dh_group)

        # generate the response payload KE
        dh = DiffieHellman(request_payload_ke.dh_group)
        dh.compute_secret(request_payload_ke.ke_data)
        logging.debug('Generated DH shared secret: {}'.format(hexstring(dh.shared_secret)))
        response_payload_ke = PayloadKE(dh.group, dh.public_key)

        # generate payload NONCE
        response_payload_nonce = PayloadNonce()

        # generate IKE SA key material
        self.generate_ike_sa_key_material(
            proposal=best_proposal,
            nonce_i=request_payload_nonce.nonce,
            nonce_r=response_payload_nonce.nonce,
            spi_i=self.peer_spi,
            spi_r=self.my_spi,
            shared_secret=dh.shared_secret
        )

        # generate the response payload VENDOR.
        response_payload_vendor = PayloadVendor(b'pyikev2-0.1')

        # generate the response Payload SA
        response_payload_sa = PayloadSA([best_proposal])

        # generate the message
        response = Message(
            spi_i=self.peer_spi,
            spi_r=self.my_spi,
            major=2,
            minor=0,
            exchange_type=Message.Exchange.IKE_SA_INIT,
            is_response=True,
            can_use_higher_version=False,
            is_initiator=False,
            message_id=self.my_msg_id,
            payloads=[response_payload_sa, response_payload_ke,
                response_payload_nonce, response_payload_vendor]
        )

        # increase msg_id and transition
        self.my_msg_id = self.my_msg_id + 1
        self.peer_msg_id = self.peer_msg_id + 1
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

        # if IKE_SA_INIT request, then a new IkeSa must be created
        if (header.exchange_type == Message.Exchange.IKE_SA_INIT and
                header.is_request):
            ike_sa = IkeSa(is_initiator=False)
            self.ike_sas[ike_sa.my_spi] = ike_sa

        # else, take the IkeSa from the dict
        else:
            my_spi = header.spi_r if header.is_initiator else header.spi_i
            ike_sa = self.ike_sas[my_spi]

        # parse the message
        message = Message.parse(data)
        self.log_message(message, addr, data, send=False)
        try:
            reply = ike_sa.process_message(message)
            if reply:
                self.log_message(reply, addr, data, send=True)
                return reply.to_bytes()
        except KeyError:
            logging.error('I don\'t know how to handle this message. '
                'Please, implement a handler!')
            pass

        return None





