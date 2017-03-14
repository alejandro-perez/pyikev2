#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import logging
import os
from message import (Message, Payload, PayloadNONCE, PayloadVENDOR, PayloadKE,
    Proposal, Transform, NoProposalChosen, PayloadSA, InvalidKePayload,
    InvalidSyntax, PayloadAUTH, AuthenticationFailed, PayloadIDi, PayloadIDr)
from helpers import SafeEnum, SafeIntEnum, hexstring
from random import SystemRandom
from crypto import DiffieHellman, Prf, Integrity, Cipher, Crypto
from struct import pack, unpack
from collections import namedtuple

class IkeSaError(Exception):
    pass

Keyring = namedtuple('Keyring',
    ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr']
)

class IkeSa:
    class State(SafeIntEnum):
        INITIAL = 0
        INIT_RES_SENT = 1
        ESTABLISHED = 2

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
        self.ike_sa_keyring = None
        self.chosen_proposal = None
        self.my_crypto = None
        self.peer_crypto = None

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
                ('>' + '{}s' * 7).format(prf.key_size, integ.key_size,
                    integ.key_size, cipher.key_size, cipher.key_size,
                    prf.key_size, prf.key_size),
                keymat))

        crypto_i = Crypto(cipher, self.ike_sa_keyring.sk_ei,
            integ, self.ike_sa_keyring.sk_ai,
            prf, self.ike_sa_keyring.sk_pi)
        crypto_r = Crypto(cipher, self.ike_sa_keyring.sk_er,
            integ, self.ike_sa_keyring.sk_ar,
            prf, self.ike_sa_keyring.sk_pr)

        self.my_crypto = crypto_i if self.is_initiator else crypto_r
        self.peer_crypto = crypto_r if self.is_initiator else crypto_i

        logging.debug('Generated sk_d: {}'.format(hexstring(self.ike_sa_keyring.sk_d)))
        logging.debug('Generated sk_ai: {}'.format(hexstring(self.ike_sa_keyring.sk_ai)))
        logging.debug('Generated sk_ar: {}'.format(hexstring(self.ike_sa_keyring.sk_ar)))
        logging.debug('Generated sk_ei: {}'.format(hexstring(self.ike_sa_keyring.sk_ei)))
        logging.debug('Generated sk_er: {}'.format(hexstring(self.ike_sa_keyring.sk_er)))
        logging.debug('Generated sk_pi: {}'.format(hexstring(self.ike_sa_keyring.sk_pi)))
        logging.debug('Generated sk_pr: {}'.format(hexstring(self.ike_sa_keyring.sk_pr)))

    def select_best_sa_proposal(self, my_proposal, peer_payload_sa):
        """ Selects a received Payload SA wit our own suite
        """
        for peer_proposal in peer_payload_sa.proposals:
            if peer_proposal.protocol_id == my_proposal.protocol_id:
                selected_transforms = {}
                for my_transform in my_proposal.transforms:
                    for peer_transform in peer_proposal.transforms:
                        if my_transform == peer_transform:
                            if my_transform.type not in selected_transforms:
                                selected_transforms[my_transform.type] = my_transform
                # If we have a transform of each type => success
                if (set(selected_transforms) ==
                        set(x.type for x in my_proposal.transforms)):
                    return Proposal(1, my_proposal.protocol_id, b'',
                        list(selected_transforms.values()))
        raise NoProposalChosen

    def select_best_ike_sa_proposal(self, peer_payload_sa):
        my_proposal = Proposal(
            1, Proposal.Protocol.IKE, b'',
            [
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 256),
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 128),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_MD5_96),
                Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_SHA1),
                Transform(Transform.Type.PRF, Prf.Id.PRF_HMAC_MD5),
                Transform(Transform.Type.DH, DiffieHellman.Id.DH_5),
                Transform(Transform.Type.DH, DiffieHellman.Id.DH_2),
            ]
        )
        return self.select_best_sa_proposal(my_proposal, peer_payload_sa)

    def select_best_child_sa_proposal(self, peer_payload_sa):
        my_proposal = Proposal(
            1, Proposal.Protocol.ESP, b'',
            [
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 256),
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 128),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_MD5_96),
            ]
        )
        return self.select_best_sa_proposal(my_proposal, peer_payload_sa)

    def log_message(self, message, addr, data, send=True):
        logging.info('{} {} {} ({} bytes) {} {}'.format(
            'Sent' if send else 'Received',
            Message.Exchange.safe_name(message.exchange_type),
            'response' if message.is_response else 'request',
            len(data),
            'to' if send else 'from',
            addr))
        logging.debug(message)

    def process_message(self, data, addr):
        """ Performs the common tasks for IKE message handling,
            including logging for the message and the reply (if any), check of
            message IDs and control of retransmissions
        """
        # dict with the form of tuple(Exchange type, is_request): method
        _handler_dict = {
            (Message.Exchange.IKE_SA_INIT, True): self.process_ike_sa_init_request,
            (Message.Exchange.IKE_AUTH, True): self.process_ike_auth_request,
        }

        # parse the whole message (including encrypted data)
        message = Message.parse(data, header_only=False, crypto=self.peer_crypto)
        self.log_message(message, addr, data, send=False)

        # get the appropriate handler fnc
        try:
            handler = _handler_dict[(message.exchange_type, message.is_request)]
        except KeyError:
            logging.error('I don\'t know how to handle this message. '
                'Please, implement a handler!')
            return None

        # generate a reply
        reply = handler(message)
        self.last_received_message_data = data
        self.last_received_message = message

        if reply:
            data = reply.to_bytes(crypto=self.my_crypto)
            self.log_message(reply, addr, data, send=True)
            self.last_sent_message_data = data
            self.last_sent_message = reply
            return data

        return None

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
        self.chosen_proposal = self.select_best_ike_sa_proposal(request_payload_sa)

        # check that DH groups match
        my_dh_group = self.chosen_proposal.get_transform(Transform.Type.DH).id
        if my_dh_group != request_payload_ke.dh_group:
            raise InvalidKePayload(my_dh_group)

        # generate the response payload KE
        dh = DiffieHellman(request_payload_ke.dh_group)
        dh.compute_secret(request_payload_ke.ke_data)
        logging.debug('Generated DH shared secret: {}'.format(hexstring(dh.shared_secret)))
        response_payload_ke = PayloadKE(dh.group, dh.public_key)

        # generate payload NONCE
        response_payload_nonce = PayloadNONCE()

        # generate IKE SA key material
        self.generate_ike_sa_key_material(
            proposal=self.chosen_proposal,
            nonce_i=request_payload_nonce.nonce,
            nonce_r=response_payload_nonce.nonce,
            spi_i=self.peer_spi,
            spi_r=self.my_spi,
            shared_secret=dh.shared_secret
        )

        # generate the response payload VENDOR.
        response_payload_vendor = PayloadVENDOR(b'pyikev2-0.1')

        # generate the response Payload SA
        response_payload_sa = PayloadSA([self.chosen_proposal])

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
                response_payload_nonce, response_payload_vendor],
            encrypted_payloads=[],
        )

        # increase msg_id and transition
        self.my_msg_id = self.my_msg_id + 1
        self.peer_msg_id = self.peer_msg_id + 1
        self.state = IkeSa.State.INIT_RES_SENT

        # return response
        return response

    def _generate_psk_auth_payload(self, message_data, nonce, payload_id, sk_p):
        prf = self.peer_crypto.prf.prf
        data_to_be_signed = (message_data + nonce + prf(sk_p, payload_id.to_bytes()))
        keypad = prf(b'this file can be whatever kind of file: TXT, JPG, GZIP, ...',
            b'Key Pad for IKEv2')
        return prf(keypad, data_to_be_signed)

    def _generate_peer_psk_auth_payload(self, payload_id):
        return self._generate_psk_auth_payload(self.last_received_message_data,
            self.last_sent_message.get_payload(Payload.Type.NONCE).nonce,
            payload_id, self.peer_crypto.sk_p)

    def _generate_my_psk_auth_payload(self, payload_id):
        return self._generate_psk_auth_payload(self.last_sent_message_data,
            self.last_received_message.get_payload(Payload.Type.NONCE).nonce,
            payload_id, self.my_crypto.sk_p)

    def process_ike_auth_request(self, request):
        """ Processes a IKE_AUTH request message and returns a
            IKE_AUTH response
        """
        # check state
        if self.state != IkeSa.State.INIT_RES_SENT:
            raise InvalidSyntax(
                'IKE SA state cannot proccess IKE_SA_INIT message')

        # get some relevant payloads from the message
        request_payload_sa = request.get_encr_payload(Payload.Type.SA)
        request_payload_tsi = request.get_encr_payload(Payload.Type.TSi)
        request_payload_tsr = request.get_encr_payload(Payload.Type.TSr)
        request_payload_idi = request.get_encr_payload(Payload.Type.IDi)
        request_payload_auth = request.get_encr_payload(Payload.Type.AUTH)

        # verify AUTH payload
        if request_payload_auth.method != PayloadAUTH.Method.PSK:
            raise AuthenticationFailed('AUTH method not supported')
        auth_data = self._generate_peer_psk_auth_payload(request_payload_idi)
        if auth_data != request_payload_auth.auth_data:
            raise AuthenticationFailed('Invalid AUTH data received')

        # generate the response payload SA with the chose proposal
        chosen_child_proposal = self.select_best_child_sa_proposal(request_payload_sa)

        # TODO: Take this SPI from an actual acquire to avoid (unlikely) collisions
        chosen_child_proposal.spi = os.urandom(4)

        # generate the response Payload SA
        response_payload_sa = PayloadSA([chosen_child_proposal])

        # TODO: Make actual TS matching
        response_payload_tsi = request_payload_tsi
        response_payload_tsr = request_payload_tsr

        # send my IDr
        response_payload_idr = PayloadIDr(PayloadIDr.Type.ID_RFC822_ADDR, b'bob@openikev2')

        # generate AUTH payload
        auth_data = self._generate_my_psk_auth_payload(response_payload_idr)
        response_payload_auth = PayloadAUTH(PayloadAUTH.Method.PSK, auth_data)

        # generate the message
        response = Message(
            spi_i=self.peer_spi,
            spi_r=self.my_spi,
            major=2,
            minor=0,
            exchange_type=Message.Exchange.IKE_AUTH,
            is_response=True,
            can_use_higher_version=False,
            is_initiator=False,
            message_id=self.my_msg_id,
            payloads=[],
            encrypted_payloads=[response_payload_sa, response_payload_tsi,
                response_payload_tsr, response_payload_idr, response_payload_auth],
        )

        # increase msg_id and transition
        self.my_msg_id = self.my_msg_id + 1
        self.peer_msg_id = self.peer_msg_id + 1
        self.state = IkeSa.State.ESTABLISHED

        return response

class IkeSaController:
    def __init__(self):
        self.ike_sas = {}

    def dispatch_message(self, data, addr):
        header = Message.parse(data, header_only=True)

        # if IKE_SA_INIT request, then a new IkeSa must be created
        if (header.exchange_type == Message.Exchange.IKE_SA_INIT and
                header.is_request):
            ike_sa = IkeSa(is_initiator=False)
            self.ike_sas[ike_sa.my_spi] = ike_sa

        # else, look for the IkeSa in the dict
        else:
            my_spi = header.spi_r if header.is_initiator else header.spi_i
            try:
                ike_sa = self.ike_sas[my_spi]
            except KeyError:
                logging.warning('Received message for unknown SPI. Omitting.')
                logging.debug(header)
                return None

        # return the reply (if any)
        reply = ike_sa.process_message(data, addr)
        return reply
