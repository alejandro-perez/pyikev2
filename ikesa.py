#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the IKE_SA handling.
"""
import hashlib
import json
import logging
import os
import random
import time
import traceback
from collections import namedtuple, OrderedDict
from enum import IntEnum
from hmac import HMAC
from struct import unpack
from eap import EAPClient

import xfrm
from crypto import Cipher, Crypto, DiffieHellman, Integrity, Prf, Certificate
from message import (AuthenticationFailed, ChildSaNotFound, IkeSaError, InvalidKePayload,
                     NoProposalChosen, TemporaryFailure, TsUnacceptable, CookieRequired, PayloadNotFound)
from message import (Message, Payload, PayloadAUTH, PayloadDELETE, PayloadIDi, PayloadIDr, PayloadKE, PayloadNONCE,
                     PayloadNOTIFY, PayloadSA, PayloadTSi, PayloadTSr, PayloadVENDOR, Proposal, Transform, PayloadCERT, PayloadEAP)

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'

Keyring = namedtuple('Keyring', ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr'])
ChildSa = namedtuple('ChildSa', ['inbound_spi', 'outbound_spi', 'original_proposal', 'proposal', 'tsi', 'tsr', 'mode',
                                 'lifetime'])
ChildSa.__str__ = lambda x: '({}, {}, {}, {})'.format(x.inbound_spi.hex(), x.outbound_spi.hex(), x.mode.name,
                                                      x.proposal.protocol_id.name)
ChildSa.to_dict = lambda x: {'spis': str(x),
                             'protocol': x.proposal.protocol_id.name,
                             'mode': x.mode.name,
                             'selectors': '[{}]:{} <-> [{}]:{}'.format(x.tsi.get_network(), x.tsi.get_port(),
                                                                       x.tsr.get_network(), x.tsr.get_port())}


class IkeSaStateError(Exception):
    pass


class ChildSaRejectedError(Exception):
    pass


class IkeSa(object):
    """ This class controls the state machine of a IKE SA
        It is triggered with received Messages and/or IPsec events
    """
    MAX_RETRANSMISSIONS = 4
    RETRANSMISSION_DELAY = 2

    class State(IntEnum):
        # Non-established states
        INITIAL = 0
        INIT_RES_SENT = 1
        INIT_REQ_SENT = 2
        AUTH_REQ_SENT = 3

        # Established states
        ESTABLISHED = 10
        NEW_CHILD_REQ_SENT = 11
        REK_CHILD_REQ_SENT = 12
        REK_IKE_SA_REQ_SENT = 13
        DEL_CHILD_REQ_SENT = 14
        DEL_IKE_SA_REQ_SENT = 15
        DEL_AFTER_REKEY_IKE_SA_REQ_SENT = 16
        DPD_REQ_SENT = 17

        # Closing states
        REKEYED = 20
        DELETED = 21

    def __init__(self, is_initiator, peer_spi, configuration, my_addr, peer_addr, cookie_secret=None, disableXfrm = False, eapTlsClientSocket = None):
        self.state = IkeSa.State.INITIAL
        self.my_spi = os.urandom(8)
        self.peer_spi = peer_spi
        self.my_msg_id = 0
        self.peer_msg_id = 0
        self.is_initiator = is_initiator
        self.ike_sa_keyring = None
        self.chosen_proposal = None
        self.my_crypto = None
        self.peer_crypto = None
        self.configuration = configuration
        self.my_addr = my_addr
        self.peer_addr = peer_addr
        self.child_sas = []
        self.ike_sa_init_req_data = None
        self.ike_sa_init_res_data = None
        self.request = None
        self.creating_child_sa = None
        self.rekeying_child_sa = None
        self.deleting_child_sa = None
        self.acquire = None
        self.new_ike_sa = None
        self.retransmit_at = 0
        self.retransmissions = 0
        self.cookie_secret = cookie_secret
        self.start_dpd_at = time.time() + configuration.dpd
        self.rekey_ike_sa_at = time.time() + configuration.lifetime + random.uniform(0, 5)
        self.delete_ike_sa_at = self.rekey_ike_sa_at + 30
        self.pending_events = []
        self.dh = None
        self.disableXfrm = disableXfrm
        self.lastPeerCerts = []
        self.lastPeerIdr = None
        self.eapClient = EAPClient(self.configuration.my_auth.eap, eapTlsClientSocket) if self.configuration.my_auth.eap else None

    def __str__(self):
        return self.my_spi.hex()

    def to_dict(self):
        result = OrderedDict({
            'my_addr': str(self.my_addr),
            'peer_addr': str(self.peer_addr),
            'my_spi': self.my_spi.hex(),
            'peer_spi': self.peer_spi.hex(),
            'is_initiator': self.is_initiator,
            'state': self.state.name,
            'msg_id': self.my_msg_id,
            'rekey_in': int(self.rekey_ike_sa_at - time.time()),
            'child_sas': [x.to_dict() for x in self.child_sas]
        })
        return result

    def log_msg(self, level, message):
        logging.log(level, f'IKE_SA: {self}. {message}')

    def log_error(self, message):
        self.log_msg(logging.ERROR, message)

    def log_info(self, message):
        self.log_msg(logging.INFO, message)

    def log_warning(self, message):
        self.log_msg(logging.WARNING, message)

    def log_debug(self, message):
        self.log_msg(logging.DEBUG, message)

    def generate_ike_sa_key_material(self, ike_proposal, nonce_i, nonce_r, spi_i, spi_r, shared_secret, old_sk_d=None):
        """ Generates IKE_SA key material based on the proposal and DH
        """
        prf = Prf(ike_proposal.get_transform(Transform.Type.PRF))
        integ = Integrity(ike_proposal.get_transform(Transform.Type.INTEG))
        cipher = Cipher(ike_proposal.get_transform(Transform.Type.ENCR))

        if not old_sk_d:
            skeyseed = prf.prf(nonce_i + nonce_r, shared_secret)
        else:
            skeyseed = prf.prf(old_sk_d, shared_secret + nonce_i + nonce_r)

        self.log_debug(f'Generated SKEYSEED: {skeyseed.hex()}')

        keymat = prf.prfplus(skeyseed, nonce_i + nonce_r + spi_i + spi_r,
                             prf.key_size * 3 + integ.key_size * 2 + cipher.key_size * 2)
        sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr = unpack(
            '>{0}s{1}s{1}s{2}s{2}s{0}s{0}s'.format(prf.key_size, integ.key_size, cipher.key_size), keymat)
        ike_sa_keyring = Keyring(sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr)
        crypto_i = Crypto(cipher, ike_sa_keyring.sk_ei, integ, ike_sa_keyring.sk_ai, prf, ike_sa_keyring.sk_pi)
        crypto_r = Crypto(cipher, ike_sa_keyring.sk_er, integ, ike_sa_keyring.sk_ar, prf, ike_sa_keyring.sk_pr)
        self.my_crypto = crypto_i if self.is_initiator else crypto_r
        self.peer_crypto = crypto_r if self.is_initiator else crypto_i

        for keyname in ('sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr'):
            hexkey = getattr(ike_sa_keyring, keyname).hex()
            self.log_debug(f'Generated {keyname}: {hexkey}')
        return ike_sa_keyring

    def before_remove(self):
        self.delete_child_sas()
        if self.eapClient is not None:
            self.eapClient.stop()

    def delete_child_sas(self):
        if not self.disableXfrm:
            for child_sa in self.child_sas:
                xfrm.Xfrm.delete_child_sa(self, child_sa)
        self.child_sas.clear()

    def generate_child_sa_key_material(self, child_proposal, keyseed, sk_d):
        """ Generates CHILD_SA key material
        """
        encr_key_size = 0
        integ_key_size = Integrity(child_proposal.get_transform(Transform.Type.INTEG)).key_size
        if child_proposal.protocol_id == Proposal.Protocol.ESP:
            encr_key_size = Cipher(child_proposal.get_transform(Transform.Type.ENCR)).key_size

        keymat = self.my_crypto.prf.prfplus(sk_d, keyseed, 2 * integ_key_size + 2 * encr_key_size)

        sk_ei, sk_ai, sk_er, sk_ar = unpack('>{0}s{1}s{0}s{1}s'.format(encr_key_size, integ_key_size), keymat)
        child_sa_keyring = Keyring(None, sk_ai, sk_ar, sk_ei, sk_er, None, None)

        for keyname in ('sk_ai', 'sk_ar', 'sk_ei', 'sk_er'):
            hexkey = getattr(child_sa_keyring, keyname).hex()
            self.log_debug(f'Generated {keyname}: {hexkey}')

        return child_sa_keyring

    def _select_best_sa_proposal(self, my_proposal, peer_payload_sa):
        """ Selects a received Payload SA with our own suite
        """
        for peer_proposal in peer_payload_sa.proposals:
            intersection = my_proposal.intersection(peer_proposal)
            if intersection is not None:
                return intersection
        raise NoProposalChosen('Could not find a suitable matching Proposal')

    def _get_ipsec_configuration(self, payload_tsi, payload_tsr):
        """ Find matching IPsec configuration.
            It iterates over the received TS in reversed order and returns the
            first configuration that is larger or smaller than the proposed
            pair, along with the chosen selectors
        """
        for tsi in reversed(payload_tsi.traffic_selectors):
            for tsr in reversed(payload_tsr.traffic_selectors):
                for ipsec_conf in self.configuration.protect:
                    # look for a larger policy
                    if tsi.is_subset(ipsec_conf.peer_ts) and tsr.is_subset(ipsec_conf.my_ts):
                        return ipsec_conf, tsr, tsi
                    # look for a smaller policy
                    elif ipsec_conf.peer_ts.is_subset(tsi) and ipsec_conf.my_ts.is_subset(tsr):
                        return ipsec_conf, ipsec_conf.my_ts, ipsec_conf.peer_ts
        raise TsUnacceptable('TS could not be matched with any IPsec configuration')

    def log_message(self, message, data, send=True):
        self.log_info('{} {} {} ({} bytes) {} {} [{}]'
                      ''.format('Sent' if send else 'Received',
                                message.exchange_type.name,
                                'response' if message.is_response else 'request',
                                len(data),
                                'to' if send else 'from',
                                self.peer_addr,
                                ', '.join(str(x) for x in message.payloads + message.encrypted_payloads)))
        self.log_debug(json.dumps(message.to_dict(), indent=logging.indent))

    def generate_response(self, exchange_type, payloads):
        return Message(spi_i=self.spi_i,
                       spi_r=self.spi_r,
                       major=2,
                       minor=0,
                       exchange_type=exchange_type,
                       is_response=True,
                       can_use_higher_version=False,
                       is_initiator=self.is_initiator,
                       message_id=self.peer_msg_id,
                       payloads=payloads if exchange_type == Message.Exchange.IKE_SA_INIT else [],
                       encrypted_payloads=payloads if exchange_type != Message.Exchange.IKE_SA_INIT else [],
                       crypto=self.my_crypto if exchange_type != Message.Exchange.IKE_SA_INIT else None)

    def generate_request(self, exchange_type, payloads):
        return Message(spi_i=self.spi_i,
                       spi_r=self.spi_r,
                       major=2,
                       minor=0,
                       exchange_type=exchange_type,
                       is_response=False,
                       can_use_higher_version=False,
                       is_initiator=self.is_initiator,
                       message_id=self.my_msg_id,
                       payloads=payloads if exchange_type == Message.Exchange.IKE_SA_INIT else [],
                       encrypted_payloads=payloads if exchange_type != Message.Exchange.IKE_SA_INIT else [],
                       crypto=self.my_crypto if exchange_type != Message.Exchange.IKE_SA_INIT else None)

    def _process_request(self, message):
        _handler_dict = {
            Message.Exchange.IKE_SA_INIT: self.process_ike_sa_init_request,
            Message.Exchange.IKE_AUTH: self.process_ike_auth_request,
            Message.Exchange.INFORMATIONAL: self.process_informational_request,
            Message.Exchange.CREATE_CHILD_SA: self.process_create_child_sa_request
        }

        # check message_id and handle retransmissions
        if message.message_id == self.peer_msg_id - 1:
            self.log_warning('Retransmission detected. Sending last sent message')
            return self.last_sent_response_data
        elif message.message_id != self.peer_msg_id:
            self.log_error('Message with invalid ID. Expecting: {}. Received: {}. Omitting.'
                           ''.format(self.peer_msg_id, message.message_id))
            return None

        try:
            handler = _handler_dict[message.exchange_type]
        except KeyError:
            self.log_error("I don't know how to handle this message. Please, implement a handler for this exchange!")
            return None
        try:
            response = handler(message)
        except IkeSaError as ex:
            self.log_error(str(ex))
            notify_error = PayloadNOTIFY.from_exception(ex)
            response = self.generate_response(message.exchange_type, [notify_error])
            self.state = IkeSa.State.DELETED
        except Exception as ex:
            traceback.print_exc()
            self.log_error(str(ex))
            notify_error = PayloadNOTIFY.from_exception(ex)
            response = self.generate_response(message.exchange_type, [notify_error])
            self.state = IkeSa.State.DELETED

        # if the message is successfully processed, increment expected message
        # ID and store response (for future retransmissions responses)
        self.peer_msg_id = self.peer_msg_id + 1
        response_data = response.to_bytes()
        self.log_message(response, response_data, send=True)
        self.last_sent_response_data = response_data
        return response_data

    def _send_request(self, request):
        self.retransmissions = 1
        self.retransmit_at = time.time() + IkeSa.RETRANSMISSION_DELAY
        request_data = request.to_bytes()
        self.log_message(request, request_data, send=True)
        return request_data

    def _process_response(self, message):
        _handler_dict = {
            Message.Exchange.IKE_SA_INIT: self.process_ike_sa_init_response,
            Message.Exchange.IKE_AUTH: self.process_ike_auth_response,
            Message.Exchange.CREATE_CHILD_SA: self.process_create_child_sa_response,
            Message.Exchange.INFORMATIONAL: self.process_informational_response,
        }

        # if message ID is not the expected one, log and omit
        if message.message_id != self.my_msg_id:
            self.log_error('Message with invalid ID. Expecting: {}. Received: {}. Omitting.'
                           ''.format(self.my_msg_id, message.message_id))
            return None

        # increment our message ID for future requests
        self.my_msg_id = self.my_msg_id + 1
        try:
            handler = _handler_dict[message.exchange_type]
        except KeyError:
            self.log_error("I don't know how to handle this message. Please, implement a handler!")
            return None
        try:
            request = handler(message)
            # If there is a another request to be sent, serialise it and return it
            if request:
                return self._send_request(request)

            # if state is ESTABLISHED, check for pending events
            if self.state == IkeSa.State.ESTABLISHED:
                for x in list(self.pending_events):
                    self.pending_events.remove(x)
                    self.log_debug('Processing pending event')
                    handler, *args = x
                    request = handler(*args)
                    if request:
                        return request
        except (IkeSaError, IkeSaStateError) as ex:
            self.log_error(str(ex))
            self.state = IkeSa.State.DELETED
        except Exception as ex:
            traceback.print_exc()
            self.log_error(str(ex))
            self.state = IkeSa.State.DELETED

        return None

    def process_message(self, data):
        # parse the whole message (including encrypted data)
        message = Message.parse(data, header_only=False, crypto=self.peer_crypto)
        self.log_message(message, data, send=False)

        # check the role the sender claims to have corresponds with what we think about ourselves
        if message.is_initiator == self.is_initiator:
            self.log_error('Received a message with the wrong "INITIATOR" flag. Ignoring')
            return None

        if (message.exchange_type != Message.Exchange.IKE_SA_INIT
                and (message.spi_i, message.spi_r) != (self.spi_i, self.spi_r)):
            self.log_error('Received a message with wrong SPI values. Expected: {}. Ignoring'
                           ''.format(self.spi_i.hex(), self.spi_r.hex()))
            return None

        # receiving any kind of message from the peer resets the DPD timer
        self.start_dpd_at = time.time() + self.configuration.dpd
        if message.is_request:
            return self._process_request(message)
        else:
            return self._process_response(message)

    def connect(self):
        request = self.generate_ike_sa_init_request(None)
        return self._send_request(request)

    def process_acquire(self, tsi, tsr, index):
        if self.state not in (IkeSa.State.INITIAL, IkeSa.State.ESTABLISHED):
            self.log_debug('Cannot process acquire while waiting for a response. Queuing')
            self.pending_events.append((self.process_acquire, tsi, tsr, index))
            return None
        try:
            ipsec_conf = next(x for x in self.configuration.protect if x.index == index)
        except StopIteration:
            self.log_warning('Could not find a matching "protect" configuration for received ACQUIRE.')
            return None

        self.log_info("Received acquire from policy with index={}".format(index))
        # Create the ChildSa object with the values we know so far
        child_sa = ChildSa(inbound_spi=os.urandom(4), outbound_spi=b'\0' * 4, original_proposal=ipsec_conf.proposal,
                           proposal=ipsec_conf.proposal, tsi=(tsi, ipsec_conf.my_ts),
                           tsr=(tsr, ipsec_conf.peer_ts), mode=ipsec_conf.mode, lifetime=ipsec_conf.lifetime)
        if self.state == IkeSa.State.INITIAL:
            child_sa._replace(proposal=child_sa.proposal.copy_without_dh_transforms())
            request = self.generate_ike_sa_init_request(child_sa)
        else:
            request = self.generate_create_child_sa_request(child_sa)

        return self._send_request(request)

    def process_expire(self, spi, hard=False):
        """ Creates a rekey CREATE_CHILD_SA message for creating a new CHILD or an INFORMATIONAL for deleting it
        """
        if self.state != IkeSa.State.ESTABLISHED:
            self.log_debug('Cannot process expire while waiting for a response. Queuing')
            self.pending_events.append((self.process_expire, spi, hard))
            return None

        child_sa = self.get_child_sa(spi)
        if child_sa is None:
            self.log_debug(f'Received expire for unknown CHILD_SA with spi {spi.hex()}')
            return None

        self.log_info(f"Received expire for CHILD_SA {child_sa}. Hard={hard}")
        # if this is a soft expire, rekey the CHILD SA
        if not hard:
            # Create the ChildSa object with the values we know so far
            new_child_sa = ChildSa(inbound_spi=os.urandom(4), outbound_spi=b'\0' * 4, mode=child_sa.mode,
                                   proposal=child_sa.original_proposal, original_proposal=child_sa.original_proposal,
                                   tsi=[child_sa.tsi], tsr=[child_sa.tsr], lifetime=child_sa.lifetime)
            request = self.generate_create_child_sa_request(new_child_sa, child_sa)
        # if this is a hard expire, delete the CHILD SA
        else:
            request = self.generate_delete_child_sa_request(child_sa)

        return self._send_request(request)

    def check_dead_peer_detection_timer(self):
        """ Creates an empty INFORMATIONAL message for Dead Peer Detection
        """
        # if state is not ESTABLISHED, the retransmission timer will take care of DPD
        if self.start_dpd_at < time.time() and self.state == IkeSa.State.ESTABLISHED:
            self.log_info('Starting DEAD-PEER-DETECTION')
            request = self.generate_dead_peer_detection_request()
            return self._send_request(request)
        return None

    def check_rekey_ike_sa_timer(self):
        """ Creates an empty INFORMATIONAL message for Dead Peer Detection
        """
        if self.state == IkeSa.State.ESTABLISHED:
            now = time.time()
            if self.delete_ike_sa_at < now:
                self.log_info("Received hard expire for IKE_SA")
                request = self.generate_delete_ike_sa_request()
                return self._send_request(request)
            elif self.rekey_ike_sa_at < now:
                request = self.generate_rekey_ike_sa_request()
                return self._send_request(request)
        return None

    def _process_ike_sa_negotiation_request(self, request, encrypted=False, old_sk_d=None):
        """ Process a IKE_SA negotiation request (SA, Ni, KEi), and returns
            appropriate response payloads (SA, Nr, KEr) or raises exception
            on error.
            It sets self.chosen_proposal and self.ike_sa_keyring as a result
        """
        payload_sa = request.get_payload(Payload.Type.SA, encrypted)
        payload_nonce = request.get_payload(Payload.Type.NONCE, encrypted)
        payload_ke = request.get_payload(Payload.Type.KE, encrypted)

        # check cookie
        if self.cookie_secret is not None:
            expected_cookie = HMAC(self.cookie_secret, request.spi_i + payload_nonce.nonce + self.peer_addr.packed,
                                   digestmod=hashlib.sha256).digest()
            received_cookies = request.get_notifies(PayloadNOTIFY.Type.COOKIE)
            if len(received_cookies) == 0 or received_cookies[0].notification_data != expected_cookie:
                raise CookieRequired('COOKIE is required', cookie=expected_cookie)

        # select the proposal and generate a response Payload SA
        self.chosen_proposal = self._select_best_sa_proposal(self.configuration.proposal, payload_sa)
        # if this is a rekey, hence spi is not empty, send ours
        if self.chosen_proposal.spi:
            self.chosen_proposal.spi = self.my_spi
        response_payload_sa = PayloadSA([self.chosen_proposal])

        # generate payload NONCE
        response_payload_nonce = PayloadNONCE()

        # check that DH groups match and generate response Payload KE
        my_dh_group = self.chosen_proposal.get_transform(Transform.Type.DH).id
        if my_dh_group != payload_ke.dh_group:
            raise InvalidKePayload('Invalid DH group used. I want {}'.format(my_dh_group), group=my_dh_group)
        dh = DiffieHellman.from_group(payload_ke.dh_group)
        dh.compute_secret(payload_ke.ke_data)
        self.log_debug(f'Generated DH shared secret: {dh.shared_secret.hex()}')
        response_payload_ke = PayloadKE(dh.group, dh.public_key)

        # generate IKE SA key material
        self.ike_sa_keyring = self.generate_ike_sa_key_material(ike_proposal=self.chosen_proposal,
                                                                nonce_i=payload_nonce.nonce,
                                                                nonce_r=response_payload_nonce.nonce,
                                                                spi_i=self.peer_spi, spi_r=self.my_spi,
                                                                shared_secret=dh.shared_secret, old_sk_d=old_sk_d)

        return [response_payload_sa, response_payload_nonce, response_payload_ke]

    def process_ike_sa_init_request(self, request):
        """ Processes a IKE_SA_INIT message and returns a IKE_SA_INIT response
        """
        self._check_in_states(request, [IkeSa.State.INITIAL])

        # process the IKE_SA negotiation payloads
        response_payloads = self._process_ike_sa_negotiation_request(request, False)

        # generate the response payload VENDOR
        response_payloads.append(PayloadVENDOR(b'pyikev2-0.1'))

        # generate the message
        response = self.generate_response(Message.Exchange.IKE_SA_INIT, response_payloads)

        # switch state
        self.state = IkeSa.State.INIT_RES_SENT

        # store messages for later authentication
        self.ike_sa_init_req_data = request.to_bytes()
        self.ike_sa_init_res_data = response.to_bytes()

        # return response
        return response

    def _generate_ike_sa_negotiation_request(self):
        # create the Payload SA
        self.chosen_proposal = self.configuration.proposal
        self.chosen_proposal.spi = self.my_spi
        payload_sa = PayloadSA([self.chosen_proposal])

        # generate payload NONCE
        payload_nonce = PayloadNONCE()

        # create DH and Paylaod KE
        my_dh_group = self.chosen_proposal.get_transform(Transform.Type.DH).id
        self.dh = DiffieHellman.from_group(my_dh_group)
        payload_ke = PayloadKE(my_dh_group, self.dh.public_key)

        return [payload_sa, payload_nonce, payload_ke]

    def generate_ike_sa_init_request(self, child_sa):
        """ Creates a IKE_SA_INIT message
        """
        # check state
        assert (self.state == IkeSa.State.INITIAL)

        # generate the IKE SA negotiation payloads
        ike_sa_payloads = self._generate_ike_sa_negotiation_request()

        # create the payload VENDOR
        payload_vendor = PayloadVENDOR(b'pyikev2-0.1')

        # generate the message
        self.request = self.generate_request(Message.Exchange.IKE_SA_INIT, ike_sa_payloads + [payload_vendor])

        # switch state
        self.state = IkeSa.State.INIT_REQ_SENT

        # save the message for later authentication
        self.ike_sa_init_req_data = self.request.to_bytes()

        # store the child sa to be used in the IKE_AUTH exchange
        self.creating_child_sa = child_sa

        # return request
        return self.request

    def generate_rekey_ike_sa_request(self):
        """ Creates a IKE_SA_INIT message
        """
        # check state
        assert (self.state == IkeSa.State.ESTABLISHED)

        self.new_ike_sa = IkeSa(True, b'', self.configuration, self.my_addr, self.peer_addr, disableXfrm = self.disableXfrm)

        # generate the IKE SA negotiation payloads
        ike_sa_payloads = self.new_ike_sa._generate_ike_sa_negotiation_request()

        # generate the message
        self.request = self.generate_request(Message.Exchange.CREATE_CHILD_SA, ike_sa_payloads)

        # switch state
        self.state = IkeSa.State.REK_IKE_SA_REQ_SENT

        # return request
        return self.request

    @property
    def spi_i(self):
        return self.my_spi if self.is_initiator else self.peer_spi

    @property
    def spi_r(self):
        return self.peer_spi if self.is_initiator else self.my_spi

    def _generate_child_sa_negotiation_req(self, child_sa):
        result = []

        # generate Payload TSi, TSr
        result.append(PayloadTSi(child_sa.tsi))
        result.append(PayloadTSr(child_sa.tsr))

        # generate Payload SA
        child_sa.proposal.spi = child_sa.inbound_spi
        result.append(PayloadSA([child_sa.proposal]))

        # generate Payload KE (if required)
        try:
            my_dh_group = child_sa.proposal.get_transform(Transform.Type.DH).id
            self.dh = DiffieHellman.from_group(my_dh_group)
            result.append(PayloadKE(my_dh_group, self.dh.public_key))
        except StopIteration:
            pass

        # generate USE_TRANSPORT_MODE notify if needed
        if child_sa.mode == xfrm.Mode.TRANSPORT:
            result.append(PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.USE_TRANSPORT_MODE))

        return result

    def generate_ike_auth_request(self):
        """ Creates a IKE_AUTH request message
        """
        assert (self.state == IkeSa.State.INIT_REQ_SENT)

        # generate the CHILD_SA negotiation payloads
        if self.creating_child_sa is not None:
            child_sa_payloads = self._generate_child_sa_negotiation_req(self.creating_child_sa)
        else:
            child_sa_payloads = []

        # generate IDi
        payload_idi = PayloadIDi(self.configuration.my_auth.id.id_type, self.configuration.my_auth.id.id_data)

        # generate Payload AUTH
        ike_sa_init_res = Message.parse(self.ike_sa_init_res_data)
        payload_auth = self._generate_auth_payload(self.ike_sa_init_req_data,
                                                   ike_sa_init_res.get_payload(Payload.Type.NONCE).nonce, payload_idi,
                                                   self.my_crypto.sk_p)

        # generate the message
        payloads = child_sa_payloads + [payload_idi]
        if payload_auth is not None:
            payloads += [payload_auth]
        self.lastAuthRequestPayloads = payloads
        self.request = self.generate_request(Message.Exchange.IKE_AUTH, payloads)

        # transition
        self.state = IkeSa.State.AUTH_REQ_SENT

        return self.request

    def process_ike_sa_negotiation_response(self, response, nonce, encrypted=False, old_sk_d=None):
        """ Process a IKE_SA negotiation response (SA, Ni, KEi)
        """
        payload_sa = response.get_payload(Payload.Type.SA, encrypted)
        payload_nonce = response.get_payload(Payload.Type.NONCE, encrypted)
        payload_ke = response.get_payload(Payload.Type.KE, encrypted)

        # select the peers proposal.
        if not payload_sa.proposals[0].is_subset(self.chosen_proposal):
            raise NoProposalChosen('Responder proposal is not a subset of what we sent')
        self.chosen_proposal = payload_sa.proposals[0]

        # update peer spi (take it from the payload SA if old_sa_d is not none ie. IKE_SA rekey)
        self.peer_spi = response.spi_r if old_sk_d is None else self.chosen_proposal.spi

        self.dh.compute_secret(payload_ke.ke_data)
        self.log_debug(f'Generated DH shared secret: {self.dh.shared_secret.hex()}')

        # generate IKE SA key material
        self.ike_sa_keyring = self.generate_ike_sa_key_material(
            ike_proposal=self.chosen_proposal,
            nonce_i=nonce,
            nonce_r=payload_nonce.nonce,
            spi_i=self.my_spi,
            spi_r=self.peer_spi,
            shared_secret=self.dh.shared_secret,
            old_sk_d=old_sk_d)

    def abort_on_error_notifies(self, message, encrypted=False, ignore=None):
        for notification in message.get_payloads(Payload.Type.NOTIFY, encrypted=encrypted):
            if notification.is_error() and (ignore is None or notification.notification_type not in ignore):
                raise IkeSaError(f'Could not establish IKE_SA due to error notification '
                                 f'received: {notification.notification_type.name}')

    def process_ike_sa_init_response(self, response):
        """ Processes a IKE_SA_INIT response message
        """
        self._check_in_states(response, [IkeSa.State.INIT_REQ_SENT])

        # Recover from INVALID_KE_PAYLOAD
        invalid_ke = response.get_notifies(PayloadNOTIFY.Type.INVALID_KE_PAYLOAD)
        if invalid_ke:
            self.my_msg_id = 0
            self.dh, self.request = self.handle_invalid_ke(invalid_ke)
            self.ike_sa_init_req_data = self.request.to_bytes()
            return self.request

        # Recover from COOKIE
        cookie = response.get_notifies(PayloadNOTIFY.Type.COOKIE)
        if cookie:
            self.log_warning("COOKIE notification received. Trying including the COOKIE")
            self.request.payloads.insert(0, cookie[0])
            self.ike_sa_init_req_data = self.request.to_bytes()
            self.my_msg_id = 0
            return self.request

        # Check error notifications
        self.abort_on_error_notifies(response)

        # process the IKE_SA negotiation payloads
        self.process_ike_sa_negotiation_response(response, self.request.get_payload(Payload.Type.NONCE).nonce)

        # save the message for later authentication
        self.ike_sa_init_res_data = response.to_bytes()

        # return IKE_AUTH request callback
        return self.generate_ike_auth_request()

    def _generate_psk_auth_payload(self, psk, data_to_be_signed):
        keypad = self.my_crypto.prf.prf(psk, b'Key Pad for IKEv2')
        return PayloadAUTH(PayloadAUTH.Method.PSK, self.my_crypto.prf.prf(keypad, data_to_be_signed))

    def _generate_rsa_auth_payload(self, data_to_be_signed):
        return PayloadAUTH(PayloadAUTH.Method.RSA, self.configuration.my_auth.privkey.sign(data_to_be_signed))

    def _verify_rsa_auth_payload(self, authdata, data_to_be_signed):
        if not self.configuration.peer_auth.pubkey:
            return False
        return self.configuration.peer_auth.pubkey.verify(authdata, data_to_be_signed, self.my_crypto.prf.hasher)

    def _verify_cert_auth_payload(self, cert, authdata, data_to_be_signed):
        return cert.verify(authdata, data_to_be_signed, self.my_crypto.prf.hasher)

    def _generate_auth_payload(self, message_data, nonce, payload_id, sk_p):
        data_to_be_signed = (message_data + nonce + self.my_crypto.prf.prf(sk_p, payload_id.to_bytes()))
        if self.configuration.my_auth.privkey:
            return self._generate_rsa_auth_payload(data_to_be_signed)
        elif self.configuration.my_auth.psk:
            return self._generate_psk_auth_payload(self.configuration.my_auth.psk, data_to_be_signed)
        elif self.configuration.my_auth.eap:
            return None # is iniated by peer
        else:
            raise AuthenticationFailed('Could not generate AUTH payload due to a lack of auth configuration')

    def _verify_auth_payload(self, payload_auth, message_data, nonce, payload_id, sk_p, certs = None):
        data_to_be_signed = (message_data + nonce + self.my_crypto.prf.prf(sk_p, payload_id.to_bytes()))
        if payload_auth.method == PayloadAUTH.Method.PSK and self.configuration.peer_auth.psk:
            if self._generate_psk_auth_payload(self.configuration.peer_auth.psk, data_to_be_signed) != payload_auth:
                raise AuthenticationFailed('PSK authentication failed')
        elif payload_auth.method == PayloadAUTH.Method.RSA and self.configuration.peer_auth.pubkey:
            if not self._verify_rsa_auth_payload(payload_auth.auth_data, data_to_be_signed):
                raise AuthenticationFailed('RSA authentication failed')
        elif payload_auth.method == PayloadAUTH.Method.RSA and self.configuration.peer_auth.certfp is not None:
            if certs is None or len(certs) < 1:
                raise AuthenticationFailed('RSA authentication failed - No certificate send by peer')
            if certs[0].encoding != PayloadCERT.Encoding.X509CertificateSignature:
                raise AuthenticationFailed('RSA authentication failed - Certificate encoding used by peer not supported')

            peerCert = Certificate(certs[0].cert_data)
            peerCertFp = peerCert.fingerprint()
            if self.configuration.peer_auth.certfp != peerCertFp:
                raise AuthenticationFailed(f'RSA authentication failed - Certificate send by peer has fingerprint {peerCertFp}')

            if not self._verify_cert_auth_payload(peerCert, payload_auth.auth_data, data_to_be_signed):
                raise AuthenticationFailed('RSA authentication failed (using certificate from peer)')
        elif self.configuration.peer_auth.ignore:
            self.log_warning('Ignore peer authentication signature')
        else:
            raise AuthenticationFailed('Authentication method not supported')

    def _process_create_child_sa_negotiation_req(self, request):
        """ This method process a CREATE CHILD SA negotiation request
        """
        # get some relevant payloads from the message
        response_payloads = []
        try:
            request_payload_sa = request.get_payload(Payload.Type.SA, True)
            request_payload_tsi = request.get_payload(Payload.Type.TSi, True)
            request_payload_tsr = request.get_payload(Payload.Type.TSr, True)

            # if we are doing anything with the IKE_SA (either rekeying or deleting), return TEMPORARY_FAILURE
            if self.state in (IkeSa.State.REK_IKE_SA_REQ_SENT, IkeSa.State.DEL_IKE_SA_REQ_SENT):
                raise TemporaryFailure(f'The IKE_SA state ({self.state.name}) does not accept new CHILD_SAs')

            # handle REKEY specifics
            rekey_notify = request.get_notifies(PayloadNOTIFY.Type.REKEY_SA, encrypted=True)
            if rekey_notify:
                # use only the first notification
                rekeyed_child_sa = self.get_child_sa(rekey_notify[0].spi)
                if rekeyed_child_sa is None:
                    raise ChildSaNotFound('The indicated SPI could not be found', spi=rekey_notify[0].spi,
                                          protocol=rekey_notify[0].protocol_id)
                # if we are deleting that SA, return TEMPORARY_FAILURE
                if self.state == IkeSa.State.DEL_CHILD_REQ_SENT and rekeyed_child_sa == self.deleting_child_sa:
                    raise TemporaryFailure('The indicated SPI is already being deleted')
                # if we are rekeying that SA, note there will be a redundant SA
                if self.state == IkeSa.State.REK_CHILD_REQ_SENT and rekeyed_child_sa == self.rekeying_child_sa:
                    raise TemporaryFailure('The indicated SPI is already being rekeyed')

                if (request_payload_tsi.traffic_selectors != [rekeyed_child_sa.tsr]
                        or request_payload_tsr.traffic_selectors != [rekeyed_child_sa.tsi]):
                    raise TsUnacceptable('Proposed Traffic Selectors do not match with those for the rekeyed CHILD_SA')

                response_payloads.append(PayloadNOTIFY(request_payload_sa.proposals[0].protocol_id,
                                                       PayloadNOTIFY.Type.REKEY_SA, rekeyed_child_sa.inbound_spi))

            # source of nonces is different for the initial exchange
            if request.exchange_type == Message.Exchange.IKE_AUTH:
                ike_sa_init_req = Message.parse(self.ike_sa_init_req_data)
                ike_sa_init_res = Message.parse(self.ike_sa_init_res_data)
                request_payload_nonce = ike_sa_init_req.get_payload(Payload.Type.NONCE)
                response_payload_nonce = ike_sa_init_res.get_payload(Payload.Type.NONCE)
            else:
                request_payload_nonce = request.get_payload(Payload.Type.NONCE, encrypted=True)
                response_payload_nonce = PayloadNONCE()
                response_payloads.append(response_payload_nonce)

            # Find matching IPsec configuration and narrow TS (reverse order as we are responders)
            ipsec_conf, chosen_tsr, chosen_tsi = self._get_ipsec_configuration(request_payload_tsi,
                                                                               request_payload_tsr)

            # check which mode peer wants and compare to ours
            requested_mode = xfrm.Mode.TUNNEL
            if request.get_notifies(PayloadNOTIFY.Type.USE_TRANSPORT_MODE, True):
                requested_mode = xfrm.Mode.TRANSPORT
                response_payloads.append(PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.USE_TRANSPORT_MODE))

            if ipsec_conf.mode != requested_mode:
                raise TsUnacceptable(f'Invalid mode requested. Requested={requested_mode.name}. '
                                     f'Desired={ipsec_conf.mode.name}')

            # generate the response payload SA with the chosen proposal
            my_proposal = (ipsec_conf.proposal.copy_without_dh_transforms()
                           if request.exchange_type == Message.Exchange.IKE_AUTH else ipsec_conf.proposal)
            chosen_child_proposal = self._select_best_sa_proposal(my_proposal, request_payload_sa)

            keyseed = request_payload_nonce.nonce + response_payload_nonce.nonce
            # if KE exchange is required
            if chosen_child_proposal.get_transforms(Transform.Type.DH):
                request_payload_ke = request.get_payload(Payload.Type.KE, True)
                my_dh_group = chosen_child_proposal.get_transform(Transform.Type.DH).id
                if my_dh_group != request_payload_ke.dh_group:
                    raise InvalidKePayload('Invalid DH group used. I want {}'.format(my_dh_group), group=my_dh_group)
                dh = DiffieHellman.from_group(request_payload_ke.dh_group)
                dh.compute_secret(request_payload_ke.ke_data)
                keyseed = dh.shared_secret + keyseed
                self.log_debug(f'Generated CHILD_SA DH shared secret: {dh.shared_secret.hex()}')
                response_payloads.append(PayloadKE(dh.group, dh.public_key))

            # generate CHILD key material
            child_sa_keyring = self.generate_child_sa_key_material(child_proposal=chosen_child_proposal,
                                                                   keyseed=keyseed, sk_d=self.ike_sa_keyring.sk_d)

            # create the IPsec SAs according to the negotiated CHILD SA
            child_sa = ChildSa(outbound_spi=chosen_child_proposal.spi, inbound_spi=os.urandom(4),
                               proposal=chosen_child_proposal, tsi=chosen_tsr, tsr=chosen_tsi, mode=requested_mode,
                               lifetime=ipsec_conf.lifetime, original_proposal=ipsec_conf.proposal)

            self.child_sas.append(child_sa)
            if not self.disableXfrm:
                xfrm.Xfrm.create_child_sa(self, child_sa, child_sa_keyring, is_initiator=False)
                self.log_info('Created CHILD_SA {} with lifetime = {}'.format(child_sa, child_sa.lifetime))
            else:
                self.log_info('SKIPPED Created CHILD_SA {} with lifetime = {}'.format(child_sa, child_sa.lifetime))

            # generate the response Payload SA
            chosen_child_proposal.spi = child_sa.inbound_spi
            response_payloads.append(PayloadSA([chosen_child_proposal]))

            # generate response Payload TSi/TSr based on the chosen selectors
            response_payloads.append(PayloadTSi([chosen_tsi]))
            response_payloads.append(PayloadTSr([chosen_tsr]))

            return response_payloads
        except (TsUnacceptable, NoProposalChosen, ChildSaNotFound, TemporaryFailure, InvalidKePayload) as ex:
            self.log_warning('CHILD_SA negotiation failed. {}'.format(ex))
            return [PayloadNOTIFY.from_exception(ex)]
        # Generic error happening while negotiating the CHILD_SA should be reported as NO_PROPOSAL_CHOSEN
        except (IkeSaError, xfrm.NetlinkError) as ex:
            self.log_warning('CHILD_SA negotiation failed. {}'.format(ex))
            return [PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN)]

    def _check_in_states(self, message, list_of_valid_states):
        if self.state not in list_of_valid_states:
            raise IkeSaStateError(
                'Cannot process an {} {} when in state {}.'.format(message.exchange_type.name,
                                                                   'request' if message.is_request else 'response',
                                                                   self.state.name))

    def check_retransmission_timer(self):
        # retransmissions only when we sent a request
        if (self.state in range(IkeSa.State.NEW_CHILD_REQ_SENT, IkeSa.State.REKEYED)
                or self.state == IkeSa.State.INIT_REQ_SENT or self.state == IkeSa.State.AUTH_REQ_SENT):
            if self.retransmit_at < time.time():
                if self.retransmissions >= IkeSa.MAX_RETRANSMISSIONS:
                    self.log_warning('Done retransmitting last request. Unilaterally closing the IKE_SA')
                    self.state = IkeSa.State.DELETED
                    return None
                self.retransmissions += 1
                self.retransmit_at = self.retransmit_at + self.retransmissions * IkeSa.RETRANSMISSION_DELAY
                ordinal = lambda n: "%d%s" % (n, "tsnrhtdd"[(n / 10 % 10 != 1) * (n % 10 < 4) * n % 10::4])
                self.log_info('Retransmitting last request for {} time'.format(ordinal(self.retransmissions)))
                return self.request.to_bytes()
        return None

    def process_ike_auth_request(self, request):
        """ Processes a IKE_AUTH request message and returns a
            IKE_AUTH response
        """
        self._check_in_states(request, [IkeSa.State.INIT_RES_SENT])

        # get some relevant payloads from the message
        request_payload_idi = request.get_payload(Payload.Type.IDi, True)
        request_payload_auth = request.get_payload(Payload.Type.AUTH, True)

        ike_sa_init_req = Message.parse(self.ike_sa_init_req_data)
        ike_sa_init_res = Message.parse(self.ike_sa_init_res_data)

        if request_payload_idi.id_type != self.configuration.peer_auth.id.id_type:
            raise AuthenticationFailed(f'Received ID type does not match with the configured one for the peer: rx {request_payload_idi.id_type.hex()} != cfg {self.configuration.peer_auth.id.id_type.hex()}')

        if request_payload_idi.id_data != self.configuration.peer_auth.id.id_data:
            raise AuthenticationFailed(f'Received ID data does not match with the configured one for the peer: rx {request_payload_idi.id_data.hex()} != cfg {self.configuration.peer_auth.id.id_data.hex()}')

        self._verify_auth_payload(request_payload_auth, self.ike_sa_init_req_data,
                                  ike_sa_init_res.get_payload(Payload.Type.NONCE).nonce, request_payload_idi,
                                  self.peer_crypto.sk_p)

        # process the CHILD_SA creation negotiation
        response_payloads = self._process_create_child_sa_negotiation_req(request)

        # generate IDr
        response_payload_idr = PayloadIDr(self.configuration.my_auth.id.id_type, self.configuration.my_auth.id.id_data)

        # generate AUTH payload
        response_payload_auth = self._generate_auth_payload(self.ike_sa_init_res_data,
                                                            ike_sa_init_req.get_payload(Payload.Type.NONCE).nonce,
                                                            response_payload_idr, self.my_crypto.sk_p)

        response_payloads += [response_payload_idr]
        if response_payload_auth is not None:
            response_payloads += [response_payload_auth]

        # generate the message
        response = self.generate_response(Message.Exchange.IKE_AUTH, response_payloads)

        # increase msg_id and transition
        self.state = IkeSa.State.ESTABLISHED

        return response

    def _process_create_child_sa_negotiation_res(self, response):
        for error in (PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN, PayloadNOTIFY.Type.TS_UNACCEPTABLE,
                      PayloadNOTIFY.Type.CHILD_SA_NOT_FOUND, PayloadNOTIFY.Type.TEMPORARY_FAILURE,
                      PayloadNOTIFY.Type.NO_ADDITIONAL_SAS):
            if response.get_notifies(error, True):
                raise ChildSaRejectedError(
                    f'CHILD_SA negotiation failed because {error.name}. Skipping creation of CHILD_SA.')

        # get some relevant payloads from the message
        response_payload_sa = response.get_payload(Payload.Type.SA, True)
        response_payload_tsi = response.get_payload(Payload.Type.TSi, True)
        response_payload_tsr = response.get_payload(Payload.Type.TSr, True)
        response_transport_mode = response.get_notifies(PayloadNOTIFY.Type.USE_TRANSPORT_MODE, True)

        # source of nonces is different for the initial exchange
        if response.exchange_type == Message.Exchange.IKE_AUTH:
            # parse IKE_SA_INIT req and response
            ike_sa_init_req = Message.parse(self.ike_sa_init_req_data)
            ike_sa_init_res = Message.parse(self.ike_sa_init_res_data)
            request_payload_nonce = ike_sa_init_req.get_payload(Payload.Type.NONCE)
            response_payload_nonce = ike_sa_init_res.get_payload(Payload.Type.NONCE)
        else:
            request_payload_nonce = self.request.get_payload(Payload.Type.NONCE, True)
            response_payload_nonce = response.get_payload(Payload.Type.NONCE, True)

        # check mode is consistent
        response_mode = xfrm.Mode.TRANSPORT if response_transport_mode else xfrm.Mode.TUNNEL
        if self.creating_child_sa.mode != response_mode:
            raise TsUnacceptable(f'Invalid mode received. Requested={self.creating_child_sa.mode.name}. '
                                 f'Received={response_mode.name}')

        # Check responder provided a valid proposal
        my_proposal = (self.creating_child_sa.proposal.copy_without_dh_transforms()
                       if response.exchange_type == Message.Exchange.IKE_AUTH else self.creating_child_sa.proposal)
        chosen_child_proposal = response_payload_sa.proposals[0]
        intersection = my_proposal.intersection(chosen_child_proposal)
        if intersection is None or intersection != chosen_child_proposal:
            raise NoProposalChosen('Responder did not choose a valid proposal')

        # generate CHILD key material
        keyseed = request_payload_nonce.nonce + response_payload_nonce.nonce

        # if KE exchange is required
        if chosen_child_proposal.get_transforms(Transform.Type.DH):
            response_payload_ke = response.get_payload(Payload.Type.KE, True)
            self.dh.compute_secret(response_payload_ke.ke_data)
            keyseed = self.dh.shared_secret + keyseed
            self.log_debug(f'Generated CHILD_SA DH shared secret: {self.dh.shared_secret.hex()}')

        child_sa_keyring = self.generate_child_sa_key_material(child_proposal=chosen_child_proposal,
                                                               keyseed=keyseed, sk_d=self.ike_sa_keyring.sk_d)

        # Check TSi and TSr are subsets of what we sent
        chosen_tsi = response_payload_tsi.traffic_selectors[0]
        chosen_tsr = response_payload_tsr.traffic_selectors[0]
        matches_tsi = [x for x in self.creating_child_sa.tsi if chosen_tsi.is_subset(x)]
        matches_tsr = [x for x in self.creating_child_sa.tsr if chosen_tsr.is_subset(x)]
        if not matches_tsi or not matches_tsr:
            raise TsUnacceptable('Responder did not select a subset of our proposed TS.')

        # create the IPsec SAs according to the negotiated CHILD SA
        self.creating_child_sa = self.creating_child_sa._replace(outbound_spi=chosen_child_proposal.spi,
                                                                 proposal=chosen_child_proposal, tsi=chosen_tsi,
                                                                 tsr=chosen_tsr)
        self.child_sas.append(self.creating_child_sa)
        if not self.disableXfrm:
            xfrm.Xfrm.create_child_sa(self, self.creating_child_sa, child_sa_keyring, is_initiator=True)
            self.log_info(f'Created CHILD_SA {self.creating_child_sa}')
        else:
            self.log_info(f'SKIPPED Created CHILD_SA {self.creating_child_sa}')

    def process_ike_auth_response(self, response):
        self._check_in_states(response, [IkeSa.State.AUTH_REQ_SENT])

        # check there are no notifies
        self.abort_on_error_notifies(response, encrypted=True, ignore=[PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN,
                                                                       PayloadNOTIFY.Type.TS_UNACCEPTABLE])

        # get some relevant payloads from the message
        try:
            response_payload_idr = response.get_payload(Payload.Type.IDr, True)
            self.lastPeerIdr = response_payload_idr
        except PayloadNotFound as ex:
            if self.lastPeerIdr is None or self.eapClient is None or not self.eapClient.running:
                raise ex
            response_payload_idr = self.lastPeerIdr
        
        response_payload_certs = response.get_payloads(Payload.Type.CERT, True)
        if len(response_payload_certs) < 1:
            response_payload_certs = self.lastPeerCerts
        else:
            self.lastPeerCerts = response_payload_certs

        response_payload_eaps = response.get_payloads(Payload.Type.EAP, True)

        try:
            response_payload_auth = response.get_payload(Payload.Type.AUTH, True)
            if response_payload_idr.id_type != self.configuration.peer_auth.id.id_type:
                raise AuthenticationFailed(f'Received ID type does not match with the configured one for the peer: rx {response_payload_idr.id_type.hex()} != cfg {self.configuration.peer_auth.id.id_type.hex()}')

            if response_payload_idr.id_data != self.configuration.peer_auth.id.id_data:
                raise AuthenticationFailed(f'Received ID data does not match with the configured one for the peer: rx {response_payload_idr.id_data.hex()} != cfg {self.configuration.peer_auth.id.id_data.hex()}')

            ike_sa_init_req = Message.parse(self.ike_sa_init_req_data)
            self._verify_auth_payload(response_payload_auth, self.ike_sa_init_res_data,
                                      ike_sa_init_req.get_payload(Payload.Type.NONCE).nonce,
                                      response_payload_idr, self.peer_crypto.sk_p, certs = response_payload_certs)
        except PayloadNotFound as ex:
            if self.eapClient is None or not self.eapClient.running:
                raise ex
            response_payload_auth = None

        # Handle EAP
        if len(response_payload_eaps) > 1:
            raise AuthenticationFailed("Too many EAP")
        elif len(response_payload_eaps) > 0 and self.eapClient:
            eapReply = self.eapClient.handleMessage(response_payload_eaps[0].eap_message)
            if not isinstance(eapReply, bool):
                self.log_debug('Sending EAP reply')
                payloads = self.lastAuthRequestPayloads + [PayloadEAP(eapReply)]
                self.request = self.generate_request(Message.Exchange.IKE_AUTH, payloads)
                return self.request
            if not eapReply:
                raise AuthenticationFailed("EAP Failure")
        elif len(response_payload_eaps) > 0:
            raise AuthenticationFailed("EAP requested but not configured")

        # process the CHILD_SA creation negotiation
        try:
            if self.creating_child_sa is not None:
                self._process_create_child_sa_negotiation_res(response)
        except ChildSaRejectedError as ex:
            self.log_warning(str(ex))
        except IkeSaError as ex:
            self.log_warning(f'Peer created an invalid CHILD_SA: {ex}. Deleting it')
            if self.creating_child_sa is not None:
                return self.generate_delete_child_sa_request(self.creating_child_sa)
            else:
                return None
        self.state = IkeSa.State.ESTABLISHED
        return None
    
    def generate_create_child_sa_request(self, child_sa, rekeyed_child_sa=None):
        """ Creates a CREATE_CHILD_SA request message for creating a new CHILD or rekeying an existing one
        """
        assert (self.state == IkeSa.State.ESTABLISHED)

        # preserve the acquire for the response
        self.creating_child_sa = child_sa

        # generate the CHILD_SA negotiation payloads
        child_sa_payloads = self._generate_child_sa_negotiation_req(child_sa)
        if rekeyed_child_sa is not None:
            self.rekeying_child_sa = rekeyed_child_sa
            child_sa_payloads.insert(0, PayloadNOTIFY(rekeyed_child_sa.proposal.protocol_id,
                                                      PayloadNOTIFY.Type.REKEY_SA,
                                                      rekeyed_child_sa.inbound_spi, b''))

        # generate Payload NONCE
        payload_nonce = PayloadNONCE()

        # generate the message
        self.request = self.generate_request(Message.Exchange.CREATE_CHILD_SA, child_sa_payloads + [payload_nonce])

        # transition
        self.state = (IkeSa.State.NEW_CHILD_REQ_SENT if rekeyed_child_sa is None
                      else IkeSa.State.REK_CHILD_REQ_SENT)

        return self.request

    def generate_delete_child_sa_request(self, child_sa):
        """ Creates an INFORMATIONAL message for deleting a CHILD_SA
        """
        assert (self.state == IkeSa.State.ESTABLISHED)

        payload_delete = PayloadDELETE(child_sa.proposal.protocol_id, [child_sa.inbound_spi])

        # generate the message
        self.request = self.generate_request(Message.Exchange.INFORMATIONAL, [payload_delete])

        # transition
        self.state = IkeSa.State.DEL_CHILD_REQ_SENT
        self.deleting_child_sa = child_sa
        return self.request

    def process_informational_request(self, request):
        """ Processes an INFORMATIONAL request
        """
        self._check_in_states(request, range(IkeSa.State.ESTABLISHED, IkeSa.State.REKEYED + 1))

        response_payloads = []
        delete_payloads = request.get_payloads(Payload.Type.DELETE, True)
        if not delete_payloads:
            self.log_info('Peer requested DEAD-PEER-DETECTION')

        for delete_payload in delete_payloads:
            # if protocol is IKE, just mark the IKE SA for removal and return emtpy INFORMATIONAL exchange
            if delete_payload.protocol_id == Proposal.Protocol.IKE:
                self.log_info('Deleting this IKE_SA')
                self.state = IkeSa.State.DELETED
                response_payloads = []
                break
            # if protocol is either AH or ESP, delete the Child SAs and return the inbound SPI
            elif delete_payload.protocol_id in (Proposal.Protocol.AH, Proposal.Protocol.ESP):
                for del_spi in delete_payload.spis:
                    child_sa = self.get_child_sa(del_spi)
                    if child_sa is not None and child_sa.proposal.protocol_id == delete_payload.protocol_id:
                        if not self.disableXfrm:
                            xfrm.Xfrm.delete_child_sa(self, child_sa)
                        self.child_sas.remove(child_sa)
                        response_payloads.append(PayloadDELETE(delete_payload.protocol_id, [child_sa.inbound_spi]))
                        self.log_info('Removing CHILD_SA {}'.format(child_sa))
                    else:
                        self.log_warning('The indicated SPI could not be found when attempting to delete a '
                                         f'Child SA: {del_spi.hex()}')

        return self.generate_response(Message.Exchange.INFORMATIONAL, response_payloads)

    def process_create_child_sa_request(self, request):
        """ Processes a CREATE_CHILD_SA message and returns response
        """
        self._check_in_states(request, range(IkeSa.State.ESTABLISHED, IkeSa.State.REKEYED))

        # determine whether this concerns to IKE_SA or CHILD_SA
        payload_sa = request.get_payload(Payload.Type.SA, True)
        proposal = payload_sa.proposals[0]

        # if this is a IKE_REKEY
        if proposal.protocol_id == Proposal.Protocol.IKE:
            self.log_info('Received request for rekeying current IKE_SA')
            if self.state != IkeSa.State.ESTABLISHED:
                self.log_warning('Cannot process IKE_SA rekeying while doing anything else. Sending TEMPORARY_FAILURE')
                response_payloads = [PayloadNOTIFY.from_exception(TemporaryFailure())]
            else:
                self.new_ike_sa = IkeSa(False, proposal.spi, self.configuration, self.my_addr, self.peer_addr, disableXfrm = self.disableXfrm)
                # take over the existing child sas
                self.new_ike_sa.child_sas = self.child_sas
                self.child_sas = []
                response_payloads = self.new_ike_sa._process_ike_sa_negotiation_request(request, True,
                                                                                        self.ike_sa_keyring.sk_d)
                self.new_ike_sa.state = IkeSa.State.ESTABLISHED
                self.state = IkeSa.State.REKEYED
        # if it is a to CHILD_SAs
        else:
            response_payloads = self._process_create_child_sa_negotiation_req(request)

        return self.generate_response(Message.Exchange.CREATE_CHILD_SA, response_payloads)

    def get_child_sa(self, spi):
        try:
            return next(x for x in self.child_sas if spi == x.inbound_spi or spi == x.outbound_spi)
        except StopIteration:
            return None

    def handle_invalid_ke(self, invalid_ke):
        invalid_ke = invalid_ke[0]
        encrypted = self.request.exchange_type > Message.Exchange.IKE_SA_INIT
        my_proposal = self.request.get_payload(Payload.Type.SA, encrypted).proposals[0]
        suggested_group = unpack('>H', invalid_ke.notification_data)[0]
        self.log_warning(
            f"INVALID_KE_PAYLOAD notification received. Trying with the suggested group: {suggested_group}")
        if suggested_group not in (x.id for x in my_proposal.transforms if x.type == Transform.Type.DH):
            raise NoProposalChosen(
                'Suggested DH group is not included in our proposal. Possible downgrade attack detected.')
        new_dh = DiffieHellman.from_group(suggested_group)
        payload_ke = self.request.get_payload(Payload.Type.KE, encrypted)
        payload_ke.dh_group = suggested_group
        payload_ke.ke_data = new_dh.public_key
        return new_dh, self.generate_request(self.request.exchange_type,
                                             self.request.encrypted_payloads if encrypted else self.request.payloads)

    def process_create_child_sa_response(self, response):
        """ Processes a CREATE_CHILD_SA response message
        """
        self._check_in_states(response, [IkeSa.State.NEW_CHILD_REQ_SENT, IkeSa.State.REK_CHILD_REQ_SENT,
                                         IkeSa.State.REK_IKE_SA_REQ_SENT])
        self.abort_on_error_notifies(response, True, ignore=[PayloadNOTIFY.Type.TS_UNACCEPTABLE,
                                                             PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN,
                                                             PayloadNOTIFY.Type.NO_ADDITIONAL_SAS,
                                                             PayloadNOTIFY.Type.SINGLE_PAIR_REQUIRED,
                                                             PayloadNOTIFY.Type.CHILD_SA_NOT_FOUND,
                                                             PayloadNOTIFY.Type.TEMPORARY_FAILURE,
                                                             PayloadNOTIFY.Type.INTERNAL_ADDRESS_FAILURE,
                                                             PayloadNOTIFY.Type.FAILED_CP_REQUIRED,
                                                             PayloadNOTIFY.Type.INVALID_KE_PAYLOAD,
                                                             PayloadNOTIFY.Type.INVALID_KE_PAYLOAD])
        # IKE_SA rekey response
        if self.state == IkeSa.State.REK_IKE_SA_REQ_SENT:
            # Recover from INVALID_KE_PAYLOAD
            invalid_ke = response.get_notifies(PayloadNOTIFY.Type.INVALID_KE_PAYLOAD, True)
            if invalid_ke:
                self.new_ike_sa.dh, new_request = self.handle_invalid_ke(invalid_ke)
                return new_request
            # If we are asked to wait, wait for a random amount of time before retrying to rekey the IKE_SA
            if response.get_notifies(PayloadNOTIFY.Type.TEMPORARY_FAILURE, True):
                self.log_debug('Push back IKE_SA rekey as we received TEMPORARY_FAILURE')
                self.state = IkeSa.State.ESTABLISHED
                self.rekey_ike_sa_at = time.time() + random.uniform(0, 2)
                return None
            # if we receive NO_ADDITIONAL_SAS it means responder does not support rekeying.
            elif response.get_notifies(PayloadNOTIFY.Type.NO_ADDITIONAL_SAS, True):
                self.log_debug('IKE_SA rekey was rejected with NO_ADDITIONAL_SAS. Deleting IKE_SA.')
                self.state = IkeSa.State.ESTABLISHED
                return self.generate_delete_ike_sa_request()
            else:
                # process the IKE_SA negotiation payloads
                self.new_ike_sa.process_ike_sa_negotiation_response(
                    response, self.request.get_payload(Payload.Type.NONCE, True).nonce, encrypted=True,
                    old_sk_d=self.ike_sa_keyring.sk_d)
                self.new_ike_sa.child_sas = self.child_sas
                self.child_sas = []
                self.state = IkeSa.State.REKEYED
                self.new_ike_sa.state = IkeSa.State.ESTABLISHED
                return self.generate_delete_ike_sa_request()
        # CHILD_SA create/rekey response
        else:
            # Recover from INVALID_KE_PAYLOAD
            invalid_ke = response.get_notifies(PayloadNOTIFY.Type.INVALID_KE_PAYLOAD, True)
            if invalid_ke:
                self.dh, new_request = self.handle_invalid_ke(invalid_ke)
                return new_request
            prev_state = self.state
            self.state = IkeSa.State.ESTABLISHED
            try:
                if self.creating_child_sa is not None:
                    self._process_create_child_sa_negotiation_res(response)
                if prev_state == IkeSa.State.REK_CHILD_REQ_SENT:
                    # CHILD_SA might have been deleted while we were waiting for our response
                    if self.rekeying_child_sa in self.child_sas:
                        return self.generate_delete_child_sa_request(self.rekeying_child_sa)
                    else:
                        self.log_warning(f'CHILD_SA {self.rekeying_child_sa} was already deleted. '
                                         f'Not starting a DELETE exchange')
            except ChildSaRejectedError as ex:
                self.log_warning(str(ex))
            except IkeSaError as ex:
                self.log_warning(f'Peer created an invalid CHILD_SA: {ex}. Deleting it')
                return self.generate_delete_child_sa_request(self.creating_child_sa)
            return None

    def process_informational_response(self, response):
        """ Processes a CREATE_CHILD_SA response message
        """
        self._check_in_states(response, [IkeSa.State.DEL_CHILD_REQ_SENT, IkeSa.State.DEL_IKE_SA_REQ_SENT,
                                         IkeSa.State.DPD_REQ_SENT, IkeSa.State.DEL_AFTER_REKEY_IKE_SA_REQ_SENT])
        self.abort_on_error_notifies(response, True)

        if self.state == IkeSa.State.DEL_CHILD_REQ_SENT:
            if self.deleting_child_sa not in self.child_sas:
                self.log_warning(f'CHILD_SA {self.deleting_child_sa} was already deleted by the peer. '
                                 f'Omitting actual deletion')
            else:
                # delete our side of the CHILD_SA
                if not self.disableXfrm:
                    xfrm.Xfrm.delete_child_sa(self, self.deleting_child_sa)
                self.child_sas.remove(self.deleting_child_sa)
                self.log_info(f'Removing CHILD_SA {self.deleting_child_sa}')
            self.state = IkeSa.State.ESTABLISHED
            return None

        elif self.state in (IkeSa.State.DEL_IKE_SA_REQ_SENT, IkeSa.State.DEL_AFTER_REKEY_IKE_SA_REQ_SENT):
            self.state = IkeSa.State.DELETED
            self.log_info('Deleting this IKE_SA')
            return None

        elif self.state == IkeSa.State.DPD_REQ_SENT:
            self.state = IkeSa.State.ESTABLISHED

    def generate_dead_peer_detection_request(self):
        """ Creates an INFORMATIONAL message for Dead Peer Detection
        """
        assert (self.state == IkeSa.State.ESTABLISHED)

        # generate the message
        self.request = self.generate_request(Message.Exchange.INFORMATIONAL, [])

        # transition
        self.state = IkeSa.State.DPD_REQ_SENT
        return self.request

    def generate_delete_ike_sa_request(self):
        assert (self.state in (IkeSa.State.ESTABLISHED, IkeSa.State.REKEYED))

        # generate the message
        self.request = self.generate_request(Message.Exchange.INFORMATIONAL,
                                             [PayloadDELETE(Proposal.Protocol.IKE, [])])

        # transition
        self.state = (IkeSa.State.DEL_IKE_SA_REQ_SENT if self.state == IkeSa.State.ESTABLISHED
                      else IkeSa.State.DEL_AFTER_REKEY_IKE_SA_REQ_SENT)
        return self.request
