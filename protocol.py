#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import json
import logging
import os
import socket
from collections import namedtuple
from ipaddress import ip_address, ip_network
from select import select
from struct import pack, unpack

import xfrm
from crypto import Cipher, Crypto, DiffieHellman, Integrity, Prf
from helpers import SafeIntEnum, hexstring
from message import (AuthenticationFailed, ChildSaNotFound, IkeSaError, InvalidKePayload, InvalidSelectors,
                     InvalidSyntax, NoProposalChosen, UnsupportedCriticalPayload, ChildSaError)
from message import (Message, Payload, PayloadAUTH, PayloadDELETE, PayloadIDi, PayloadIDr, PayloadKE, PayloadNONCE,
                     PayloadNOTIFY, PayloadSA, PayloadTSi, PayloadTSr, PayloadVENDOR, Proposal, TrafficSelector,
                     Transform)

__author__ = 'Alejandro Perez <alex@um.es>'

# TODO: Implement tests for this with valid and invalid exchange sequences

Keyring = namedtuple('Keyring', ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr'])
ChildSa = namedtuple('ChildSa', ['inbound_spi', 'outbound_spi', 'proposal', 'tsi', 'tsr', 'mode'])
Acquire = namedtuple('Acquire', ['tsi', 'tsr', 'index'])

ChildSa.__str__ = lambda x: '({}, {})'.format(hexstring(x.inbound_spi), hexstring(x.outbound_spi))


class IkeSaStateError(Exception):
    pass


class IkeSa(object):
    """ This class controls the state machine of a IKE SA
        It is triggered with received Messages and/or IPsec events
    """

    class State(SafeIntEnum):
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

        # Closing states
        REKEYED = 20
        DELETED = 21

    def __init__(self, is_initiator, peer_spi, configuration, my_addr, peer_addr):
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
        self.acquire = None
        self.new_ike_sa = None
        self.xfrm = xfrm.Xfrm()

    def __str__(self):
        return hexstring(self.my_spi)

    def log_msg(self, level, message):
        logging.log(level, 'IKE_SA: {}. {}'.format(self, message))

    def log_error(self, message):
        self.log_msg(logging.ERROR, message)

    def log_info(self, message):
        self.log_msg(logging.INFO, message)

    def log_warning(self, message):
        self.log_msg(logging.WARNING, message)

    def log_debug(self, message):
        self.log_msg(logging.DEBUG, message)

    def _generate_ike_sa_key_material(self, ike_proposal, nonce_i, nonce_r, spi_i, spi_r, shared_secret,
                                      old_sk_d=None):
        """ Generates IKE_SA key material based on the proposal and DH
        """
        prf = Prf(ike_proposal.get_transform(Transform.Type.PRF))
        integ = Integrity(ike_proposal.get_transform(Transform.Type.INTEG))
        cipher = Cipher(ike_proposal.get_transform(Transform.Type.ENCR))

        if not old_sk_d:
            skeyseed = prf.prf(nonce_i + nonce_r, shared_secret)
        else:
            skeyseed = prf.prf(old_sk_d, shared_secret + nonce_i + nonce_r)

        self.log_debug('Generated SKEYSEED: {}'.format(hexstring(skeyseed)))

        keymat = prf.prfplus(skeyseed, nonce_i + nonce_r + spi_i + spi_r,
                             prf.key_size * 3 + integ.key_size * 2 + cipher.key_size * 2)
        sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr = unpack(
            '>{0}s{1}s{1}s{2}s{2}s{0}s{0}s'.format(prf.key_size, integ.key_size, cipher.key_size),
            keymat)
        ike_sa_keyring = Keyring(sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr)
        crypto_i = Crypto(cipher, ike_sa_keyring.sk_ei, integ, ike_sa_keyring.sk_ai, prf, ike_sa_keyring.sk_pi)
        crypto_r = Crypto(cipher, ike_sa_keyring.sk_er, integ, ike_sa_keyring.sk_ar, prf, ike_sa_keyring.sk_pr)
        self.my_crypto = crypto_i if self.is_initiator else crypto_r
        self.peer_crypto = crypto_r if self.is_initiator else crypto_i

        for keyname in ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr']:
            hexkey = hexstring(getattr(ike_sa_keyring, keyname))
            self.log_debug('Generated {}: {}'.format(keyname, hexkey))
        return ike_sa_keyring

    def delete_child_sas(self):
        for child_sa in self.child_sas:
            self.xfrm.delete_sa(self.peer_addr, child_sa.proposal.protocol_id, child_sa.outbound_spi)
            self.xfrm.delete_sa(self.my_addr, child_sa.proposal.protocol_id, child_sa.inbound_spi)

    def _generate_child_sa_key_material(self, child_proposal, nonce_i, nonce_r, sk_d):
        """ Generates CHILD_SA key material
        """
        encr_key_size = 0
        integ_key_size = Integrity(child_proposal.get_transform(Transform.Type.INTEG)).key_size
        if child_proposal.protocol_id == Proposal.Protocol.ESP:
            encr_key_size = Cipher(child_proposal.get_transform(Transform.Type.ENCR)).key_size

        keymat = self.my_crypto.prf.prfplus(sk_d, nonce_i + nonce_r, 2 * integ_key_size + 2 * encr_key_size)

        sk_ei, sk_ai, sk_er, sk_ar = unpack('>{0}s{1}s{0}s{1}s'.format(encr_key_size, integ_key_size), keymat)
        child_sa_keyring = Keyring(None, sk_ai, sk_ar, sk_ei, sk_er, None, None)

        self.log_debug('Generated sk_ai: {}'.format(hexstring(sk_ai)))
        self.log_debug('Generated sk_ar: {}'.format(hexstring(sk_ar)))
        self.log_debug('Generated sk_ei: {}'.format(hexstring(sk_ei)))
        self.log_debug('Generated sk_er: {}'.format(hexstring(sk_er)))

        return child_sa_keyring

    def _select_best_sa_proposal(self, my_proposal, peer_payload_sa):
        """ Selects a received Payload SA with our own suite
        """
        for peer_proposal in peer_payload_sa.proposals:
            intersection = my_proposal.intersection(peer_proposal)
            if intersection is not None:
                return intersection
        raise NoProposalChosen('Could not find a suitable matching Proposal')

    def _ike_conf_2_proposal(self):
        return Proposal(1, Proposal.Protocol.IKE, b'', (self.configuration['encr'] + self.configuration['integ']
                                                        + self.configuration['prf'] + self.configuration['dh']))

    def _ipsec_conf_2_proposal(self, ipsec_conf):
        proto = ipsec_conf['ipsec_proto']
        if proto == Proposal.Protocol.ESP:
            return Proposal(1, proto, b'', ipsec_conf['encr'] + ipsec_conf['integ'])
        else:
            return Proposal(1, proto, b'', ipsec_conf['integ'])

    def _select_best_ike_sa_proposal(self, peer_payload_sa):
        my_proposal = self._ike_conf_2_proposal()
        return self._select_best_sa_proposal(my_proposal, peer_payload_sa)

    def _select_best_child_sa_proposal(self, peer_payload_sa, ipsec_conf):
        my_proposal = self._ipsec_conf_2_proposal(ipsec_conf)
        return self._select_best_sa_proposal(my_proposal, peer_payload_sa)

    def _ipsec_conf_2_ts(self, ipsec_conf):
        """ Generates traffic selectors based on an ipsec configuration
        """
        conf_tsi = TrafficSelector.from_network(ipsec_conf['my_subnet'], ipsec_conf['my_port'], ipsec_conf['ip_proto'])
        conf_tsr = TrafficSelector.from_network(ipsec_conf['peer_subnet'], ipsec_conf['peer_port'],
                                                ipsec_conf['ip_proto'])
        return conf_tsi, conf_tsr

    def _get_ipsec_configuration(self, payload_tsi, payload_tsr):
        """ Find matching IPsec configuration.
            It iterates over the received TS in reversed order and returns the
            first configuration that is larger or smaller than the proposed
            pair, along with the chosen selectors
        """
        for tsi in reversed(payload_tsi.traffic_selectors):
            for tsr in reversed(payload_tsr.traffic_selectors):
                for ipsec_conf in self.configuration['protect']:
                    conf_tsi, conf_tsr = self._ipsec_conf_2_ts(ipsec_conf)
                    # look for a larger policy
                    if tsi.is_subset(conf_tsi) and tsr.is_subset(conf_tsr):
                        return ipsec_conf, tsi, tsr
                    # look for a smaller policy
                    elif conf_tsi.is_subset(tsi) and conf_tsr.is_subset(tsr):
                        return ipsec_conf, conf_tsi, conf_tsr
        raise InvalidSelectors('TS could not be matched with any IPsec configuration')

    # TODO: Logging should be done per exchange, instead of having a generic
    # call, to make it more specific (e.g. CHILD_SA_REKEY, IKE_SA_REKEY, IKE_SA_DELETE, etc.)
    def log_message(self, message, addr, data, send=True):
        self.log_info('{} {} {} ({} bytes) {} {}'.format('Sent' if send else 'Received',
                                                         Message.Exchange.safe_name(message.exchange_type),
                                                         'response' if message.is_response else 'request',
                                                         len(data),
                                                         'to' if send else 'from',
                                                         addr))
        self.log_debug(json.dumps(message.to_dict(), indent=logging.indent))

    def _generate_ike_error_response(self, request, notification_type, notification_data=b''):
        notify_error = PayloadNOTIFY(Proposal.Protocol.NONE, notification_type, b'', notification_data)
        return Message(spi_i=request.spi_i,
                       spi_r=request.spi_r,
                       major=2,
                       minor=0,
                       exchange_type=request.exchange_type,
                       is_response=True,
                       can_use_higher_version=False,
                       is_initiator=self.is_initiator,
                       message_id=self.peer_msg_id,
                       payloads=([notify_error]
                                 if request.exchange_type == Message.Exchange.IKE_SA_INIT else []),
                       encrypted_payloads=([notify_error]
                                           if request.exchange_type != Message.Exchange.IKE_SA_INIT else []),
                       crypto=(self.my_crypto
                               if request.exchange_type != Message.Exchange.IKE_SA_INIT else None))

    def _process_request(self, message, addr):
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
            self.log_error('Message with invalid ID. Expecting: {}. Received: {}. Omitting.'.format(self.peer_msg_id,
                                                                                                    message.message_id))
            return None

        hexspi = hexstring(self.my_spi)
        try:
            handler = _handler_dict[message.exchange_type]
            response = handler(message)
        except KeyError:
            self.log_error("I don't know how to handle this message. Please, implement a handler for this exchange!")
            return None
        except (IkeSaError, ChildSaError) as ex:
            exception_2_notify = {
                NoProposalChosen: PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN,
                UnsupportedCriticalPayload: PayloadNOTIFY.Type.UNSUPPORTED_CRITICAL_PAYLOAD,
                InvalidSyntax: PayloadNOTIFY.Type.INVALID_SYNTAX,
                AuthenticationFailed: PayloadNOTIFY.Type.AUTHENTICATION_FAILED,
                InvalidSelectors: PayloadNOTIFY.Type.INVALID_SELECTORS,
                InvalidKePayload: PayloadNOTIFY.Type.INVALID_KE_PAYLOAD,
                ChildSaNotFound: PayloadNOTIFY.Type.CHILD_SA_NOT_FOUND,
            }
            self.log_error('IKE_SA: {}. {}'.format(hexspi, ex))
            notification_type = exception_2_notify.get(type(ex), PayloadNOTIFY.Type.INVALID_SYNTAX)
            notification_data = pack('>H', ex.group) if type(ex) is InvalidKePayload else b''
            response = self._generate_ike_error_response(message, notification_type, notification_data)
            self.state = IkeSa.State.DELETED

        # if the message is successfully processed, increment expected message
        # ID and store response (for future retransmissions responses)
        self.peer_msg_id = self.peer_msg_id + 1
        response_data = response.to_bytes()
        self.log_message(response, addr, response_data, send=True)
        self.last_sent_response_data = response_data
        return response_data

    def _process_response(self, message, addr):
        _handler_dict = {
            Message.Exchange.IKE_SA_INIT: self.process_ike_sa_init_response,
            Message.Exchange.IKE_AUTH: self.process_ike_auth_response,
            Message.Exchange.CREATE_CHILD_SA: self.process_create_child_sa_response,
            Message.Exchange.INFORMATIONAL: self.process_informational_response,
        }

        # if message ID is not the expected one, log and omit
        if message.message_id != self.my_msg_id:
            self.log_error('Message with invalid ID. Expecting: {}. Received: {}. Omitting.'.format(self.my_msg_id,
                                                                                                    message.message_id))
            return None

        # increment our message ID for future requests
        self.my_msg_id = self.my_msg_id + 1
        try:
            handler = _handler_dict[message.exchange_type]
            request = handler(message)
            # If there is a another request to be sent, serizalize it and return it
            if request:
                request_data = request.to_bytes()
                self.log_message(request, addr, request_data, send=True)
                return request_data
        except IkeSaError as ex:
            self.log_error(str(ex))
            self.state = IkeSa.State.DELETED
        except KeyError:
            self.log_error("I don't know how to handle this message. Please, implement a handler!")

        return None

    def process_message(self, data, addr):
        # parse the whole message (including encrypted data)
        message = Message.parse(data, header_only=False, crypto=self.peer_crypto)
        self.log_message(message, addr, data, send=False)
        if message.is_request:
            return self._process_request(message, addr)
        else:
            return self._process_response(message, addr)

    def process_acquire(self, acquire):
        if self.state == IkeSa.State.INITIAL:
            request = self.generate_ike_sa_init_request(acquire)
        elif self.state == IkeSa.State.ESTABLISHED:
            request = self.generate_create_child_sa_request(acquire)
        else:
            self.log_warning('Cannot process acquire while waiting for a response.')
            return None

        request_data = request.to_bytes()
        self.log_message(request, self.peer_addr, request_data, send=True)
        return request_data

    def process_expire(self, spi):
        """ Creates a rekey CREATE_CHILD_SA message for creating a new CHILD
        """
        if self.state != IkeSa.State.ESTABLISHED:
            self.log_warning('Cannot process expire while waiting for a response')
            return None

        rekeyed_child_sa = self.get_child_sa(spi)
        if rekeyed_child_sa is None:
            self.log_warning("Received expire for unknown CHILD_SA with spi {}".format(hexstring(spi)))
            return None

        request = self.generate_rekey_child_sa_request(rekeyed_child_sa)
        request_data = request.to_bytes()
        self.log_message(self.request, self.peer_addr, request_data, send=True)
        return request_data

    def _process_ike_sa_negotiation_request(self, request, encrypted=False, old_sk_d=None):
        """ Process a IKE_SA negotiation request (SA, Ni, KEi), and returns
            appropriate response payloads (SA, Nr, KEr) or raises exception
            on error.
            It sets self.chosen_proposal and self.ike_sa_keyring as a result
        """
        payload_sa = request.get_payload(Payload.Type.SA, encrypted)
        payload_nonce = request.get_payload(Payload.Type.NONCE, encrypted)
        payload_ke = request.get_payload(Payload.Type.KE, encrypted)

        # select the proposal and generate a response Payload SA
        self.chosen_proposal = self._select_best_ike_sa_proposal(payload_sa)
        # if this is a rekey, hence spi is not empty, send ours
        if self.chosen_proposal.spi:
            self.chosen_proposal.spi = self.my_spi
        response_payload_sa = PayloadSA([self.chosen_proposal])

        # generate payload NONCE
        response_payload_nonce = PayloadNONCE()

        # check that DH groups match and generate response Paylaod KE
        my_dh_group = self.chosen_proposal.get_transform(Transform.Type.DH).id
        if my_dh_group != payload_ke.dh_group:
            raise InvalidKePayload('Invalid DH group used. I want {}'.format(my_dh_group), group=my_dh_group)
        dh = DiffieHellman(payload_ke.dh_group)
        dh.compute_secret(payload_ke.ke_data)
        self.log_debug('Generated DH shared secret: {}'.format(hexstring(dh.shared_secret)))
        response_payload_ke = PayloadKE(dh.group, dh.public_key)

        # generate IKE SA key material
        self.ike_sa_keyring = self._generate_ike_sa_key_material(ike_proposal=self.chosen_proposal,
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
        response = Message(spi_i=request.spi_i,
                           spi_r=self.my_spi,
                           major=2,
                           minor=0,
                           exchange_type=Message.Exchange.IKE_SA_INIT,
                           is_response=True,
                           can_use_higher_version=False,
                           is_initiator=False,
                           message_id=self.peer_msg_id,
                           payloads=response_payloads,
                           encrypted_payloads=[],
                           crypto=self.my_crypto)

        # switch state
        self.state = IkeSa.State.INIT_RES_SENT

        # store messages for later authentication
        self.ike_sa_init_req_data = request.to_bytes()
        self.ike_sa_init_res_data = response.to_bytes()

        # return response
        return response

    def _generate_ike_sa_negotiation_request(self):
        # create the Payload SA
        my_proposal = self._ike_conf_2_proposal()
        payload_sa = PayloadSA([my_proposal])

        # generate payload NONCE
        payload_nonce = PayloadNONCE()

        # create DH and Paylaod KE
        my_dh_group = my_proposal.get_transform(Transform.Type.DH).id
        self.dh = DiffieHellman(my_dh_group)
        payload_ke = PayloadKE(my_dh_group, self.dh.public_key)

        return [payload_sa, payload_nonce, payload_ke]

    def generate_ike_sa_init_request(self, acquire):
        """ Creates a IKE_SA_INIT message
        """
        # check state
        assert (self.state == IkeSa.State.INITIAL)

        # generate the IKE SA negotiation payloads
        ike_sa_payloads = self._generate_ike_sa_negotiation_request()

        # create the payload VENDOR
        payload_vendor = PayloadVENDOR(b'pyikev2-0.1')

        # generate the message
        self.request = Message(spi_i=self.my_spi,
                               spi_r=b'\0' * 8,
                               major=2,
                               minor=0,
                               exchange_type=Message.Exchange.IKE_SA_INIT,
                               is_response=False,
                               can_use_higher_version=False,
                               is_initiator=True,
                               message_id=self.my_msg_id,
                               payloads=ike_sa_payloads + [payload_vendor],
                               encrypted_payloads=[],
                               crypto=self.my_crypto)

        # switch state
        self.state = IkeSa.State.INIT_REQ_SENT

        # save the message for later authentication
        self.ike_sa_init_req_data = self.request.to_bytes()

        # store the acquire object to be used in the IKE_AUTH exchange
        self.acquire = acquire

        # return request
        return self.request

    @property
    def spi_i(self):
        return self.my_spi if self.is_initiator else self.peer_spi

    @property
    def spi_r(self):
        return self.peer_spi if self.is_initiator else self.my_spi

    def _generate_child_sa_negotiation_req(self, acquire):
        result = []
        # get the ipsec configuration
        ipsec_conf = next(x for x in self.configuration['protect'] if x['index'] == acquire.index)

        # generate Payload TSi, TSr
        tsi, tsr = self._ipsec_conf_2_ts(ipsec_conf)
        result.append(PayloadTSi([acquire.tsi, tsi]))
        result.append(PayloadTSr([acquire.tsr, tsr]))

        # generate Payload SA
        proposal = self._ipsec_conf_2_proposal(ipsec_conf)
        proposal.spi = os.urandom(4)
        result.append(PayloadSA([proposal]))

        # genereate USE_TRANSPORT_MODE notify if needed
        if ipsec_conf['mode'] == xfrm.Mode.TRANSPORT:
            result.append(PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.USE_TRANSPORT_MODE, b'', b''))
        return result

    def generate_ike_auth_request(self):
        """ Creates a IKE_AUTH request message
        """
        assert (self.state == IkeSa.State.INIT_REQ_SENT)

        # generate the CHILD_SA negotiation payloads
        child_sa_payloads = self._generate_child_sa_negotiation_req(self.acquire)

        # generate IDi
        payload_idi = PayloadIDi(self.configuration['id'].id_type, self.configuration['id'].id_data)

        # generate Payload AUTH
        ike_sa_init_res = Message.parse(self.ike_sa_init_res_data)
        auth_data = self._generate_psk_auth_payload(self.ike_sa_init_req_data,
                                                    ike_sa_init_res.get_payload(Payload.Type.NONCE).nonce,
                                                    payload_idi, self.my_crypto.sk_p)

        payload_auth = PayloadAUTH(PayloadAUTH.Method.PSK, auth_data)

        # generate the message
        self.request = Message(spi_i=self.my_spi,
                               spi_r=self.peer_spi,
                               major=2,
                               minor=0,
                               exchange_type=Message.Exchange.IKE_AUTH,
                               is_response=False,
                               can_use_higher_version=False,
                               is_initiator=True,
                               message_id=self.my_msg_id,
                               payloads=[],
                               encrypted_payloads=child_sa_payloads + [payload_idi, payload_auth],
                               crypto=self.my_crypto)

        # transition
        self.state = IkeSa.State.AUTH_REQ_SENT

        return self.request

    def _process_ike_sa_negotiation_response(self, response, encrypted=False, old_sk_d=None):
        """ Process a IKE_SA negotiation response (SA, Ni, KEi)
            It sets self.chosen_proposal and self.ike_sa_keyring as a result
        """
        payload_sa = response.get_payload(Payload.Type.SA, encrypted)
        payload_nonce = response.get_payload(Payload.Type.NONCE, encrypted)
        payload_ke = response.get_payload(Payload.Type.KE, encrypted)

        # update peer spi
        self.peer_spi = response.spi_r

        # select the peers proposal.
        # TODO: Must check that peer actually selected a subset
        self.chosen_proposal = payload_sa.proposals[0]

        # if this is a rekey, hence spi is not empty, send ours
        # if self.chosen_proposal.spi:
        #     self.chosen_proposal.spi = self.my_spi
        # response_payload_sa = PayloadSA([self.chosen_proposal])

        self.dh.compute_secret(payload_ke.ke_data)
        self.log_debug('Generated DH shared secret: {}'.format(hexstring(self.dh.shared_secret)))

        # generate IKE SA key material
        self.ike_sa_keyring = self._generate_ike_sa_key_material(
            ike_proposal=self.chosen_proposal,
            nonce_i=self.request.get_payload(Payload.Type.NONCE, encrypted).nonce,
            nonce_r=payload_nonce.nonce,
            spi_i=self.my_spi,
            spi_r=self.peer_spi,
            shared_secret=self.dh.shared_secret,
            old_sk_d=old_sk_d)

    def abort_on_error_notifies(self, message, encrypted=False, ignore=None):
        for notification in message.get_payloads(Payload.Type.NOTIFY, encrypted=encrypted):
            if notification.is_error() and (ignore is None or notification.notification_type not in ignore):
                raise IkeSaError('Could not establish IKE_SA due to error notification received: {}'.format(
                    PayloadNOTIFY.Type.safe_name(notification.notification_type)))

    def process_ike_sa_init_response(self, response):
        """ Processes a IKE_SA_INIT response message
        """
        self._check_in_states(response, [IkeSa.State.INIT_REQ_SENT])

        # Recover from INVALID_KE_PAYLOAD
        invalid_ke = response.get_notifies(PayloadNOTIFY.Type.INVALID_KE_PAYLOAD)
        if invalid_ke:
            invalid_ke = invalid_ke[0]
            self.log_warning("INVALID_KE_PAYLOAD notification received. Trying with the suggested group")
            # # create DH and Paylaod KE
            my_dh_group = unpack('>H', invalid_ke.notification_data)[0]
            self.dh = DiffieHellman(my_dh_group)
            new_payload_ke = PayloadKE(my_dh_group, self.dh.public_key)

            payload_ke = self.request.get_payload(Payload.Type.KE)
            payload_ke.dh_group = new_payload_ke.dh_group
            payload_ke.ke_data = new_payload_ke.ke_data
            self.ike_sa_init_req_data = self.request.to_bytes()
            return self.request

        # Check error notifications
        self.abort_on_error_notifies(response)

        # process the IKE_SA negotiation payloads
        self._process_ike_sa_negotiation_response(response)

        # save the message for later authentication
        self.ike_sa_init_res_data = response.to_bytes()

        # return IKE_AUTH request callback
        return self.generate_ike_auth_request()

    def _generate_psk_auth_payload(self, message_data, nonce, payload_id, sk_p):
        prf = self.peer_crypto.prf.prf
        data_to_be_signed = (message_data + nonce + prf(sk_p, payload_id.to_bytes()))
        keypad = prf(self.configuration['psk'], b'Key Pad for IKEv2')
        return prf(keypad, data_to_be_signed)

    def _process_create_child_sa_negotiation_req(self, request):
        """ This method process a CREATE CHILD SA negotiation request
        """
        # get some relevant payloads from the message
        try:
            response_payloads = []
            request_payload_sa = request.get_payload(Payload.Type.SA, True)
            request_payload_tsi = request.get_payload(Payload.Type.TSi, True)
            request_payload_tsr = request.get_payload(Payload.Type.TSr, True)

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
            ipsec_conf, chosen_tsr, chosen_tsi = self._get_ipsec_configuration(request_payload_tsr,
                                                                               request_payload_tsi)

            # check which mode peer wants and compare to ours
            mode = xfrm.Mode.TUNNEL
            if request.get_notifies(PayloadNOTIFY.Type.USE_TRANSPORT_MODE, True):
                mode = xfrm.Mode.TRANSPORT
                response_payloads.append(
                    PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.USE_TRANSPORT_MODE, b'', b''))

            if ipsec_conf['mode'] != mode:
                raise InvalidSelectors('Invalid mode requested')

            # generate the response payload SA with the chosen proposal
            chosen_child_proposal = self._select_best_child_sa_proposal(request_payload_sa, ipsec_conf)

            # generate CHILD key material
            child_sa_keyring = self._generate_child_sa_key_material(child_proposal=chosen_child_proposal,
                                                                    nonce_i=request_payload_nonce.nonce,
                                                                    nonce_r=response_payload_nonce.nonce,
                                                                    sk_d=self.ike_sa_keyring.sk_d)

            # create the IPsec SAs according to the negotiated CHILD SA
            child_sa = ChildSa(outbound_spi=chosen_child_proposal.spi, inbound_spi=os.urandom(4),
                               proposal=chosen_child_proposal, tsi=chosen_tsr, tsr=chosen_tsi, mode=mode)

            self.child_sas.append(child_sa)
            if ipsec_conf['ipsec_proto'] == Proposal.Protocol.ESP:
                encr_transform = chosen_child_proposal.get_transform(Transform.Type.ENCR).id
            else:
                encr_transform = None
            self.xfrm.create_sa(self.my_addr, self.peer_addr, chosen_tsr, chosen_tsi,
                                chosen_child_proposal.protocol_id,
                                child_sa.outbound_spi, encr_transform, child_sa_keyring.sk_er,
                                chosen_child_proposal.get_transform(Transform.Type.INTEG).id,
                                child_sa_keyring.sk_ar, mode, ipsec_conf['lifetime'])
            self.xfrm.create_sa(self.peer_addr, self.my_addr, chosen_tsi, chosen_tsr,
                                chosen_child_proposal.protocol_id,
                                child_sa.inbound_spi, encr_transform, child_sa_keyring.sk_ei,
                                chosen_child_proposal.get_transform(Transform.Type.INTEG).id,
                                child_sa_keyring.sk_ai, mode, ipsec_conf['lifetime'])
            self.log_info('Created CHILD_SA {}'.format(child_sa))

            # generate the response Payload SA
            chosen_child_proposal.spi = child_sa.inbound_spi
            response_payloads.append(PayloadSA([chosen_child_proposal]))

            # generate response Payload TSi/TSr based on the chosen selectors
            response_payloads.append(PayloadTSi([chosen_tsi]))
            response_payloads.append(PayloadTSr([chosen_tsr]))

            return response_payloads
        except InvalidSelectors as ex:
            self.log_warning('CHILD_SA negotiation failed. {}'.format(ex))
            return [PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.INVALID_SELECTORS, b'', b'')]
        except (IkeSaError, ChildSaError) as ex:
            self.log_warning('CHILD_SA negotiation failed. {}'.format(ex))
            return [PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN, b'', b'')]

    def _check_in_states(self, message, list_of_valid_states):
        if self.state not in list_of_valid_states:
            raise IkeSaStateError(
                'Cannot process an {} {} when in state {}.'.format(Message.Exchange.safe_name(message.exchange_type),
                                                                   'request' if message.is_request else 'response',
                                                                   self.state.name))

    def _check_established(self, message):
        return self._check_in_states(message, range(IkeSa.State.ESTABLISHED, IkeSa.State.REKEYED))

    def _check_established_or_rekeyed(self, message):
        return self._check_in_states(message, range(IkeSa.State.ESTABLISHED, IkeSa.State.REKEYED + 1))

    def process_ike_auth_request(self, request):
        """ Processes a IKE_AUTH request message and returns a
            IKE_AUTH response
        """
        self._check_in_states(request, [IkeSa.State.INIT_RES_SENT])

        # get some relevant payloads from the message
        request_payload_idi = request.get_payload(Payload.Type.IDi, True)
        request_payload_auth = request.get_payload(Payload.Type.AUTH, True)

        # verify AUTH payload
        if request_payload_auth.method != PayloadAUTH.Method.PSK:
            raise AuthenticationFailed('AUTH method not supported')

        ike_sa_init_req = Message.parse(self.ike_sa_init_req_data)
        ike_sa_init_res = Message.parse(self.ike_sa_init_res_data)

        auth_data = self._generate_psk_auth_payload(self.ike_sa_init_req_data,
                                                    ike_sa_init_res.get_payload(Payload.Type.NONCE).nonce,
                                                    request_payload_idi, self.peer_crypto.sk_p)

        if auth_data != request_payload_auth.auth_data:
            raise AuthenticationFailed('Invalid AUTH data received')

        # process the CHILD_SA creation negotiation
        response_payloads = self._process_create_child_sa_negotiation_req(request)

        # generate IDr
        response_payload_idr = PayloadIDr(self.configuration['id'].id_type, self.configuration['id'].id_data)

        # generate AUTH payload
        # TODO: Use a function for generating/validating AUTH payloads
        auth_data = self._generate_psk_auth_payload(self.ike_sa_init_res_data,
                                                    ike_sa_init_req.get_payload(Payload.Type.NONCE).nonce,
                                                    response_payload_idr, self.my_crypto.sk_p)
        response_payload_auth = PayloadAUTH(PayloadAUTH.Method.PSK, auth_data)

        response_payloads += [response_payload_idr, response_payload_auth]

        # generate the message
        response = Message(spi_i=request.spi_i,
                           spi_r=request.spi_r,
                           major=2,
                           minor=0,
                           exchange_type=Message.Exchange.IKE_AUTH,
                           is_response=True,
                           can_use_higher_version=False,
                           is_initiator=False,
                           message_id=self.peer_msg_id,
                           payloads=[],
                           encrypted_payloads=response_payloads,
                           crypto=self.my_crypto)

        # increase msg_id and transition
        self.state = IkeSa.State.ESTABLISHED

        return response

    def _process_create_child_sa_negotiation_res(self, response):
        error_notification = (response.get_notifies(PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN, True)
                              or response.get_notifies(PayloadNOTIFY.Type.INVALID_SELECTORS, True))
        if error_notification:
            self.log_warning('CHILD_SA negotiation failed because {}. Skipping creation of CHILD_SA.'.format(
                PayloadNOTIFY.Type.safe_name(error_notification[0].notification_type)))
            return

        # get some relevant payloads from the message
        response_payload_sa = response.get_payload(Payload.Type.SA, True)
        response_payload_tsi = response.get_payload(Payload.Type.TSi, True)
        response_payload_tsr = response.get_payload(Payload.Type.TSr, True)
        response_transport_mode = response.get_notifies(PayloadNOTIFY.Type.USE_TRANSPORT_MODE, True)

        # recover some relevant payloads from the request
        request_payload_sa = self.request.get_payload(Payload.Type.SA, True)
        request_payload_tsi = self.request.get_payload(Payload.Type.TSi, True)
        request_payload_tsr = self.request.get_payload(Payload.Type.TSr, True)
        request_transport_mode = self.request.get_notifies(PayloadNOTIFY.Type.USE_TRANSPORT_MODE, True)

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
        request_mode = (xfrm.Mode.TRANSPORT if request_transport_mode else xfrm.Mode.TUNNEL)
        response_mode = (xfrm.Mode.TRANSPORT if response_transport_mode else xfrm.Mode.TUNNEL)
        if request_mode != response_mode:
            raise InvalidSelectors('Invalid mode requested {} vs {}'.format(request_mode, response_mode))

        # Check responder provided a valid proposal
        chosen_child_proposal = response_payload_sa.proposals[0]
        my_proposal = request_payload_sa.proposals[0]
        intersection = my_proposal.intersection(chosen_child_proposal)
        if intersection != chosen_child_proposal:
            raise NoProposalChosen('Responder did not choose a valid proposal')

        # generate CHILD key material
        child_sa_keyring = self._generate_child_sa_key_material(child_proposal=chosen_child_proposal,
                                                                nonce_i=request_payload_nonce.nonce,
                                                                nonce_r=response_payload_nonce.nonce,
                                                                sk_d=self.ike_sa_keyring.sk_d)

        # Check TSi and TSr are subsets of what we sent
        chosen_tsi = response_payload_tsi.traffic_selectors[0]
        chosen_tsr = response_payload_tsr.traffic_selectors[0]
        matches_tsi = [x for x in request_payload_tsi.traffic_selectors if chosen_tsi.is_subset(x)]
        matches_tsr = [x for x in request_payload_tsr.traffic_selectors if chosen_tsr.is_subset(x)]
        if not matches_tsi or not matches_tsr:
            raise InvalidSelectors('Responder did not select a subset of our proposed TS.')

        # recover ipsec configuration from Acquire's Index
        ipsec_conf = next(x for x in self.configuration['protect'] if x['index'] == self.acquire.index)

        # create the IPsec SAs according to the negotiated CHILD SA
        child_sa = ChildSa(outbound_spi=chosen_child_proposal.spi, inbound_spi=request_payload_sa.proposals[0].spi,
                           proposal=chosen_child_proposal, tsi=chosen_tsi, tsr=chosen_tsr, mode=request_mode)
        self.child_sas.append(child_sa)

        encr_transform = None
        if chosen_child_proposal.protocol_id == Proposal.Protocol.ESP:
            encr_transform = chosen_child_proposal.get_transform(Transform.Type.ENCR).id
        self.xfrm.create_sa(self.my_addr, self.peer_addr, chosen_tsi, chosen_tsr, chosen_child_proposal.protocol_id,
                            child_sa.outbound_spi, encr_transform, child_sa_keyring.sk_ei,
                            chosen_child_proposal.get_transform(Transform.Type.INTEG).id,
                            child_sa_keyring.sk_ai, request_mode, ipsec_conf['lifetime'])
        self.xfrm.create_sa(self.peer_addr, self.my_addr, chosen_tsr, chosen_tsi, chosen_child_proposal.protocol_id,
                            child_sa.inbound_spi, encr_transform, child_sa_keyring.sk_er,
                            chosen_child_proposal.get_transform(Transform.Type.INTEG).id,
                            child_sa_keyring.sk_ar, request_mode, ipsec_conf['lifetime'])
        self.log_info('Created CHILD_SA {}'.format(child_sa))

    def process_ike_auth_response(self, response):
        self._check_in_states(response, [IkeSa.State.AUTH_REQ_SENT])

        # check there are no notifies
        self.abort_on_error_notifies(response, encrypted=True, ignore=[PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN,
                                                                       PayloadNOTIFY.Type.INVALID_SELECTORS])

        # get some relevant payloads from the message
        response_payload_idr = response.get_payload(Payload.Type.IDr, True)
        response_payload_auth = response.get_payload(Payload.Type.AUTH, True)

        # verify AUTH payload
        if response_payload_auth.method != PayloadAUTH.Method.PSK:
            raise AuthenticationFailed('AUTH method not supported')

        ike_sa_init_req = Message.parse(self.ike_sa_init_req_data)
        auth_data = self._generate_psk_auth_payload(self.ike_sa_init_res_data,
                                                    ike_sa_init_req.get_payload(Payload.Type.NONCE).nonce,
                                                    response_payload_idr, self.peer_crypto.sk_p)

        if auth_data != response_payload_auth.auth_data:
            raise AuthenticationFailed('Invalid AUTH data received')

        # process the CHILD_SA creation negotiation
        self._process_create_child_sa_negotiation_res(response)

        self.state = IkeSa.State.ESTABLISHED
        return None

    def generate_create_child_sa_request(self, acquire):
        """ Creates a CREATE_CHILD_SA request message for creating a new CHILD
        """
        assert (self.state == IkeSa.State.ESTABLISHED)

        # preserve the acquire for the response
        self.acquire = acquire

        # generate the CHILD_SA negotiation payloads
        child_sa_payloads = self._generate_child_sa_negotiation_req(self.acquire)

        # generate Payload NONCE
        payload_nonce = PayloadNONCE()

        # generate the message
        self.request = Message(spi_i=self.spi_i,
                               spi_r=self.spi_r,
                               major=2,
                               minor=0,
                               exchange_type=Message.Exchange.CREATE_CHILD_SA,
                               is_response=False,
                               can_use_higher_version=False,
                               is_initiator=self.is_initiator,
                               message_id=self.my_msg_id,
                               payloads=[],
                               encrypted_payloads=child_sa_payloads + [payload_nonce],
                               crypto=self.my_crypto)

        # transition
        self.state = IkeSa.State.NEW_CHILD_REQ_SENT

        return self.request

    def generate_rekey_child_sa_request(self, rekeyed_child_sa):
        """ Creates a rekey CREATE_CHILD_SA message for rekeying a new CHILD
        """
        assert (self.state == IkeSa.State.ESTABLISHED)

        payloads = []

        # generate Payload TSi, TSr
        payloads.append(PayloadTSi([rekeyed_child_sa.tsi]))
        payloads.append(PayloadTSr([rekeyed_child_sa.tsr]))

        # generate Payload SA
        proposal = rekeyed_child_sa.proposal
        proposal.spi = os.urandom(4)
        payloads.append(PayloadSA([proposal]))

        # generate USE_TRANSPORT_MODE notify if needed
        if rekeyed_child_sa.mode == xfrm.Mode.TRANSPORT:
            payloads.append(PayloadNOTIFY(Proposal.Protocol.NONE, PayloadNOTIFY.Type.USE_TRANSPORT_MODE, b'', b''))

        payloads.append(
            PayloadNOTIFY(proposal.protocol_id, PayloadNOTIFY.Type.REKEY_SA, rekeyed_child_sa.inbound_spi, b''))

        payloads.append(PayloadNONCE())

        # generate the message
        self.request = Message(spi_i=self.spi_i,
                               spi_r=self.spi_r,
                               major=2,
                               minor=0,
                               exchange_type=Message.Exchange.CREATE_CHILD_SA,
                               is_response=False,
                               can_use_higher_version=False,
                               is_initiator=self.is_initiator,
                               message_id=self.my_msg_id,
                               payloads=[],
                               encrypted_payloads=payloads,
                               crypto=self.my_crypto)

        # transition
        self.state = IkeSa.State.REK_CHILD_REQ_SENT
        self.rekeyed_child_sa = rekeyed_child_sa

        return self.request

    def generate_delete_child_sa_request(self, child_sa):
        """ Creates an INFORMATIONAL message for deleting a CHILD_SA
        """
        assert (self.state == IkeSa.State.ESTABLISHED)

        payload_delete = PayloadDELETE(Proposal.Protocol.NONE, [child_sa.inbound_spi])

        # generate the message
        self.request = Message(spi_i=self.spi_i,
                               spi_r=self.spi_r,
                               major=2,
                               minor=0,
                               exchange_type=Message.Exchange.INFORMATIONAL,
                               is_response=False,
                               can_use_higher_version=False,
                               is_initiator=self.is_initiator,
                               message_id=self.my_msg_id,
                               payloads=[],
                               encrypted_payloads=[payload_delete],
                               crypto=self.my_crypto)

        # transition
        self.state = IkeSa.State.DEL_CHILD_REQ_SENT
        self.deleting_child_sa = child_sa
        return self.request

    def process_informational_request(self, request):
        """ Processes an INFORMATIONAL request
        """
        self._check_established_or_rekeyed(request)
        response_payloads = []
        for delete_payload in request.get_payloads(Payload.Type.DELETE, True):
            # if protocol is IKE, just mark the IKE SA for removal and return  emtpy INFORMATIONAL exchange
            if delete_payload.protocol_id == Proposal.Protocol.IKE:
                self.state = IkeSa.State.DELETED
            # if protocol is either AH or ESP, delete the Child SAs and return the inbound SPI
            else:
                for del_spi in delete_payload.spis:
                    child_sa = self.get_child_sa(del_spi)
                    if child_sa is not None:
                        self.xfrm.delete_sa(self.peer_addr, child_sa.proposal.protocol_id, child_sa.outbound_spi)
                        self.xfrm.delete_sa(self.my_addr, child_sa.proposal.protocol_id, child_sa.inbound_spi)
                        self.child_sas.remove(child_sa)
                        response_payloads.append(PayloadDELETE(delete_payload.protocol_id, [child_sa.inbound_spi]))
                        self.log_info('Removing CHILD_SA {}'.format(child_sa))
                    else:
                        self.log_warning('The indicated SPI could not be found when attempting to delete a '
                                         'Child SA: {}'.format(hexstring(del_spi)))

        return Message(spi_i=request.spi_i,
                       spi_r=request.spi_r,
                       major=2,
                       minor=0,
                       exchange_type=Message.Exchange.INFORMATIONAL,
                       is_response=True,
                       can_use_higher_version=False,
                       is_initiator=self.is_initiator,
                       message_id=self.peer_msg_id,
                       payloads=[],
                       encrypted_payloads=response_payloads,
                       crypto=self.my_crypto)

    def process_create_child_sa_request(self, request):
        """ Processes a CREATE_CHILD_SA message and returns response
        """
        self._check_established(request)

        # determine whether this concerns to IKE_SA or CHILD_SA
        payload_sa = request.get_payload(Payload.Type.SA, True)
        proposal = payload_sa.proposals[0]

        # if this is a IKE_REKEY
        if proposal.protocol_id == Proposal.Protocol.IKE:
            self.log_info('Received request for rekeying current IKE_SA')
            self.new_ike_sa = IkeSa(False, proposal.spi, self.configuration, self.my_addr, self.peer_addr)
            # take over the existing child sas
            self.new_ike_sa.child_sas = self.child_sas
            self.child_sas = []
            response_payloads = self.new_ike_sa._process_ike_sa_negotiation_request(request, True,
                                                                                    self.ike_sa_keyring.sk_d)
            self.new_ike_sa.state = IkeSa.State.ESTABLISHED
            self.state = IkeSa.State.REKEYED

        # if it concerns to CHILD_SAs
        else:
            # if this is a rekey, check if CHILD SA exists and add notification
            response_payloads = []
            rekey_notify = request.get_notifies(PayloadNOTIFY.Type.REKEY_SA, encrypted=True)
            if rekey_notify:
                # use only the first notification
                rekeyed_child_sa = self.get_child_sa(rekey_notify[0].spi)
                if rekeyed_child_sa is None:
                    raise ChildSaNotFound('The indicated SPI could not be found', spi=rekey_notify[0].spi)
                response_payloads.append(
                    PayloadNOTIFY(proposal.protocol_id, PayloadNOTIFY.Type.REKEY_SA, rekeyed_child_sa.inbound_spi,
                                  b''))

            response_payloads += self._process_create_child_sa_negotiation_req(request)

        return Message(spi_i=request.spi_i,
                       spi_r=request.spi_r,
                       major=2,
                       minor=0,
                       exchange_type=Message.Exchange.CREATE_CHILD_SA,
                       is_response=True,
                       can_use_higher_version=False,
                       is_initiator=self.is_initiator,
                       message_id=self.peer_msg_id,
                       payloads=[],
                       encrypted_payloads=response_payloads,
                       crypto=self.my_crypto)

    def get_child_sa(self, spi):
        try:
            return next(x for x in self.child_sas if spi == x.inbound_spi or spi == x.outbound_spi)
        except StopIteration:
            return None

    def process_create_child_sa_response(self, response):
        """ Processes a CREATE_CHILD_SA response message
        """
        self._check_in_states(response, [IkeSa.State.NEW_CHILD_REQ_SENT, IkeSa.State.REK_CHILD_REQ_SENT])
        self.abort_on_error_notifies(response, True, ignore=[PayloadNOTIFY.Type.INVALID_SELECTORS,
                                                             PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN])

        self._process_create_child_sa_negotiation_res(response)

        if self.state == IkeSa.State.NEW_CHILD_REQ_SENT:
            self.state = IkeSa.State.ESTABLISHED
            return None
        elif self.state == IkeSa.State.REK_CHILD_REQ_SENT:
            self.state = IkeSa.State.ESTABLISHED
            return self.generate_delete_child_sa_request(self.rekeyed_child_sa)

    def process_informational_response(self, response):
        """ Processes a CREATE_CHILD_SA response message
        """
        self._check_in_states(response, [IkeSa.State.DEL_CHILD_REQ_SENT, IkeSa.State.DEL_IKE_SA_REQ_SENT])
        self.abort_on_error_notifies(response, True)

        if self.state == IkeSa.State.DEL_CHILD_REQ_SENT:
            # delete our side of the
            self.xfrm.delete_sa(self.peer_addr, self.deleting_child_sa.proposal.protocol_id,
                                self.deleting_child_sa.outbound_spi)
            self.xfrm.delete_sa(self.my_addr, self.deleting_child_sa.proposal.protocol_id,
                                self.deleting_child_sa.inbound_spi)
            self.child_sas.remove(self.deleting_child_sa)
            self.log_info('Removing CHILD_SA {}'.format(self.deleting_child_sa))
            # we check that the counterpart has been deleted
            payload_delete = response.get_payload(Payload.Type.DELETE, True)
            if not payload_delete:
                raise InvalidSyntax('Received unexpected number of DELETE payloads')
            if len(payload_delete.spis) != 1:
                raise InvalidSyntax('Received unexpected number of SPIs in DELETE payload')
            if (payload_delete.spis[0] != self.deleting_child_sa.outbound_spi):
                raise InvalidSyntax('Received unexpected SPI value in DELETE payload')
            self.state = IkeSa.State.ESTABLISHED
            return None

        elif self.state == IkeSa.State.REK_CHILD_REQ_SENT:
            self.state = IkeSa.State.DELETED
            return self.generate_delete_child_sa_request(self.rekeyed_child_sa)


class IkeSaController:
    def __init__(self, my_addr, configuration):
        self.ike_sas = []
        self.configuration = configuration
        self.xfrm = xfrm.Xfrm()
        self.my_addr = my_addr

        # establish policies
        self.xfrm.flush_policies()
        self.xfrm.flush_sas()
        for peer_addr, ike_conf in configuration.items():
            self.xfrm.create_policies(my_addr, peer_addr, ike_conf)

    def _get_ike_sa_by_spi(self, spi):
        return next(x for x in self.ike_sas if x.my_spi == spi)

    def _get_ike_sa_by_peer_addr(self, peer_addr):
        return next(x for x in self.ike_sas if x.peer_addr == peer_addr)

    def _get_ike_sa_by_child_sa_spi(self, spi):
        for ike_sa in self.ike_sas:
            for child_sa in ike_sa.child_sas:
                if child_sa.inbound_spi == spi or child_sa.outbound_spi == spi:
                    return ike_sa
        return None

    def dispatch_message(self, data, my_addr, peer_addr):
        header = Message.parse(data, header_only=True)

        # if IKE_SA_INIT request, then a new IkeSa must be created
        if (header.exchange_type == Message.Exchange.IKE_SA_INIT and header.is_request):
            # look for matching configuration
            ike_conf = self.configuration.get_ike_configuration(peer_addr[0])
            ike_sa = IkeSa(is_initiator=False, peer_spi=header.spi_i, configuration=ike_conf,
                           my_addr=ip_address(my_addr[0]), peer_addr=ip_address(peer_addr[0]))
            self.ike_sas.append(ike_sa)
            logging.info('Starting the creation of IKE SA with SPI={}. Count={}'.format(hexstring(ike_sa.my_spi),
                                                                                        len(self.ike_sas)))
        # else, look for the IkeSa in the dict
        else:
            my_spi = header.spi_r if header.is_initiator else header.spi_i
            try:
                ike_sa = self._get_ike_sa_by_spi(my_spi)
            except StopIteration:
                logging.warning('Received message for unknown SPI={}. Omitting.'.format(hexstring(my_spi)))
                logging.debug(json.dumps(header.to_dict(), indent=logging.indent))
                return None

        # generate the reply (if any)
        reply = ike_sa.process_message(data, peer_addr)

        # if rekeyed, add the new IkeSa
        if ike_sa.state == IkeSa.State.REKEYED:
            self.ike_sas.append(ike_sa.new_ike_sa)
            logging.info('IKE SA with SPI={} created by rekey. Count={}'.format(hexstring(ike_sa.new_ike_sa.my_spi),
                                                                                len(self.ike_sas)))

        # if the IKE_SA needs to be closed
        if ike_sa.state in (IkeSa.State.DELETED,):
            ike_sa.delete_child_sas()
            self.ike_sas.remove(ike_sa)
            logging.info('Deleted IKE_SA with SPI={}. Count={}'.format(hexstring(ike_sa.my_spi), len(self.ike_sas)))

        return reply

    def process_acquire(self, xfrm_acquire, xfrm_tmpl):
        peer_addr = xfrm_acquire.id.daddr.to_ipaddr()
        logging.debug('Received acquire for {}'.format(peer_addr))

        # look for an active IKE_SA with the peer
        # TODO: Probably need to check state to see if we can use it or not
        try:
            ike_sa = self._get_ike_sa_by_peer_addr(peer_addr)
        except StopIteration:
            my_addr = xfrm_acquire.saddr.to_ipaddr()
            ike_conf = self.configuration.get_ike_configuration(peer_addr)
            # create new IKE_SA (for now)
            ike_sa = IkeSa(is_initiator=True, peer_spi=b'\0' * 8, configuration=ike_conf, my_addr=my_addr,
                           peer_addr=peer_addr)
            self.ike_sas.append(ike_sa)
            logging.info('Starting the creation of IKE SA with SPI={}. Count={}'
                         ''.format(hexstring(ike_sa.my_spi), len(self.ike_sas)))

        small_tsi = TrafficSelector.from_network(ip_network(xfrm_acquire.sel.saddr.to_ipaddr()),
                                                 xfrm_acquire.sel.sport, xfrm_acquire.sel.proto)
        small_tsr = TrafficSelector.from_network(ip_network(xfrm_acquire.sel.daddr.to_ipaddr()),
                                                 xfrm_acquire.sel.dport, xfrm_acquire.sel.proto)
        acquire = Acquire(small_tsi, small_tsr, xfrm_acquire.policy.index)
        request = ike_sa.process_acquire(acquire)

        # look for ipsec configuration
        return request, (str(ike_sa.peer_addr), 500)

    def process_expire(self, xfrm_expire):
        spi = bytes(xfrm_expire.state.id.spi)
        hard = xfrm_expire.hard
        logging.debug('Received EXPIRE for spi {}. Hard={}'.format(hexstring(spi), hard))
        ike_sa = self._get_ike_sa_by_child_sa_spi(spi)
        if (ike_sa):
            request = ike_sa.process_expire(spi)
            return request, (str(ike_sa.peer_addr), 500)
        return None, None

    def main_loop(self):
        # create network socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port = 500
        sock.bind((str(self.my_addr), port))
        logging.info('Listening from {}:{}'.format(self.my_addr, port))

        # create XFRM socket
        xfrm_obj = xfrm.Xfrm()
        xfrm_socket = xfrm_obj.get_socket()
        logging.info('Listening XFRM events.')

        # do server
        while True:
            readable = select([sock, xfrm_socket], [], [])[0]
            if sock in readable:
                data, addr = sock.recvfrom(4096)
                data = self.dispatch_message(data, sock.getsockname(), addr)
                if data:
                    sock.sendto(data, addr)
            # TODO: Wrong. _parse_message should not be used here
            if xfrm_socket in readable:
                data = xfrm_socket.recv(4096)
                header, msg, attributes = xfrm_obj.parse_message(data)
                reply_data, addr = None, None
                if header.type == xfrm.XFRM_MSG_ACQUIRE:
                    reply_data, addr = self.process_acquire(msg, attributes[xfrm.XFRMA_TMPL])
                elif header.type == xfrm.XFRM_MSG_EXPIRE:
                    reply_data, addr = self.process_expire(msg)
                if reply_data:
                    sock.sendto(reply_data, addr)
