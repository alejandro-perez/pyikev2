#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import logging
import os
from message import (
    Message, Payload, PayloadNONCE, PayloadVENDOR, PayloadKE, Proposal,
    Transform, PayloadSA, PayloadAUTH, PayloadIDi, PayloadIDr, PayloadTSi,
    PayloadTSr, TrafficSelector, PayloadNOTIFY, PayloadDELETE)
from message import (
    IkeSaError, ChildSaError, InvalidSyntax, UnsupportedCriticalPayload,
    NoProposalChosen, InvalidKePayload, AuthenticationFailed, InvalidSelectors,
    PayloadNotFound, ChildSaNotFound)
from helpers import SafeEnum, SafeIntEnum, hexstring
from random import SystemRandom
from crypto import DiffieHellman, Prf, Integrity, Cipher, Crypto
from struct import pack, unpack
from collections import namedtuple, OrderedDict
import json
from ipaddress import ip_address, ip_network
import ipsec
import sys

Keyring = namedtuple('Keyring',
    ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr']
)

ChildSa = namedtuple('ChildSa', ['inbound_spi', 'outbound_spi', 'protocol'])

class IkeSa(object):
    """ This class controls the state machine of a IKE SA
        It is triggered with received Messages and/or IPsec events
    """
    class State(SafeIntEnum):
        INITIAL = 0
        INIT_RES_SENT = 1
        ESTABLISHED = 2
        REKEYED = 3
        DELETED = 4

    def __init__(self, is_initiator, peer_spi, configuration, myaddr, peeraddr):
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
        self.myaddr = myaddr
        self.peeraddr = peeraddr
        self.child_sas = []

    def _generate_ike_sa_key_material(self, ike_proposal, nonce_i, nonce_r,
                                      spi_i, spi_r, shared_secret,
                                      old_sk_d=None):
        """ Generates IKE_SA key material based on the proposal and DH
        """
        prf = Prf(ike_proposal.get_transform(Transform.Type.PRF).id)
        integ = Integrity(ike_proposal.get_transform(Transform.Type.INTEG).id)
        cipher = Cipher(ike_proposal.get_transform(Transform.Type.ENCR).id,
                        ike_proposal.get_transform(Transform.Type.ENCR).keylen)

        if not old_sk_d:
            SKEYSEED = prf.prf(nonce_i + nonce_r, shared_secret)
        else:
            SKEYSEED = prf.prf(old_sk_d, shared_secret + nonce_i + nonce_r)

        logging.debug('Generated SKEYSEED: {}'.format(hexstring(SKEYSEED)))

        keymat = prf.prfplus(
            SKEYSEED,
            nonce_i + nonce_r + spi_i + spi_r,
            prf.key_size * 3 + integ.key_size * 2 + cipher.key_size * 2)
        ike_sa_keyring = Keyring._make(
            unpack('>{0}s{1}s{1}s{2}s{2}s{0}s{0}s'.format(prf.key_size,
                                                          integ.key_size,
                                                          cipher.key_size),
                   keymat))
        crypto_i = Crypto(cipher, ike_sa_keyring.sk_ei,
                          integ, ike_sa_keyring.sk_ai,
                          prf, ike_sa_keyring.sk_pi)
        crypto_r = Crypto(cipher, ike_sa_keyring.sk_er,
                          integ, ike_sa_keyring.sk_ar,
                          prf, ike_sa_keyring.sk_pr)
        self.my_crypto = crypto_i if self.is_initiator else crypto_r
        self.peer_crypto = crypto_r if self.is_initiator else crypto_i

        logging.debug('Generated sk_d: {}'.format(hexstring(ike_sa_keyring.sk_d)))
        logging.debug('Generated sk_ai: {}'.format(hexstring(ike_sa_keyring.sk_ai)))
        logging.debug('Generated sk_ar: {}'.format(hexstring(ike_sa_keyring.sk_ar)))
        logging.debug('Generated sk_ei: {}'.format(hexstring(ike_sa_keyring.sk_ei)))
        logging.debug('Generated sk_er: {}'.format(hexstring(ike_sa_keyring.sk_er)))
        logging.debug('Generated sk_pi: {}'.format(hexstring(ike_sa_keyring.sk_pi)))
        logging.debug('Generated sk_pr: {}'.format(hexstring(ike_sa_keyring.sk_pr)))

        return ike_sa_keyring

    def delete_child_sas(self):
        for child_sa in self.child_sas:
            ipsec.delete_sa(ip_address(self.peeraddr[0]), child_sa.protocol,
                            child_sa.outbound_spi)
            ipsec.delete_sa(ip_address(self.myaddr[0]), child_sa.protocol,
                            child_sa.inbound_spi)

    def _generate_child_sa_key_material(self, ike_proposal, child_proposal,
                                        nonce_i, nonce_r, sk_d):
        """ Generates CHILD_SA key material
        """
        prf = Prf(ike_proposal.get_transform(Transform.Type.PRF).id)

        # ESP and AH need integrity transform
        integ = Integrity(child_proposal.get_transform(Transform.Type.INTEG).id)
        integ_key_size = integ.key_size
        encr_key_size = 0
        if child_proposal.protocol_id == Proposal.Protocol.ESP:
            cipher = Cipher(
                child_proposal.get_transform(Transform.Type.ENCR).id,
                child_proposal.get_transform(Transform.Type.ENCR).keylen)
            encr_key_size = cipher.key_size

        keymat = prf.prfplus(
            sk_d, nonce_i + nonce_r, 2 * integ_key_size + 2 * encr_key_size)

        (sk_ei, sk_ai, sk_er, sk_ar) = unpack(
            '>{0}s{1}s{0}s{1}s'.format(encr_key_size, integ_key_size),
            keymat)
        child_sa_keyring = Keyring(sk_ai=sk_ai, sk_ei=sk_ei, sk_ar=sk_ar,
                                   sk_er=sk_er, sk_d=None, sk_pi=None,
                                   sk_pr=None)

        logging.debug('Generated sk_ai: {}'.format(hexstring(sk_ai)))
        logging.debug('Generated sk_ar: {}'.format(hexstring(sk_ar)))
        logging.debug('Generated sk_ei: {}'.format(hexstring(sk_ei)))
        logging.debug('Generated sk_er: {}'.format(hexstring(sk_er)))

        return child_sa_keyring

    def _select_best_sa_proposal(self, my_proposal, peer_payload_sa):
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
                if (set(selected_transforms)
                        == set(x.type for x in my_proposal.transforms)):
                    return Proposal(1, my_proposal.protocol_id,
                                    peer_proposal.spi,
                                    list(selected_transforms.values()))
        raise NoProposalChosen('Could not find a suitable matching Proposal')

    def _select_best_ike_sa_proposal(self, peer_payload_sa):
        my_proposal = Proposal(
            1, Proposal.Protocol.IKE, b'',
            (self.configuration['encr'] + self.configuration['integ']
             + self.configuration['prf'] + self.configuration['dh']))
        return self._select_best_sa_proposal(my_proposal, peer_payload_sa)

    def _select_best_child_sa_proposal(self, peer_payload_sa, ipsec_conf):
        proto = ipsec_conf['ipsec_proto']
        if proto == Proposal.Protocol.ESP:
            my_proposal = Proposal(1, proto, b'',
                                   ipsec_conf['encr'] + ipsec_conf['integ'])
        else:
            my_proposal = Proposal(1, proto, b'', ipsec_conf['integ'])
        return self._select_best_sa_proposal(my_proposal, peer_payload_sa)

    def _generate_traffic_selectors(self, ipsec_conf):
        """ Generates traffic selectors based on an ipsec configuration
        """
        conf_tsi = TrafficSelector.from_network(ipsec_conf['my_subnet'],
                                                ipsec_conf['my_port'],
                                                ipsec_conf['ip_proto'])
        conf_tsr = TrafficSelector.from_network(ipsec_conf['peer_subnet'],
                                                ipsec_conf['peer_port'],
                                                ipsec_conf['ip_proto'])
        return (conf_tsi, conf_tsr)

    def _get_ipsec_configuration(self, payload_tsi, payload_tsr):
        """ Find matching IPsec configuration.
            It iterates over the received TS in reversed order and returns the
            first configuration that is bigger than our selectors, and the
            narrowed selectors as well
        """
        for tsi in reversed(payload_tsi.traffic_selectors):
            for tsr in reversed(payload_tsr.traffic_selectors):
                for ipsec_conf in self.configuration['protect']:
                    (conf_tsi,
                     conf_tsr) = self._generate_traffic_selectors(ipsec_conf)
                    narrowed_tsi = tsi.intersection(conf_tsi)
                    narrowed_tsr = tsr.intersection(conf_tsr)
                    if narrowed_tsi and narrowed_tsr:
                        return (ipsec_conf, narrowed_tsi, narrowed_tsr)
        raise InvalidSelectors(
            'TS could not be matched with any IPsec configuration')

    def log_message(self, message, addr, data, send=True):
        logging.info(
            'IKE_SA: {}. {} {} {} ({} bytes) {} {}:{}'.format(
                hexstring(self.my_spi),
                'Sent' if send else 'Received',
                Message.Exchange.safe_name(message.exchange_type),
                'response' if message.is_response else 'request',
                len(data),
                'to' if send else 'from',
                addr[0], addr[1]))
        logging.debug(json.dumps(message.to_dict(),
                                 indent=None if logging.no_indent else 2))

    def _generate_ike_error_response(self, request, notification_type,
                                     notification_data=b''):
        notify_error = PayloadNOTIFY(Proposal.Protocol.NONE, notification_type,
                                     b'', notification_data)
        return  Message(
            spi_i=request.spi_i,
            spi_r=request.spi_r,
            major=2,
            minor=0,
            exchange_type=request.exchange_type,
            is_response=True,
            can_use_higher_version=False,
            is_initiator=self.is_initiator,
            message_id=self.peer_msg_id,
            payloads=([notify_error] if request.exchange_type
                        == Message.Exchange.IKE_SA_INIT else []),
            encrypted_payloads=([notify_error] if request.exchange_type
                                    != Message.Exchange.IKE_SA_INIT else [])
        )

    def process_message(self, data, addr):
        """ Performs the common tasks for IKE message handling,
            including logging for the message and the reply (if any), check of
            message IDs and control of retransmissions
        """
        # dict with the form of tuple(Exchange type, is_request): method
        _handler_dict = {
            (Message.Exchange.IKE_SA_INIT, True): self.process_ike_sa_init_request,
            (Message.Exchange.IKE_AUTH, True): self.process_ike_auth_request,
            (Message.Exchange.INFORMATIONAL, True): self.process_informational_request,
            (Message.Exchange.CREATE_CHILD_SA, True): self.process_create_child_sa_request,
        }

        # parse the whole message (including encrypted data)
        message = Message.parse(data, header_only=False,
                                crypto=self.peer_crypto)
        self.log_message(message, addr, data, send=False)

        # check message_id and handle retransmissions
        if (message.message_id == self.peer_msg_id - 1
                and data == self.last_received_message_data):
            logging.warning(
                'Retransmission detected. Sending last sent message')
            return (True, self.last_sent_message_data)
        elif message.message_id != self.peer_msg_id:
            logging.error(
                'Message with invalid ID. Expecting {}. Omitting.'
                ''.format(self.peer_msg_id))
            return (True, None)

        # process the message
        try:
            handler = _handler_dict[(message.exchange_type, message.is_request)]
        except KeyError:
            logging.error('I don\'t know how to handle this message. '
                'Please, implement a handler!')
        status = False
        reply = None
        try:
            reply = handler(message)
            status = True
            # if the message was processed succesfully, we record it for future reference
            self.last_received_message_data = data
            self.last_received_message = message
            self.peer_msg_id = self.peer_msg_id + 1
        except NoProposalChosen as ex:
            logging.error('IKE_SA: {}. {}'.format(
                hexstring(self.my_spi)),str(ex))
            reply = self._generate_ike_error_response(
                message, PayloadNOTIFY.Type.NO_PROPOSAL_CHOSEN)
        except UnsupportedCriticalPayload as ex:
            logging.error('IKE_SA: {}. {}'.format(
                hexstring(self.my_spi)),str(ex))
            reply = self._generate_ike_error_response(
                message, PayloadNOTIFY.Type.UNSUPPORTED_CRITICAL_PAYLOAD)
        except InvalidSyntax as ex:
            logging.error('IKE_SA: {}. {}'.format(
                hexstring(self.my_spi)),str(ex))
            reply = self._generate_ike_error_response(
                message, PayloadNOTIFY.Type.INVALID_SYNTAX)
        except AuthenticationFailed as ex:
            logging.error('IKE_SA: {}. {}'.format(
                hexstring(self.my_spi)),str(ex))
            reply = self._generate_ike_error_response(
                message, PayloadNOTIFY.Type.AUTHENTICATION_FAILED)
        except InvalidSelectors as ex:
            logging.error('IKE_SA: {}. {}'.format(
                hexstring(self.my_spi)),str(ex))
            reply = self._generate_ike_error_response(
                message, PayloadNOTIFY.Type.INVALID_SELECTORS)
        except InvalidKePayload as ex:
            logging.error('IKE_SA: {}. {}'.format(
                hexstring(self.my_spi)),str(ex))
            reply = self._generate_ike_error_response(
                message,
                PayloadNOTIFY.Type.INVALID_KE_PAYLOAD,
                notification_data=pack('>H', ex.group))
        except IkeSaError as ex:
            logging.error('IKE_SA: {}. {}'.format(
                hexstring(self.my_spi)),str(ex))
            reply = self._generate_ike_error_response(
                message, PayloadNOTIFY.Type.INVALID_SYNTAX)

        # If there is a reply
        if reply:
            crypto = (self.my_crypto
                        if reply.exchange_type != Message.Exchange.IKE_SA_INIT
                        else None)
            reply_data = reply.to_bytes(crypto)
            self.log_message(reply, addr, reply_data, send=True)
            self.last_sent_message_data = reply_data
            self.last_sent_message = reply
            return True, reply_data

        return True, None

    def _process_ike_sa_negotiation_request(self, request, encrypted=False,
                                            old_sk_d=None):
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
            raise InvalidKePayload('Invalid DH group used. I requested {}'
                                   ''.format(my_dh_group), group=my_dh_group)
        dh = DiffieHellman(payload_ke.dh_group)
        dh.compute_secret(payload_ke.ke_data)
        logging.debug('Generated DH shared secret: {}'
                      ''.format(hexstring(dh.shared_secret)))
        response_payload_ke = PayloadKE(dh.group, dh.public_key)

        # generate IKE SA key material
        self.ike_sa_keyring = self._generate_ike_sa_key_material(
            ike_proposal=self.chosen_proposal,
            nonce_i=payload_nonce.nonce,
            nonce_r=response_payload_nonce.nonce,
            spi_i=self.peer_spi,
            spi_r=self.my_spi,
            shared_secret=dh.shared_secret,
            old_sk_d=old_sk_d)

        return [response_payload_sa, response_payload_nonce,
                response_payload_ke]

    def process_ike_sa_init_request(self, request):
        """ Processes a IKE_SA_INIT message and returns a IKE_SA_INIT response
        """
        # check state
        if self.state != IkeSa.State.INITIAL:
            raise IkeSaError('IKE SA state cannot proccess IKE_SA_INIT message')

        # process the IKE_SA negotiation payloads
        response_payloads = self._process_ike_sa_negotiation_request(request,
                                                                     False)

        # generate the response payload VENDOR
        response_payloads.append(PayloadVENDOR(b'pyikev2-0.1'))

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
            message_id=self.peer_msg_id,
            payloads=response_payloads,
            encrypted_payloads=[])

        # switch state
        self.state = IkeSa.State.INIT_RES_SENT

        # return response
        return response

    def _generate_psk_auth_payload(self, message_data, nonce, payload_id, sk_p):
        prf = self.peer_crypto.prf.prf
        data_to_be_signed = (message_data + nonce
                             + prf(sk_p, payload_id.to_bytes()))
        keypad = prf(self.configuration['psk'], b'Key Pad for IKEv2')
        return prf(keypad, data_to_be_signed)

    def _generate_peer_psk_auth_payload(self, payload_id):
        return self._generate_psk_auth_payload(
            self.last_received_message_data,
            self.last_sent_message.get_payload(Payload.Type.NONCE).nonce,
            payload_id, self.peer_crypto.sk_p)

    def _generate_my_psk_auth_payload(self, payload_id):
        return self._generate_psk_auth_payload(
            self.last_sent_message_data,
            self.last_received_message.get_payload(Payload.Type.NONCE).nonce,
            payload_id, self.my_crypto.sk_p)

    def _process_create_child_sa_negotiation_req(self, request,
                                                 initial_exchange=True):
        """ This method process a CREATE CHILD SA negotiation request
        """
        # get some relevant payloads from the message
        response_payloads = []
        request_payload_sa = request.get_payload(Payload.Type.SA, True)
        request_payload_tsi = request.get_payload(Payload.Type.TSi, True)
        request_payload_tsr = request.get_payload(Payload.Type.TSr, True)

        # source of nonces is different for the initial exchange
        if initial_exchange:
            request_payload_nonce = (
                self.last_received_message.get_payload(Payload.Type.NONCE))
            response_payload_nonce = (
                self.last_sent_message.get_payload(Payload.Type.NONCE))
        else:
            request_payload_nonce = request.get_payload(Payload.Type.NONCE,
                                                        True)
            response_payload_nonce = PayloadNONCE()
            response_payloads.append(response_payload_nonce)

        # Find matching IPsec configuration and narrow TS
        # (reverse order as we are responders)
        (ipsec_conf, chosen_tsr, chosen_tsi) = self._get_ipsec_configuration(
            request_payload_tsr, request_payload_tsi)

        # check which mode peer wants and compare to ours
        mode = ipsec.Mode.TUNNEL
        if request.get_notifies(PayloadNOTIFY.Type.USE_TRANSPORT_MODE, True):
            mode = ipsec.Mode.TRANSPORT
            response_payloads.append(
                PayloadNOTIFY(
                    Proposal.Protocol.NONE,
                    PayloadNOTIFY.Type.USE_TRANSPORT_MODE, b'', b''))

        if ipsec_conf['mode'] != mode:
            raise InvalidSelectors('Invalid mode requested')

        # generate the response payload SA with the chosen proposal
        chosen_child_proposal = self._select_best_child_sa_proposal(
            request_payload_sa, ipsec_conf)

        # generate CHILD key material
        child_sa_keyring = self._generate_child_sa_key_material(
            ike_proposal=self.chosen_proposal,
            child_proposal=chosen_child_proposal,
            nonce_i=request_payload_nonce.nonce,
            nonce_r=response_payload_nonce.nonce,
            sk_d=self.ike_sa_keyring.sk_d)

        # create the IPsec SAs according to the negotiated CHILD SA
        child_sa = ChildSa(outbound_spi=chosen_child_proposal.spi,
                           inbound_spi=os.urandom(4),
                           protocol=chosen_child_proposal.protocol_id)
        self.child_sas.append(child_sa)
        if ipsec_conf['ipsec_proto'] == Proposal.Protocol.ESP:
            encr_transform = chosen_child_proposal.get_transform(
                Transform.Type.ENCR).id
        else:
            encr_transform = None
        ipsec.create_sa(
            ip_address(self.myaddr[0]), ip_address(self.peeraddr[0]),
            chosen_tsr, chosen_tsi,
            chosen_child_proposal.protocol_id,
            child_sa.outbound_spi,
            encr_transform,
            child_sa_keyring.sk_er,
            chosen_child_proposal.get_transform(Transform.Type.INTEG).id,
            child_sa_keyring.sk_ar,
            mode)
        ipsec.create_sa(
            ip_address(self.peeraddr[0]), ip_address(self.myaddr[0]),
            chosen_tsi, chosen_tsr,
            chosen_child_proposal.protocol_id,
            child_sa.inbound_spi,
            encr_transform,
            child_sa_keyring.sk_ei,
            chosen_child_proposal.get_transform(Transform.Type.INTEG).id,
            child_sa_keyring.sk_ai,
            mode)

        # generate the response Payload SA
        chosen_child_proposal.spi = child_sa.inbound_spi
        response_payloads.append(PayloadSA([chosen_child_proposal]))

        # generate response Payload TSi/TSr based on the chosen selectors
        response_payloads.append(PayloadTSi([chosen_tsi]))
        response_payloads.append(PayloadTSr([chosen_tsr]))

        return response_payloads

    def process_ike_auth_request(self, request):
        """ Processes a IKE_AUTH request message and returns a
            IKE_AUTH response
        """
        if self.state != IkeSa.State.INIT_RES_SENT:
            raise InvalidSyntax(
                'IKE SA state cannot proccess IKE_SA_INIT message')

        # get some relevant payloads from the message
        request_payload_idi = request.get_payload(Payload.Type.IDi, True)
        request_payload_auth = request.get_payload(Payload.Type.AUTH, True)

        # verify AUTH payload
        if request_payload_auth.method != PayloadAUTH.Method.PSK:
            raise AuthenticationFailed('AUTH method not supported')
        auth_data = self._generate_peer_psk_auth_payload(request_payload_idi)
        if auth_data != request_payload_auth.auth_data:
            raise AuthenticationFailed('Invalid AUTH data received')

        # process the CHILD_SA creation negotiation
        response_payloads = self._process_create_child_sa_negotiation_req(
            request, initial_exchange=True)

        # generate IDr
        response_payload_idr = PayloadIDr(self.configuration['id'].id_type,
                                          self.configuration['id'].id_data)

        # generate AUTH payload
        auth_data = self._generate_my_psk_auth_payload(response_payload_idr)
        response_payload_auth = PayloadAUTH(PayloadAUTH.Method.PSK, auth_data)

        response_payloads += [response_payload_idr, response_payload_auth]

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
            message_id=self.peer_msg_id,
            payloads=[],
            encrypted_payloads=response_payloads)

        # increase msg_id and transition
        self.state = IkeSa.State.ESTABLISHED

        return response

    def process_informational_request(self, request):
        """ Processes an INFORMATIONAL message and returns a INFORMATIONAL response
        """
        response_payloads = []
        try:
            delete_payload = request.get_payload(Payload.Type.DELETE, True)
        except PayloadNotFound:
            delete_payload = None

        if delete_payload is not None:
            # if protocol is IKE, just mark the IKE SA for removal and return
            # emtpy INFORMATIONAL exchange
            if delete_payload.protocol_id == Proposal.Protocol.IKE:
                if self.state not in (IkeSa.State.ESTABLISHED,
                                      IkeSa.State.REKEYED):
                    raise IkeSaError(
                        'IKE SA state cannot be deleted on this state: {}'
                        ''.format(self.state))
                self.state = IkeSa.State.DELETED

            # if protocol is either AH or ESP, delete the Child SAs and return
            # the inbound SPI
            else:
                try:
                    child_sa = next(x for x in self.child_sas
                                    if x.outbound_spi == delete_payload.spis[0])
                except StopIteration:
                    raise ChildSaNotFound(delete_payload.spis[0])
                ipsec.delete_sa(ip_address(self.peeraddr[0]),
                                child_sa.protocol, child_sa.outbound_spi)
                ipsec.delete_sa(ip_address(self.myaddr[0]),
                                child_sa.protocol, child_sa.inbound_spi)
                self.child_sas.remove(child_sa)
                response_payloads.append(
                    PayloadDELETE(delete_payload.protocol_id,
                                  [child_sa.inbound_spi]))

        return Message(
            spi_i=request.spi_i,
            spi_r=request.spi_r,
            major=2,
            minor=0,
            exchange_type=Message.Exchange.INFORMATIONAL,
            is_response=True,
            can_use_higher_version=False,
            is_initiator=self.is_initiator,
            message_id=self.peer_msg_id,
            payloads=[],
            encrypted_payloads=response_payloads)

    def process_create_child_sa_request(self, request):
        """ Processes a CREATE_CHILD_SA message and returns response
        """
        if self.state != IkeSa.State.ESTABLISHED:
            raise IkeSaError(
                'IKE SA state cannot proccess CREATE_CHILD_SA message')

        # determine whether this concerns to IKE_SA or CHILD_SA
        payload_sa = request.get_payload(Payload.Type.SA, True)
        proposal = payload_sa.proposals[0]

        # if this is a IKE_REKEY
        if proposal.protocol_id == Proposal.Protocol.IKE:
            logging.info('Received request for rekeying current IKE_SA')
            self.new_ike_sa = IkeSa(
                self.is_initiator, int.from_bytes(proposal.spi, 'big'),
                self.configuration, self.myaddr, self.peeraddr)
            # take over the existing child sas
            self.new_ike_sa.child_sas = self.child_sas
            self.child_sas = []
            response_payloads = (
                self.new_ike_sa._process_ike_sa_negotiation_request(
                    request, True, self.ike_sa_keyring.sk_d))
            self.new_ike_sa.state = IkeSa.State.ESTABLISHED
            self.state = IkeSa.State.REKEYED

        # if it concerns to CHILD_SAs
        else:
            # if this is a rekey, check if CHILD SA exists and add notification
            response_payloads = []
            rekey_notify = request.get_notifies(PayloadNOTIFY.Type.REKEY_SA,
                                                encrypted=True)
            if rekey_notify:
                try:
                    # use only the first notification
                    rekeyed_child_sa = next(x for x in self.child_sas
                                    if x.outbound_spi == rekey_notify[0].spi)
                except StopIteration:
                    raise ChildSaNotFound(rekey_notify[0].spi)
                response_payloads.append(
                    PayloadNOTIFY(proposal.protocol_id,
                                  PayloadNOTIFY.Type.REKEY_SA,
                                  rekeyed_child_sa.inbound_spi, b''))

            response_payloads += self._process_create_child_sa_negotiation_req(
                    request, initial_exchange=False)

        return Message(
            spi_i=request.spi_i,
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
        )

class IkeSaController:
    def __init__(self, myaddr, configuration):
        self.ike_sas = {}
        self.configuration = configuration

        # establish policies
        ipsec.flush_policies()
        ipsec.flush_sas()
        for peer_addr, ike_conf in configuration.items():
            ipsec.create_policies(myaddr, peer_addr, ike_conf)

    def dispatch_message(self, data, myaddr, peeraddr):
        header = Message.parse(data, header_only=True)

        # if IKE_SA_INIT request, then a new IkeSa must be created
        if (header.exchange_type == Message.Exchange.IKE_SA_INIT and
                header.is_request):
            # look for matching configuration
            ike_configuration = self.configuration.get_ike_configuration(
                peeraddr[0])
            ike_sa = IkeSa(is_initiator=False, peer_spi=header.spi_i,
                           configuration=ike_configuration,
                           myaddr=myaddr, peeraddr=peeraddr)
            self.ike_sas[ike_sa.my_spi] = ike_sa
            logging.info('Starting the creation of IKE SA with SPI={}. '
                         'Count={}'.format(hexstring(ike_sa.my_spi),
                                           len(self.ike_sas)))
        # else, look for the IkeSa in the dict
        else:
            my_spi = header.spi_r if header.is_initiator else header.spi_i
            try:
                ike_sa = self.ike_sas[my_spi]
            except KeyError:
                logging.warning('Received message for unknown SPI={}. Omitting.'
                                ''.format(hexstring(my_spi)))
                logging.debug(json.dumps(header.to_dict(),
                              indent=None if logging.no_indent else 2))
                return None

        # generate the reply (if any)
        status, reply = ike_sa.process_message(data, peeraddr)

        # if rekeyed, add the new IkeSa
        if ike_sa.state == IkeSa.State.REKEYED:
            self.ike_sas[ike_sa.new_ike_sa.my_spi] = ike_sa.new_ike_sa
            logging.info('IKE SA with SPI={} created by rekey.'
                         'Count={}'.format(hexstring(ike_sa.my_spi)),
                                           len(self.ike_sas))

        # if the IKE_SA needs to be closed
        if not status or ike_sa.state in (IkeSa.State.DELETED,):
            ike_sa.delete_child_sas()
            del self.ike_sas[ike_sa.my_spi]
            logging.info('Deleted IKE_SA with SPI={}. Count={}'
                         ''.format(hexstring(ike_sa.my_spi)),
                                   len(self.ike_sas))
        return reply
