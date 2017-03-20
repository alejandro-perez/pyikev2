#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import logging
import os
from message import (Message, Payload, PayloadNONCE, PayloadVENDOR, PayloadKE,
    Proposal, Transform, NoProposalChosen, PayloadSA, InvalidKePayload,
    InvalidSyntax, PayloadAUTH, AuthenticationFailed, PayloadIDi, PayloadIDr,
    IkeSaError, PayloadTSi, PayloadTSr, TrafficSelector, InvalidSelectors)
from helpers import SafeEnum, SafeIntEnum, hexstring
from random import SystemRandom
from crypto import DiffieHellman, Prf, Integrity, Cipher, Crypto
from struct import pack, unpack
from collections import namedtuple, OrderedDict
import json
from ipaddress import ip_address, ip_network

Keyring = namedtuple('Keyring',
    ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr']
)

class Policy(object):
    """ Represents a security policy

        Policies are always defined as if src_selector was our side of the
        conversation. E.g. a HTTP server would set src_port=80 and dst_port=0
    """
    class Mode(SafeIntEnum):
        TRANSPORT = 1
        TUNNEL = 2

    def __init__(self, src_selector, src_port, dst_selector, dst_port,
            ip_proto, ipsec_proto, mode, tunnel_src=None,
            tunnel_dst=None):
        self.src_selector = ip_network(src_selector)
        self.src_port = src_port
        self.dst_selector = ip_network(dst_selector)
        self.dst_port = dst_port
        self.ip_protocol = ip_proto
        self.ipsec_protocol = ipsec_proto
        self.mode = mode
        self.tunnel_src = ip_address(tunnel_src) if tunnel_src else None
        self.tunnel_dst = ip_address(tunnel_dst) if tunnel_dst else None

    def get_tsi(self):
        return TrafficSelector(
            ts_type=TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            ip_proto=self.ip_protocol,
            start_port=self.src_port,
            end_port=65535 if self.src_port == 0 else self.src_port,
            start_addr=self.src_selector[0],
            end_addr=self.src_selector[-1]
        )

    def get_tsr(self):
        return TrafficSelector(
            ts_type=TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            ip_proto=self.ip_protocol,
            start_port=self.dst_port,
            end_port=65535 if self.dst_port == 0 else self.dst_port,
            start_addr=self.dst_selector[0],
            end_addr=self.dst_selector[-1]
        )

    def to_dict(self):
        result = OrderedDict([
            ('src_selector', '{}:{}'.format(self.src_selector, self.src_port)),
            ('dst_selector', '{}:{}'.format(self.dst_selector, self.dst_port)),
            ('ip_protocol', TrafficSelector.IpProtocol.safe_name(self.ip_protocol)),
            ('ipsec_protocol', Proposal.Protocol.safe_name(self.ipsec_protocol)),
            ('mode', Policy.Mode.safe_name(self.mode)),
        ])
        if self.mode == Policy.Mode.TUNNEL:
            result.update(OrderedDict([
                ('tunnel_src', str(self.tunnel_src)),
                ('tunnel_dst', str(self.tunnel_dst)),
            ]))
        return result

class IkeSa(object):
    class State(SafeIntEnum):
        INITIAL = 0
        INIT_RES_SENT = 1
        ESTABLISHED = 2

    """ This class controls the state machine of a IKE SA
        It is triggered with received Messages and/or IPsec events
    """
    def __init__(self, is_initiator, policies, configuration):
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
        self.policies = policies
        self.configuration = configuration

    @property
    def spi_i(self):
        return self.my_spi if self.is_initiator else self.peer_spi

    @property
    def spi_r(self):
        return self.my_spi if self.is_initiator else self.peer_spi

    def _generate_ike_sa_key_material(self, ike_proposal, nonce_i, nonce_r,
                spi_i, spi_r, shared_secret):
        """ Generates IKE_SA key material based on the proposal and DH
        """
        prf = Prf(ike_proposal.get_transform(Transform.Type.PRF).id)
        integ = Integrity(ike_proposal.get_transform(Transform.Type.INTEG).id)
        cipher = Cipher(
            ike_proposal.get_transform(Transform.Type.ENCR).id,
            ike_proposal.get_transform(Transform.Type.ENCR).keylen
        )

        SKEYSEED = prf.prf(nonce_i + nonce_r, shared_secret)
        logging.debug('Generated SKEYSEED: {}'.format(hexstring(SKEYSEED)))

        keymat = prf.prfplus(
            SKEYSEED,
            nonce_i + nonce_r + pack('>Q', spi_i) + pack('>Q', spi_r),
            prf.key_size * 3 + integ.key_size * 2 + cipher.key_size * 2
        )

        self.ike_sa_keyring = Keyring._make(
            unpack('>{0}s{1}s{1}s{2}s{2}s{0}s{0}s'.format(
                    prf.key_size, integ.key_size, cipher.key_size),
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

        sk_ei, sk_ai, sk_er, sk_ar = unpack(
            '>{0}s{1}s{0}s{1}s'.format(encr_key_size, integ_key_size),
            keymat)

        logging.debug('Generated sk_ai: {}'.format(hexstring(sk_ai)))
        logging.debug('Generated sk_ar: {}'.format(hexstring(sk_ar)))
        logging.debug('Generated sk_ei: {}'.format(hexstring(sk_ei)))
        logging.debug('Generated sk_er: {}'.format(hexstring(sk_er)))

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
                if (set(selected_transforms) ==
                        set(x.type for x in my_proposal.transforms)):
                    return Proposal(1, my_proposal.protocol_id, b'',
                        list(selected_transforms.values()))
        raise NoProposalChosen('Could not find a suitable matching Proposal')

    def _select_best_ike_sa_proposal(self, peer_payload_sa):
        my_proposal = Proposal(
            1, Proposal.Protocol.IKE, b'',
            (self.configuration['encr'] + self.configuration['integ'] +
                self.configuration['prf'] + self.configuration['dh'])
        )
        return self._select_best_sa_proposal(my_proposal, peer_payload_sa)

    def _select_best_child_sa_proposal(self, peer_payload_sa):
        my_proposal = Proposal(
            1, Proposal.Protocol.ESP, b'',
            [
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 256),
                Transform(Transform.Type.ENCR, Cipher.Id.ENCR_AES_CBC, 128),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_SHA1_96),
                Transform(Transform.Type.INTEG, Integrity.Id.AUTH_HMAC_MD5_96),
            ]
        )
        return self._select_best_sa_proposal(my_proposal, peer_payload_sa)

    def _select_best_traffic_selector(self, payload_tsi, payload_tsr):
        """ Selects best matching traffic selectors.
            Only executed on the responder side, thus we need to use policy's
            reversed TSs.
            It iterates over the received TS in reversed order and returns the
            first pair that intersecs with any of our policies
        """
        for tsi in reversed(payload_tsi.traffic_selectors):
            for tsr in reversed(payload_tsr.traffic_selectors):
                for policy in self.policies:
                    policy_tsi = policy.get_tsi()
                    policy_tsr = policy.get_tsr()
                    narrowed_tsi = tsi.intersection(policy_tsr)
                    narrowed_tsr = tsr.intersection(policy_tsi)
                    if narrowed_tsi and narrowed_tsr:
                        return (narrowed_tsi, narrowed_tsr)
        raise InvalidSelectors('TS could not be matched with any Policy')

    def log_message(self, message, addr, data, send=True):
        logging.info('IKE_SA: {}. {} {} {} ({} bytes) {} {}'.format(
            hexstring(pack('>Q', self.my_spi)),
            'Sent' if send else 'Received',
            Message.Exchange.safe_name(message.exchange_type),
            'response' if message.is_response else 'request',
            len(data),
            'to' if send else 'from',
            addr))
        logging.debug(json.dumps(message.to_dict(), indent=logging.indent_json))

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
        }

        # parse the whole message (including encrypted data)
        message = Message.parse(data, header_only=False, crypto=self.peer_crypto)
        self.log_message(message, addr, data, send=False)

        # check message_id
        if (message.message_id == self.peer_msg_id - 1 and
                data == self.last_received_message_data):
            logging.warning('Retransmission detected. Sending last sent message')
            return self.last_sent_message_data
        elif message.message_id != self.peer_msg_id:
            logging.error(
                'Message with invalid ID. Expecting {}. Omitting.'
                ''.format(self.peer_msg_id))
            return True, None

        # get the handler fnc
        try:
            handler = _handler_dict[(message.exchange_type, message.is_request)]
        except KeyError:
            logging.error('I don\'t know how to handle this message. '
                'Please, implement a handler!')
            return False, None

        # try to process the message and get a reply
        try:
            reply = handler(message)
        except IkeSaError as ex:
            # TODO: Some errors are non-aborting (and send NOTIFY or such)
            logging.error(ex)
            return False, None

        # if the message was processed succesfully, we record it for future reference
        self.last_received_message_data = data
        self.last_received_message = message
        self.peer_msg_id = self.peer_msg_id + 1

        # If there is a reply
        if reply:
            crypto = (self.my_crypto
                if reply.exchange_type != Message.Exchange.IKE_SA_INIT else None)
            reply_data = reply.to_bytes(crypto)
            self.log_message(reply, addr, reply_data, send=True)
            self.last_sent_message_data = reply_data
            self.last_sent_message = reply
            self.my_msg_id = self.my_msg_id + 1
            return True, reply_data

        return True, None

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
        self.chosen_proposal = self._select_best_ike_sa_proposal(request_payload_sa)

        # check that DH groups match
        my_dh_group = self.chosen_proposal.get_transform(Transform.Type.DH).id
        if my_dh_group != request_payload_ke.dh_group:
            raise InvalidKePayload('Invalid DH group used. I request {}'.format(my_dh_group))

        # generate the response payload KE
        dh = DiffieHellman(request_payload_ke.dh_group)
        dh.compute_secret(request_payload_ke.ke_data)
        logging.debug('Generated DH shared secret: {}'.format(hexstring(dh.shared_secret)))
        response_payload_ke = PayloadKE(dh.group, dh.public_key)

        # generate payload NONCE
        response_payload_nonce = PayloadNONCE()

        # generate IKE SA key material
        self._generate_ike_sa_key_material(
            ike_proposal=self.chosen_proposal,
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

        # transition
        self.state = IkeSa.State.INIT_RES_SENT

        # return response
        return response

    def _generate_psk_auth_payload(self, message_data, nonce, payload_id, sk_p):
        prf = self.peer_crypto.prf.prf
        data_to_be_signed = (message_data + nonce + prf(sk_p, payload_id.to_bytes()))
        keypad = prf(self.configuration['psk'], b'Key Pad for IKEv2')
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

        # generate the response payload SA with the chosen proposal
        chosen_child_proposal = self._select_best_child_sa_proposal(
            request_payload_sa)

        # find matching TS
        chosen_tsi, chosen_tsr = self._select_best_traffic_selector(
            request_payload_tsi, request_payload_tsr)

        # TODO: Take this SPI from an actual acquire to avoid (unlikely) collisions
        chosen_child_proposal.spi = os.urandom(4)

        # generate CHILD key material
        self._generate_child_sa_key_material(
            ike_proposal=self.chosen_proposal,
            child_proposal=chosen_child_proposal,
            nonce_i=self.last_received_message.get_payload(Payload.Type.NONCE).nonce,
            nonce_r=self.last_sent_message.get_payload(Payload.Type.NONCE).nonce,
            sk_d=self.ike_sa_keyring.sk_d
        )

        # generate the response Payload SA
        response_payload_sa = PayloadSA([chosen_child_proposal])

        # generate response Payload TSi/TSr based on the chosen selectors
        response_payload_tsi = PayloadTSi([chosen_tsi])
        response_payload_tsr = PayloadTSr([chosen_tsr])

        # send my IDr
        response_payload_idr = PayloadIDr(self.configuration['id'].id_type,
                                          self.configuration['id'].id_data)

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
                response_payload_tsr, response_payload_idr,
                response_payload_auth],
        )

        # increase msg_id and transition
        self.state = IkeSa.State.ESTABLISHED

        return response

    def process_informational_request(self, request):
        """ Processes an INFORMATIONAL message and returns a INFORMATIONAL response
        """
        # check state
        if self.state != IkeSa.State.ESTABLISHED:
            raise IkeSaError(
                'IKE SA state cannot proccess INFORMATIONAL message')

        # don't do anything yet, just reply with empty informational
        response = Message(
            spi_i=request.spi_i,
            spi_r=request.spi_r,
            major=2,
            minor=0,
            exchange_type=Message.Exchange.INFORMATIONAL,
            is_response=True,
            can_use_higher_version=False,
            is_initiator=self.is_initiator,
            message_id=self.my_msg_id,
            payloads=[],
            encrypted_payloads=[],
        )

        # transition NOT NEEDED

        # return response
        return response
class IkeSaController:
    def __init__(self, configuration):
        self.ike_sas = {}
        self.policies = [
            Policy('10.0.5.17/32', 23, '10.0.5.0/24', 0,
                TrafficSelector.IpProtocol.TCP, Proposal.Protocol.ESP,
                Policy.Mode.TRANSPORT),
        ]
        self.configuration = configuration

    def dispatch_message(self, data, addr):
        header = Message.parse(data, header_only=True)

        # if IKE_SA_INIT request, then a new IkeSa must be created
        if (header.exchange_type == Message.Exchange.IKE_SA_INIT and
                header.is_request):
            # look for matching configuration
            ike_configuration = self.configuration.get_ike_configuration(addr[0])

            ike_sa = IkeSa(is_initiator=False,
                           policies=self.policies, configuration=ike_configuration)
            self.ike_sas[ike_sa.my_spi] = ike_sa
            logging.info('Starting the creation of IKE SA with SPI={}. Count={}'.format(
                hexstring(pack('>Q', ike_sa.my_spi)), len(self.ike_sas)))

        # else, look for the IkeSa in the dict
        else:
            my_spi = header.spi_r if header.is_initiator else header.spi_i
            try:
                ike_sa = self.ike_sas[my_spi]
            except KeyError:
                logging.warning(
                    'Received message for unknown SPI={}. Omitting.'.format(
                        hexstring(pack('>Q', my_spi))))
                logging.debug(json.dumps(header.to_dict(),
                    indent=logging.indent_json))
                return None

        # generate the reply (if any)
        status, reply = ike_sa.process_message(data, addr)

        # if the IKE_SA needs to be closed
        if not status:
            del self.ike_sas[ike_sa.my_spi]
            logging.info('Deleted IKE_SA with SPI={}. Count={}'.format(
                hexstring(pack('>Q', ike_sa.my_spi)), len(self.ike_sas)))
        return reply
