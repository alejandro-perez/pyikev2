#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import logging
import os
from message import (Message, Payload, PayloadNonce, PayloadVendor, PayloadKE)
from helpers import SafeEnum, SafeIntEnum, hexstring
from random import SystemRandom
from dh import DiffieHellman

class Ikev2ProtocolError(Exception):
    pass

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

    def process_ike_sa_init_request(self, request):
        """ Processes a IKE_SA_INIT message and returns a IKE_SA_INIT response
        """
        # check state
        if self.state != IkeSa.State.INITIAL:
            raise Ikev2ProtocolError(
                'IKE SA state cannot proccess IKE_SA_INIT message')

        # initialize peer's information
        self.spi_i = request.spi_i
        self.spi_r = SystemRandom().randint(0, 0xFFFFFFFFFFFFFFFF)
        self.is_initiator = False
        self.msg_id_i = request.message_id
        self.msg_id_r = 0

        # generate DH shared secret
        peer_payload_ke = request.get_payload_by_type(Payload.Type.KE)
        dh = DiffieHellman(peer_payload_ke.dh_group, peer_payload_ke.ke_data)
        logging.debug('Generated DH shared secret: {}'.format(hexstring(dh.shared_secret)))

        # create response message

        # add the response payload SA. So far, we just copy theirs
        payload_sa = request.get_payload_by_type(Payload.Type.SA)

        # add the response payload KE
        payload_ke = PayloadKE(dh.group, dh.public_key)

        # add the response payload NONCE.
        payload_nonce = PayloadNonce()

        # add the response payload VENDOR.
        payload_vendor = PayloadVendor(b'pyikev2-0.1')

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

    def dispatch_message(self, data):
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




