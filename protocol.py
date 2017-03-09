#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import logging
import os
from message import Message, Payload, PayloadNonce, PayloadVendor
from helpers import SafeEnum, SafeIntEnum, hexstring
from random import SystemRandom

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

        # create response message
        response = Message(
            self.spi_i, self.spi_r, 0, 2, 0, Message.Exchange.IKE_SA_INIT,
            True, False, self.is_initiator, self.msg_id_r
        )

        # add the response payload SA. So far, we just copy theirs
        payload_sa = request.get_payload_by_type(Payload.Type.SA)
        response.payloads.append(payload_sa)

        # add the response payload KE. So far, we just copy theirs
        payload_ke = request.get_payload_by_type(Payload.Type.KE)
        response.payloads.append(payload_ke)

        # add the response payload NONCE.
        payload_nonce = PayloadNonce()
        response.payloads.append(payload_nonce)

        # add the response payload VENDOR.
        payload_vendor = PayloadVendor(b'pyikev2-0.1')
        response.payloads.append(payload_vendor)


        # increase msg_id and transition
        self.msg_id_r = self.msg_id_r + 1
        self.state = IkeSa.State.HALF_OPEN

        return response

class IkeSaController:
    def __init__(self):
        self.ike_sas = {}

    def dispatch_message(self, data):
        header = Message.parse_header(data)

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

        else:
            logging.debug('Received unexpected IKE message. Omitting: {}'.format(header))
            return None


        logging.debug('Received message: {}'.format(message))


