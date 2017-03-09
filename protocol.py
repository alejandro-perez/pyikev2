#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
from message import Message
import logging
class Ikev2ProtocolError(Exception):
    pass


class IkeSa:
    class State:
        """ State codes
        """
        UNINITIALIZED = 0

    """ This class controls the state machine of a IKE SA
        It is triggered with received Messages and/or IPsec events
    """
    def __init__(self):
        self.spi_i = None
        self.spi_r = None
        self.is_initiator = is_initiator
        self.state = IkeSa.State.UNINITIALIZED
        self.msg_id_i = 0
        self.msg_id_r = 0
        self.last_msg_received = None

    def process_ike_sa_init(message):
        """ Processes a IKE_SA_INIT message and returns a IKE_SA_INIT response
        """
        # check state
        if self.state != IkeSa.State.UNINITIALIZED:
            raise Ikev2ProtocolError('IKE SA state cannot proccess IKE_SA_INIT message')

        # set initial values


class IkeSaController:
    def __init__(self):
        self.ike_sas = {}

    def dispatch_message(self, data):
        message = Message.parse(data)
        logging.debug('Received message: {}'.format(message))

        # if IKE_SA_INIT request, create new IKE

