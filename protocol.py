#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines the classes for the protocol handling.
"""
import json
import logging
import os
import socket
from ipaddress import ip_address, ip_network
from select import select

import xfrm
from helpers import hexstring
from ikesa import IkeSa
from message import (Message, TrafficSelector)

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'

class IkeSaController:
    def __init__(self, my_addr, configuration):
        self.ike_sas = []
        self.configuration = configuration
        self.xfrm = xfrm.Xfrm()
        self.my_addr = my_addr
        self.cookie_threshold = 0
        self.cookie_secret = os.urandom(8)
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
            if sum(1 for x in self.ike_sas if x.state < IkeSa.State.ESTABLISHED) > self.cookie_threshold:
                ike_sa.cookie_secret = self.cookie_secret
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
        reply = ike_sa.process_message(data)

        # if rekeyed, add the new IkeSa
        if ike_sa.state in (IkeSa.State.REKEYED, IkeSa.State.DEL_AFTER_REKEY_IKE_SA_REQ_SENT):
            self.ike_sas.append(ike_sa.new_ike_sa)
            logging.info('IKE SA with SPI={} created by rekey. Count={}'.format(hexstring(ike_sa.new_ike_sa.my_spi),
                                                                                len(self.ike_sas)))

        # if the IKE_SA needs to be closed
        if ike_sa.state == IkeSa.State.DELETED:
            ike_sa.delete_child_sas()
            self.ike_sas.remove(ike_sa)
            logging.info('Deleted IKE_SA with SPI={}. Count={}'.format(hexstring(ike_sa.my_spi), len(self.ike_sas)))

        return reply

    def process_acquire(self, xfrm_acquire):
        peer_addr = xfrm_acquire.id.daddr.to_ipaddr()
        logging.debug('Received acquire for {}'.format(peer_addr))

        # look for an active IKE_SA with the peer
        try:
            ike_sa = self._get_ike_sa_by_peer_addr(peer_addr)
        except StopIteration:
            my_addr = xfrm_acquire.saddr.to_ipaddr()
            ike_conf = self.configuration.get_ike_configuration(peer_addr)
            # create new IKE_SA (for now)
            ike_sa = IkeSa(is_initiator=True, peer_spi=b'\0'*8, configuration=ike_conf, my_addr=my_addr,
                           peer_addr=peer_addr)
            self.ike_sas.append(ike_sa)
            logging.info('Starting the creation of IKE SA with SPI={}. Count={}'
                         ''.format(hexstring(ike_sa.my_spi), len(self.ike_sas)))

        small_tsi = TrafficSelector.from_network(ip_network(xfrm_acquire.sel.saddr.to_ipaddr()),
                                                 xfrm_acquire.sel.sport, xfrm_acquire.sel.proto)
        small_tsr = TrafficSelector.from_network(ip_network(xfrm_acquire.sel.daddr.to_ipaddr()),
                                                 xfrm_acquire.sel.dport, xfrm_acquire.sel.proto)
        request = ike_sa.process_acquire(small_tsi, small_tsr, xfrm_acquire.policy.index >> 3)

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
            readable = select([sock, xfrm_socket], [], [], 1)[0]
            if sock in readable:
                data, addr = sock.recvfrom(4096)
                data = self.dispatch_message(data, sock.getsockname(), addr)
                if data:
                    sock.sendto(data, addr)

            if xfrm_socket in readable:
                data = xfrm_socket.recv(4096)
                header, msg, attributes = xfrm_obj.parse_message(data)
                reply_data, addr = None, None
                if header.type == xfrm.XFRM_MSG_ACQUIRE:
                    reply_data, addr = self.process_acquire(msg)
                elif header.type == xfrm.XFRM_MSG_EXPIRE:
                    reply_data, addr = self.process_expire(msg)
                if reply_data:
                    sock.sendto(reply_data, addr)

            # check retransmissions
            for ikesa in self.ike_sas:
                request_data = ikesa.check_retransmission_timer()
                if request_data:
                    sock.sendto(request_data, (str(ikesa.peer_addr), 500))
                if ikesa.state == IkeSa.State.DELETED:
                    ikesa.delete_child_sas()
                    self.ike_sas.remove(ikesa)
                    logging.info('Deleted IKE_SA {}. Count={}'.format(ikesa, len(self.ike_sas)))

            # start DPD
            for ikesa in self.ike_sas:
                request_data = ikesa.check_dead_peer_detection_timer()
                if request_data:
                    sock.sendto(request_data, (str(ikesa.peer_addr), 500))

            # start IKE_SA rekeyings
            for ikesa in self.ike_sas:
                request_data = ikesa.check_rekey_ike_sa_timer()
                if request_data:
                    sock.sendto(request_data, (str(ikesa.peer_addr), 500))

    def close(self):
        self.xfrm.flush_policies()
        self.xfrm.flush_sas()
