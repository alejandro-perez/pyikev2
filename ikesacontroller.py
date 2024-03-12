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
from ikesa import IkeSa
from message import (Message, TrafficSelector)

__author__ = 'Alejandro Perez-Mendez <alejandro.perez.mendez@gmail.com>'


class IkeSaController:
    def __init__(self, my_addrs, configuration, disableXfrm, my_port):
        self.ike_sas = []
        self.configuration = configuration
        self.my_addrs = my_addrs
        self.my_port = my_port
        self.cookie_threshold = 10
        self.cookie_secret = os.urandom(8)
        # establish policies
        self.disableXfrm = disableXfrm
        if not self.disableXfrm:
            xfrm.Xfrm.flush_policies()
            xfrm.Xfrm.flush_sas()
            for ike_conf in self.configuration.ike_configurations.values():
                xfrm.Xfrm.create_policies(ike_conf)

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
        if header.exchange_type == Message.Exchange.IKE_SA_INIT and header.is_request:
            # look for matching configuration
            ike_conf = self.configuration.get_ike_configuration(ip_address(my_addr), ip_address(peer_addr))
            ike_sa = IkeSa(is_initiator=False, peer_spi=header.spi_i, configuration=ike_conf,
                           my_addr=ip_address(my_addr), peer_addr=ip_address(peer_addr), disableXfrm=self.disableXfrm)
            self.ike_sas.append(ike_sa)
            if sum(1 for x in self.ike_sas if x.state < IkeSa.State.ESTABLISHED) > self.cookie_threshold:
                ike_sa.cookie_secret = self.cookie_secret
            logging.info(f'Starting the creation of IKE SA={ike_sa}. Count={len(self.ike_sas)}')

        # else, look for the IkeSa in the dict
        else:
            my_spi = header.spi_r if header.is_initiator else header.spi_i
            try:
                ike_sa = self._get_ike_sa_by_spi(my_spi)
            except StopIteration:
                logging.warning(f'Received message for unknown SPI={my_spi.hex()}. Omitting.')
                return None

        # generate the reply (if any)
        reply = ike_sa.process_message(data)

        # if rekeyed, add the new IkeSa
        if ike_sa.state in (IkeSa.State.REKEYED, IkeSa.State.DEL_AFTER_REKEY_IKE_SA_REQ_SENT):
            self.ike_sas.append(ike_sa.new_ike_sa)
            logging.info(f'IKE SA={ike_sa.new_ike_sa} created by rekey. Count={len(self.ike_sas)}')

        # if the IKE_SA needs to be closed
        if ike_sa.state == IkeSa.State.DELETED:
            ike_sa.delete_child_sas()
            self.ike_sas.remove(ike_sa)
            logging.info(f'Deleted IKE_SA={ike_sa}. Count={len(self.ike_sas)}')

        return reply

    def process_acquire(self, xfrm_acquire, attributes):
        family = attributes[xfrm.XFRMA_TMPL].family
        peer_addr = xfrm_acquire.id.daddr.to_ipaddr(family)
        my_addr = xfrm_acquire.saddr.to_ipaddr(family)
        logging.debug('Received acquire for {}'.format(peer_addr))

        # look for an active IKE_SA with the peer
        try:
            ike_sa = self._get_ike_sa_by_peer_addr(peer_addr)
        except StopIteration:
            my_addr = xfrm_acquire.saddr.to_ipaddr(family)
            ike_conf = self.configuration.get_ike_configuration(my_addr, peer_addr)
            # create new IKE_SA (for now)
            ike_sa = IkeSa(is_initiator=True, peer_spi=b'\0'*8, configuration=ike_conf, my_addr=my_addr,
                           peer_addr=peer_addr, disableXfrm = self.disableXfrm)
            self.ike_sas.append(ike_sa)
            logging.info(f'Starting the creation of IKE SA={ike_sa}. Count={len(self.ike_sas)}')
        sel_family = xfrm_acquire.sel.family
        small_tsi = TrafficSelector.from_network(ip_network(xfrm_acquire.sel.saddr.to_ipaddr(sel_family)),
                                                 xfrm_acquire.sel.sport, xfrm_acquire.sel.proto)
        small_tsr = TrafficSelector.from_network(ip_network(xfrm_acquire.sel.daddr.to_ipaddr(sel_family)),
                                                 xfrm_acquire.sel.dport, xfrm_acquire.sel.proto)
        request = ike_sa.process_acquire(small_tsi, small_tsr, xfrm_acquire.policy.index >> 3)

        # look for ipsec configuration
        return request, ike_sa.my_addr, ike_sa.peer_addr

    def process_expire(self, xfrm_expire):
        spi = bytes(xfrm_expire.state.id.spi)
        hard = xfrm_expire.hard
        logging.debug(f'Received EXPIRE for CHILD_SA SPI={spi.hex()}. Hard={hard}')
        ike_sa = self._get_ike_sa_by_child_sa_spi(spi)
        if ike_sa:
            request = ike_sa.process_expire(spi, hard)
            return request, ike_sa.my_addr, ike_sa.peer_addr
        return None, None, None

    def main_loop(self):
        # create network sockets
        udp_sockets = {}
        port = int(self.my_port) if self.my_port is not None else 500
        for addr in self.my_addrs:
            logging.info(f'Listening from [{addr}]:{port}')
            udp_sockets[addr] = socket.socket(socket.AF_INET6 if addr.version == 6 else socket.AF_INET, socket.SOCK_DGRAM)
            udp_sockets[addr].bind((str(addr), port))

        self.control_socket = control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        control_addr = ("127.0.0.1", 9999)
        control_socket.bind(control_addr)
        control_socket.listen()
        logging.info(f'Listening control events on [{control_addr[0]}]:{control_addr[1]}')

        # create XFRM socket
        if not self.disableXfrm:
            xfrm_socket = xfrm.Xfrm.get_socket()
            logging.info('Listening XFRM events.')
        else:
            xfrm_socket = None

        allsockets = list(udp_sockets.values()) + [control_socket]
        if xfrm_socket is not None:
            allsockets.append(xfrm_socket)

        if self.disableXfrm:
            for ike_conf in self.configuration.ike_configurations.values():
                logging.info(f'Connect to {ike_conf.my_addr} -> {ike_conf.peer_addr}')
                ike_sa = IkeSa(is_initiator=True, peer_spi=b'\0'*8, configuration=ike_conf, my_addr=ike_conf.my_addr,
                               peer_addr=ike_conf.peer_addr, disableXfrm = self.disableXfrm)
                self.ike_sas.append(ike_sa)
                reply_data = ike_sa.connect()
                dst_addr = (str(ike_conf.peer_addr), 500)
                udp_sockets[ike_conf.my_addr].sendto(reply_data, dst_addr)

        # do server
        while True:
            try:
                readable = select(allsockets, [], [], 1)[0]
                for my_addr, sock in udp_sockets.items():
                    if sock in readable:
                        data, peer_addr = sock.recvfrom(4096)
                        data = self.dispatch_message(data, my_addr, peer_addr[0])
                        if data:
                            sock.sendto(data, peer_addr)

                if xfrm_socket in readable and not disableXfrm:
                    data = xfrm_socket.recv(4096)
                    header, msg, attributes = xfrm.Xfrm.parse_message(data)
                    reply_data, my_addr, peer_addr = None, None, None
                    if header.type == xfrm.XFRM_MSG_ACQUIRE:
                        reply_data, my_addr, peer_addr = self.process_acquire(msg, attributes)
                    elif header.type == xfrm.XFRM_MSG_EXPIRE:
                        reply_data, my_addr, peer_addr = self.process_expire(msg)
                    if reply_data:
                        dst_addr = (str(peer_addr), 500)
                        udp_sockets[my_addr].sendto(reply_data, dst_addr)

                if control_socket in readable:
                    conn, addr = control_socket.accept()
                    data = conn.recv(4096)
                    result = []
                    for ikesa in self.ike_sas:
                        result.append(ikesa.to_dict())
                    conn.sendall(json.dumps(result).encode())
                    conn.close()

                # check retransmissions
                for ikesa in self.ike_sas:
                    request_data = ikesa.check_retransmission_timer()
                    if request_data:
                        dst_addr = (str(ikesa.peer_addr), 500)
                        udp_sockets[ikesa.my_addr].sendto(request_data, dst_addr)
                    if ikesa.state == IkeSa.State.DELETED:
                        ikesa.delete_child_sas()
                        self.ike_sas.remove(ikesa)
                        logging.info('Deleted IKE_SA {}. Count={}'.format(ikesa, len(self.ike_sas)))

                # start DPD
                for ikesa in self.ike_sas:
                    request_data = ikesa.check_dead_peer_detection_timer()
                    if request_data:
                        dst_addr = (str(ikesa.peer_addr), 500)
                        udp_sockets[ikesa.my_addr].sendto(request_data, dst_addr)

                # start IKE_SA rekeyings
                for ikesa in self.ike_sas:
                    request_data = ikesa.check_rekey_ike_sa_timer()
                    if request_data:
                        dst_addr = (str(ikesa.peer_addr), 500)
                        udp_sockets[ikesa.my_addr].sendto(request_data, dst_addr)

            except socket.gaierror as ex:
                logging.error(f'Problem sending message: {ex}')
            except KeyError as ex:
                logging.error(f'Could not find socket with the appropriate source address: {str(ex)}')

    def close(self):
        if not self.disableXfrm:
            xfrm.Xfrm.flush_policies()
            xfrm.Xfrm.flush_sas()
        logging.info('Closing IKE_SA controller')
        self.control_socket.close()
