#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'

import socket
from message import Message
from protocol import IkeSaController

import logging

# set logger
logging.basicConfig(level=logging.INFO,
    format='[%(asctime)s.%(msecs)03d] [%(levelname)-6s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')

logging.info('Start daemon')

# create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 500))

# create IkeSaController
ike_sa_contorller = IkeSaController()

# do server
while True:
    data, addr = sock.recvfrom(4096)
    data = ike_sa_contorller.dispatch_message(data, addr)
    if data:
        sock.sendto(data, addr)
