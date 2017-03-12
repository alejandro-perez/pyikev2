#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'

import socket
import argparse
import logging
from message import Message
from protocol import IkeSaController

# parses the arguments
parser = argparse.ArgumentParser(description='Opensource IKEv2 daemon written in Python')
parser.add_argument('--verbose', '-v', action='store_true')
parser.add_argument('--listen', '-l', default='0.0.0.0',
    help='IP address where the daemon will listen from. Defaults to 0.0.0.0')
args = parser.parse_args()

# set logger
logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
    format='[%(asctime)s.%(msecs)03d] [%(levelname)-6s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')

logging.info('Start daemon')

# create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((args.listen, 500))
logging.info('Listening from {}'.format(sock.getsockname()))

# create IkeSaController
ike_sa_contorller = IkeSaController()

# do server
while True:
    data, addr = sock.recvfrom(4096)
    data = ike_sa_contorller.dispatch_message(data, addr)
    if data:
        sock.sendto(data, addr)
