#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'

import socket
import argparse
import logging
from message import Message, PayloadID
from protocol import IkeSaController
from ipaddress import ip_address
from configuration import Configuration

# parses the arguments
parser = argparse.ArgumentParser(description='Opensource IKEv2 daemon written in Python.')
parser.add_argument('--verbose', '-v', action='store_true',
    help='Enable (much) more verbosity. WARNING: This will make your key '
    'material to be shown in the log output!')
parser.add_argument('--listen', '-l', default='0.0.0.0', metavar='IP',
    help='IP address where the daemon will listen from. Defaults to 0.0.0.0.')
parser.add_argument('--indent-json', '-i', type=int, default=None, metavar='N',
    help='Indent JSON log output with the provided number of spaces.'),
args = parser.parse_args()

# set logger
logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
    format='[%(asctime)s.%(msecs)03d] [%(levelname)-6s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')
logging.indent_json = args.indent_json


# create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((args.listen, 500))
logging.info('Listening from {}'.format(sock.getsockname()))

configuration = Configuration(sock.getsockname()[0], {
    '10.0.5.107': {
        'psk': 'testing',
        'id': 'bob@openikev2',
        'peer_id': 'alice',
        'encr': ['aes128'],
        'dh': ['5']
    }
})

# create IkeSaController
ike_sa_controller = IkeSaController(configuration=configuration)

# do server
while True:
    data, addr = sock.recvfrom(4096)
    data = ike_sa_controller.dispatch_message(data, addr)
    if data:
        sock.sendto(data, addr)
