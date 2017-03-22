#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'

import socket
import argparse
import logging
from message import Message, PayloadID, TrafficSelector, Proposal
from protocol import IkeSaController
from ipaddress import ip_address
from configuration import Configuration
import ipsec
import json
import netifaces
import sys

# parses the arguments
parser = argparse.ArgumentParser(
    description='Opensource IKEv2 daemon written in Python.')
parser.add_argument('--verbose', '-v', action='store_true',
    help='Enable (much) more verbosity. WARNING: This will make your key '
    'material to be shown in the log output!')
parser.add_argument('--interface', '-i', required=True, metavar='IFACE',
    help='Interface where the daemon will listen from.')
parser.add_argument('--indent-spaces', '-s', type=int, default=2, metavar='N',
    help='Indent JSON log output with the provided number of spaces.'
    ' Use 0 to disable indentation.')
args = parser.parse_args()

try:
    addrs = netifaces.ifaddresses(args.interface)
    ip = addrs[netifaces.AF_INET][0]['addr']
except ValueError as ex:
    print(ex)
    sys.exit(1)
except KeyError:
    print('Interface do not have a valid IPv4 number')
    sys.exit(1)

# set logger
logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
    format='[%(asctime)s.%(msecs)03d] [%(levelname)-6s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')
logging.indent_spaces = args.indent_spaces if args.indent_spaces > 0 else None

# create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, 500))
logging.info('Listening from {}'.format(sock.getsockname()))

configuration = Configuration(
    sock.getsockname()[0],
    {
        '10.0.5.107': {
            'psk': 'testing',
            'dh': ['5'],
            'id': 'bob@openikev2',
            'protect': [
                {
                    'encr': ['aes256', 'aes128'],
                    'ipsec_proto': 'esp',
                    'ip_proto': 'tcp',
                    'mode': 'tunnel',
                }
            ]
        },
    }
)

# create IkeSaController
ike_sa_controller = IkeSaController(sock.getsockname()[0],
                                    configuration=configuration)

# do server
while True:
    data, addr = sock.recvfrom(4096)
    data = ike_sa_controller.dispatch_message(data, sock.getsockname(), addr)
    if data:
        sock.sendto(data, addr)
