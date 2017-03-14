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

# parses the arguments
parser = argparse.ArgumentParser(description='Opensource IKEv2 daemon written in Python')
parser.add_argument('--verbose', '-v', action='store_true',
    help='Enable (much) more verbosity. WARNING: This will make your key '
    'material to be shown in the log output!')
parser.add_argument('--listen', '-l', default='0.0.0.0',
    help='IP address where the daemon will listen from. Defaults to 0.0.0.0')
parser.add_argument('--email-id', '-e', default='pyikev2@github.com',
    help='An email address to be used as our identity. '
    'Defaults to "pyikev2@github.com"'),
parser.add_argument('--use-ip-id', '-ip', action='store_true',
    help='Whether to use the current IP address as our identity. '
    'It has precedence over --email.')
parser.add_argument('--pre-shared-key', '-psk', required=True,
    help='The PSK to be used for authentication.'),
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

# create the template identity payload
if args.use_ip_id:
    my_id = PayloadID(PayloadID.Type.ID_IPV4_ADDR,
        ip_address(sock.getsockname()[0]).packed)
else:
    my_id = PayloadID(PayloadID.Type.ID_RFC822_ADDR, args.email_id.encode())

# create IkeSaController
ike_sa_contorller = IkeSaController(psk=args.pre_shared_key.encode(), my_id=my_id)

# do server
while True:
    data, addr = sock.recvfrom(4096)
    data = ike_sa_contorller.dispatch_message(data, addr)
    if data:
        sock.sendto(data, addr)
