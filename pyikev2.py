#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'
__version__ = "0.1"

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
import yaml

# check the available interfaces
interfaces = netifaces.interfaces()

# parses the arguments
parser = argparse.ArgumentParser(
    description='Opensource IKEv2 daemon written in Python.', prog='pyikev2')
parser.add_argument('--verbose', '-v', action='store_true',
    help='Enable (much) more verbosity. WARNING: This will make your key '
    'material to be shown in the log output!')
parser.add_argument('--interface', '-i', required=True, metavar='IFACE',
    choices=interfaces,
    help='Interface where the daemon will listen from. Choices: %(choices)s')
parser.add_argument('--configuration-file', '-c', required=True, metavar='FILE',
    help='Configuration file.')
parser.add_argument('--no-indent', '-ni', action='store_true',
    help='Disables JSON indentation to provide a more compact log output.')
parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
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
logging.no_indent = args.no_indent

# create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, 500))
logging.info('Listening from {}'.format(sock.getsockname()))

# load configuration
try:
    with open(args.configuration_file, 'r') as file:
        conf_dict = yaml.load(file, yaml.Loader)
except FileNotFoundError:
    logging.error(
        'Configuration file "{}" do not exist.'.format(args.configuration_file))
    sys.exit(1)
except yaml.YAMLError as ex:
    logging.error(
        'Error in configuration file {}:\n{}'.format(args.configuration_file,
                                                    str(ex)))
    sys.exit(1)

configuration = Configuration(sock.getsockname()[0], conf_dict)

# create IkeSaController
ike_sa_controller = IkeSaController(sock.getsockname()[0],
                                    configuration=configuration)

# do server
while True:
    data, addr = sock.recvfrom(4096)
    data = ike_sa_controller.dispatch_message(data, sock.getsockname(), addr)
    if data:
        sock.sendto(data, addr)
