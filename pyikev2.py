#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'
__version__ = "0.1"

import socket
import argparse
import logging
from protocol import IkeSaController
from ipaddress import ip_address
from configuration import Configuration
import ipsec
import netifaces
import sys
import yaml
from select import select

# check the available interfaces
interfaces = netifaces.interfaces()

# parses the arguments
parser = argparse.ArgumentParser(
    description='Opensource IKEv2 daemon written in Python.', prog='pyikev2')
parser.add_argument(
    '--verbose', '-v', action='store_true',
    help='Enable (much) more verbosity. WARNING: This will make your key '
    'material to be shown in the log output!')
parser.add_argument(
    '--interface', '-i', required=True, metavar='IFACE', choices=interfaces,
    help='Interface where the daemon will listen from. Choices: %(choices)s')
parser.add_argument(
    '--configuration-file', '-c', required=True, metavar='FILE',
    help='Configuration file.')
parser.add_argument(
    '--no-indent', '-ni', action='store_true',
    help='Disables JSON indentation to provide a more compact log output.')
parser.add_argument(
    '--version', action='version', version='%(prog)s {}'.format(__version__))
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
logging.indent = None if args.no_indent else 2

# create network socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, 500))
logging.info('Listening from {}:{}'.format(sock.getsockname()[0],
                                           sock.getsockname()[1]))

# create XFRM socket
xfrm = ipsec.get_socket()
logging.info('Listening XFRM events.')

# load configuration
try:
    with open(args.configuration_file, 'r') as file:
        conf_dict = yaml.load(file, yaml.Loader)
except (FileNotFoundError, yaml.YAMLError) as ex:
    logging.error('Error in configuration file {}:\n{}'
                  ''.format(args.configuration_file, str(ex)))
    sys.exit(1)

configuration = Configuration(sock.getsockname()[0], conf_dict)

# create IkeSaController
ike_sa_controller = IkeSaController(ip_address(sock.getsockname()[0]),
                                    configuration=configuration)


import signal
def signal_handler(signal, frame):
        print('SIGINT received. Exiting.')
        # TODO: Close IKE_SA_CONTROLLER gracefully
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# do server
while True:
    ready_to_read, _, _ = select([sock, xfrm], [], [])
    if sock in ready_to_read:
        data, addr = sock.recvfrom(4096)
        data = ike_sa_controller.dispatch_message(data, sock.getsockname(), addr)
        if data:
            sock.sendto(data, addr)
    if xfrm in ready_to_read:
        data = xfrm.recv(4096)
        header, msg, attributes = ipsec.parse_xfrm_message(data)
        reply_data = None
        if header.type == ipsec.XFRM_MSG_ACQUIRE:
            reply_data, addr = ike_sa_controller.process_acquire(
                msg, attributes[ipsec.XFRMA_TMPL])
        elif header.type == ipsec.XFRM_MSG_EXPIRE:
            reply_data, addr = ike_sa_controller.process_expire(msg)
        if reply_data:
            sock.sendto(reply_data, addr)
