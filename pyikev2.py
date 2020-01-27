#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
import argparse
import logging
import signal
import socket
import sys
from ipaddress import ip_address

import netifaces
import yaml

from configuration import Configuration, ConfigurationError
from ikesacontroller import IkeSaController

__author__ = 'Alejandro Perez <alejandro.perez.mendez@gmail.com>'
__version__ = "0.2"

# parses the arguments
parser = argparse.ArgumentParser(description='Opensource IKEv2 daemon written in Python.',
                                 prog='pyikev2')
parser.add_argument('--verbose', '-v', action='store_true',
                    help='Enable (much) more verbosity. WARNING: This will make your key '
                         'material to be shown in the log output!')
parser.add_argument('--ip-address', '-i', metavar='IPADDR', action='append',
                    help='IP address where the daemon will listen from.')
parser.add_argument('--configuration-file', '-c', required=True, metavar='FILE',
                    help='Configuration file.')
parser.add_argument('--no-indent', '-ni', action='store_true',
                    help='Disables JSON indentation to provide a more compact log output.')
parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
args = parser.parse_args()

try:
    ip_addresses = []
    if args.ip_address:
        for ip in args.ip_address:
            ip_addresses.append(ip_address(ip))
    else:
        interfaces = [x for x in netifaces.interfaces() if not x.startswith('lo')]
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            for address in addresses.get(netifaces.AF_INET, []) + addresses.get(netifaces.AF_INET6, []):
                # avoid link local addresses
                if '%' not in address['addr']:
                    ip_addresses.append(ip_address(address['addr']))
except ValueError as ex:
    print(ex)
    sys.exit(1)

# set logger
logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.indent = None if args.no_indent else 2

# load configuration
try:
    with open(args.configuration_file, 'r') as file:
        conf_dict = yaml.load(file, yaml.Loader)
except (FileNotFoundError, yaml.YAMLError) as ex:
    logging.error('Error in configuration file {}:\n{}'.format(args.configuration_file, str(ex)))
    sys.exit(1)

try:
    configuration = Configuration(ip_addresses, conf_dict)
except ConfigurationError as ex:
    logging.error(f'Configuration error: {ex}')
    sys.exit(1)

# create IkeSaController
ike_sa_controller = IkeSaController(ip_addresses, configuration)


def signal_handler(*unused):
    print('SIGINT received. Exiting.')
    ike_sa_controller.close()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

ike_sa_controller.main_loop()
