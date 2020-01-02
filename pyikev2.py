#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
import argparse
import logging
import netifaces
import signal
import sys
from ipaddress import ip_address

import yaml

from configuration import Configuration
from protocol import IkeSaController

__author__ = 'Alejandro Perez <alex@um.es>'
__version__ = "0.1"

# check the available interfaces
interfaces = netifaces.interfaces()

# parses the arguments
parser = argparse.ArgumentParser(description='Opensource IKEv2 daemon written in Python.',
                                 prog='pyikev2')
parser.add_argument('--verbose', '-v', action='store_true',
                    help='Enable (much) more verbosity. WARNING: This will make your key '
                         'material to be shown in the log output!')
parser.add_argument('--interface', '-i', required=True, metavar='IFACE', choices=interfaces,
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

configuration = Configuration(ip, conf_dict)

# create IkeSaController
ike_sa_controller = IkeSaController(ip_address(ip), configuration=configuration)


def signal_handler(*unused):
    print('SIGINT received. Exiting.')
    # TODO: Close IKE_SA_CONTROLLER gracefully
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

ike_sa_controller.main_loop()
