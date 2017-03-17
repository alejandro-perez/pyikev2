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
from ipsec import Policy
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
parser.add_argument('--email-id', '-e', default='pyikev2@github.com',
    help='An email address to be used as our identity. '
    'Defaults to "pyikev2@github.com"', metavar='EMAIL')
parser.add_argument('--use-ip-id', '-ip', action='store_true',
    help='Whether to use the current IP address as our identity.'
    ' It has precedence over --email.')
parser.add_argument('--pre-shared-key', '-psk', required=True, metavar='KEY',
    help='The PSK to be used for authentication.')
parser.add_argument('--indent-spaces', '-s', type=int, default=None, metavar='N',
    help='Indent JSON log output with the provided number of spaces.')
parser.add_argument('--src-selector', '-src', required=True,
    metavar='IP/MASK:PORT', help='Source selector of protected traffic')
parser.add_argument('--dst-selector', '-dst', required=True,
    metavar='IP/MASK:PORT', help='Destination selector of protected traffic')
parser.add_argument('--proto', '-p', required=True, default='tcp',
    metavar='PROTO', help='IP protocol to be protected (tcp, udp, icmp)')
parser.add_argument('--ips-proto', '-ipp', required=True, default='esp',
    metavar='PROTO', help='IPSEC protocol to be used (esp, ah)')
parser.add_argument('--mode', '-m', required=True, default='transport',
    metavar='MODE', help='IPSEC mode to be used (tunnel, transport)')
parser.add_argument('--tunnel-src', '-ts')
parser.add_argument('--tunnel-dst', '-td')
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
logging.indent_spaces = args.indent_spaces

# create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, 500))
logging.info('Listening from {}'.format(sock.getsockname()))

# create the template identity payload
if args.use_ip_id:
    my_id = PayloadID(PayloadID.Type.ID_IPV4_ADDR,
        ip_address(sock.getsockname()[0]).packed)
else:
    my_id = PayloadID(PayloadID.Type.ID_RFC822_ADDR, args.email_id.encode())

_mode_name_to_enum = {
    'transport': Policy.Mode.TRANSPORT,
    'tunnel': Policy.Mode.TUNNEL,
}

_ip_proto_to_enum = {
    'tcp': TrafficSelector.IpProtocol.TCP,
    'udp': TrafficSelector.IpProtocol.UDP,
    'any': TrafficSelector.IpProtocol.ANY,
}

_ipsec_proto_to_enum = {
    'esp': Proposal.Protocol.ESP,
    'ah': Proposal.Protocol.AH
}

# create the policy
policy = Policy(
    args.src_selector.split(':')[0], int(args.src_selector.split(':')[1]),
    args.dst_selector.split(':')[0], int(args.dst_selector.split(':')[1]),
    _ip_proto_to_enum[args.proto], _ipsec_proto_to_enum[args.ips_proto],
    _mode_name_to_enum[args.mode], args.tunnel_src, args.tunnel_dst)

logging.debug('Creating IPsec policy: {}'.format(
    json.dumps(policy.to_dict(), indent=logging.indent_spaces)))
# create IkeSaController
ike_sa_controller = IkeSaController(
    psk=args.pre_shared_key.encode(),
    my_id=my_id,
    policies=[policy]
)

# do server
while True:
    data, addr = sock.recvfrom(4096)
    data = ike_sa_controller.dispatch_message(data, sock.getsockname(), addr)
    if data:
        sock.sendto(data, addr)
