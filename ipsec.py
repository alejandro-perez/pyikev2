#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines a simple SPI to access to IPsec features of the kernel
"""

# TODO: Implement this with the NETLINK interface rather than using ip xfrm command
import subprocess
from message import TrafficSelector, Proposal, Transform
from crypto import Cipher, Integrity
from helpers import hexstring, SafeIntEnum
from ipaddress import ip_address, ip_network
from collections import OrderedDict
from xfrm2 import (XFRM_MODE_TRANSPORT, XFRM_MODE_TUNNEL, XFRM_POLICY_IN,
                   XFRM_POLICY_OUT, XFRM_POLICY_FWD, xfrm_create_policy,
                   xfrm_create_ipsec_sa)
class IpsecError(Exception):
    pass

class Mode(SafeIntEnum):
    TRANSPORT = XFRM_MODE_TRANSPORT
    TUNNEL = XFRM_MODE_TUNNEL


def create_policies(my_addr, peer_addr, ike_conf):
    """ Creates all the IPsec policies associated to a ike_configuration
    """
    for ipsec_conf in ike_conf['protect']:
        if ipsec_conf['mode'] == Mode.TUNNEL:
            src_selector = ipsec_conf['my_subnet']
            dst_selector = ipsec_conf['peer_subnet']
        else:
            src_selector = ip_network(my_addr)
            dst_selector = ip_network(peer_addr)

        xfrm_create_policy(src_selector, dst_selector, ipsec_conf['my_port'],
                           ipsec_conf['peer_port'], ipsec_conf['ip_proto'],
                           XFRM_POLICY_OUT, ipsec_conf['ipsec_proto'],
                           ipsec_conf['mode'], my_addr, peer_addr)
        xfrm_create_policy(dst_selector, src_selector, ipsec_conf['peer_port'],
                           ipsec_conf['my_port'], ipsec_conf['ip_proto'],
                           XFRM_POLICY_IN, ipsec_conf['ipsec_proto'],
                           ipsec_conf['mode'], peer_addr, my_addr)
        xfrm_create_policy(dst_selector, src_selector, ipsec_conf['peer_port'],
                           ipsec_conf['my_port'], ipsec_conf['ip_proto'],
                           XFRM_POLICY_FWD, ipsec_conf['ipsec_proto'],
                           ipsec_conf['mode'], peer_addr, my_addr)

def create_child_sa(src, dst, src_sel, dst_sel, ipsec_protocol, spi, enc_algorith, sk_e,
        auth_algorithm, sk_a, mode):

    xfrm_create_ipsec_sa(src_sel.get_network(), dst_sel.get_network(),
                         src_sel.get_port(), dst_sel.get_port(), spi,
                         src_sel.ip_proto, ipsec_protocol, mode, src, dst,
                         enc_algorith, sk_e, auth_algorithm, sk_a)

def delete_child_sa(spi):
    _ip_xfrm_del_state('0x{}'.format(hexstring(spi)))

def flush_policies():
    subprocess.call(['ip', 'xfrm', 'policy', 'flush'])

def flush_ipsec_sa():
    subprocess.call(['ip', 'xfrm', 'state', 'flush'])

