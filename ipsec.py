#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines a simple SPI to access to IPsec features of the kernel
"""

# TODO: Implement this with the NETLINK interface rather than using ip xfrm command
import subprocess
from protocol import Policy
from message import TrafficSelector, Proposal

class IpsecError(Exception):
    pass

def create_policy(policy):
    """ Creates all the directions of a Policy object
    """
    _ip_proto_names = {
        TrafficSelector.IpProtocol.TCP: 'tcp',
        TrafficSelector.IpProtocol.UDP: 'udp',
    }

    _ipsec_proto_names = {
        Proposal.Protocol.ESP: 'esp',
        Proposal.Protocol.AH: 'ah',
    }
    _mode_names = {
        Policy.Mode.TUNNEL: 'tunnel',
        Policy.Mode.TRANSPORT: 'transport',
    }

    command = ['ip', 'xfrm', 'policy', 'add',
        'src', str(policy.src_selector),
        'dst', str(policy.dst_selector),
        'proto', _ip_proto_names[policy.ip_protocol],
        'sport', str(policy.src_port),
        'dport', str(policy.dst_port),
        'dir', 'out',
        'action', 'allow',
        'tmpl'
    ]

    # if tunnel model, add src and dst
    if policy.mode == Policy.Mode.TUNNEL:
        command += [
            'src', str(policy.tunnel_src),
            'dst', str(policy.tunnel_dst),
        ]
    command += [
        'proto', _ipsec_proto_names[policy.ipsec_protocol],
        'mode', _mode_names[policy.mode],
    ]

    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        outs, errs = proc.communicate(timeout=15)
    except:
        proc.kill()
        raise IpsecError('Timeout sending ip xfrm command')

    if proc.poll() != 0:
        raise IpsecError('Could not create IPsec policy: {}'.format(errs))
