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

def _ip_xfrm_add_policy(src, dst, ip_proto, sport, dport, dir,
                        ipsec_proto, mode, tsrc, tdst):
    command = [
        'ip', 'xfrm', 'policy', 'add', 'src', src, 'dst', dst, 'proto', ip_proto,
        'sport', sport, 'dport', dport, 'dir', dir, 'action', 'allow', 'tmpl'
    ]
    if mode == 'tunnel':
        command += ['src', tsrc, 'dst', tdst]
    command += ['proto', ipsec_proto, 'mode', mode]

    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        outs, errs = proc.communicate(timeout=15)
    except:
        proc.kill()
        raise IpsecError('Timeout sending ip xfrm command')

    if proc.poll() != 0:
        raise IpsecError('Could not create IPsec policy: {}'.format(errs))

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

    # add outbound
    _ip_xfrm_add_policy(
        str(policy.src_selector), str(policy.dst_selector),
        _ip_proto_names[policy.ip_protocol], str(policy.src_port),
        str(policy.dst_port), 'out', _ipsec_proto_names[policy.ipsec_protocol],
        _mode_names[policy.mode], str(policy.tunnel_src), str(policy.tunnel_dst))

    # add inbound
    _ip_xfrm_add_policy(
        str(policy.dst_selector), str(policy.src_selector),
        _ip_proto_names[policy.ip_protocol], str(policy.dst_port),
        str(policy.src_port), 'in', _ipsec_proto_names[policy.ipsec_protocol],
        _mode_names[policy.mode], str(policy.tunnel_dst), str(policy.tunnel_src))

def flush_policies():
    subprocess.call(['ip', 'xfrm', 'policy', 'flush'])
