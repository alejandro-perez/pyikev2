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

class IpsecError(Exception):
    pass

class Policy(object):
    """ Represents a security policy

        Policies are always defined as if src_selector was our side of the
        conversation. E.g. a HTTP server would set src_port=80 and dst_port=0
    """
    class Mode(SafeIntEnum):
        TRANSPORT = 1
        TUNNEL = 2

    def __init__(self, src_selector, src_port, dst_selector, dst_port,
            ip_proto, ipsec_proto, mode, tunnel_src=None,
            tunnel_dst=None):
        self.src_selector = ip_network(src_selector)
        self.src_port = src_port
        self.dst_selector = ip_network(dst_selector)
        self.dst_port = dst_port
        self.ip_protocol = ip_proto
        self.ipsec_protocol = ipsec_proto
        self.mode = mode
        self.tunnel_src = ip_address(tunnel_src) if tunnel_src else None
        self.tunnel_dst = ip_address(tunnel_dst) if tunnel_dst else None

    def get_tsi(self):
        return TrafficSelector(
            ts_type=TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            ip_proto=self.ip_protocol,
            start_port=self.src_port,
            end_port=65535 if self.src_port == 0 else self.src_port,
            start_addr=self.src_selector[0],
            end_addr=self.src_selector[-1]
        )

    def get_tsr(self):
        return TrafficSelector(
            ts_type=TrafficSelector.Type.TS_IPV4_ADDR_RANGE,
            ip_proto=self.ip_protocol,
            start_port=self.dst_port,
            end_port=65535 if self.dst_port == 0 else self.dst_port,
            start_addr=self.dst_selector[0],
            end_addr=self.dst_selector[-1]
        )

    def to_dict(self):
        result = OrderedDict([
            ('src_selector', '{}:{}'.format(self.src_selector, self.src_port)),
            ('dst_selector', '{}:{}'.format(self.dst_selector, self.dst_port)),
            ('ip_protocol', TrafficSelector.IpProtocol.safe_name(self.ip_protocol)),
            ('ipsec_protocol', Proposal.Protocol.safe_name(self.ipsec_protocol)),
            ('mode', Policy.Mode.safe_name(self.mode)),
        ])
        if self.mode == Policy.Mode.TUNNEL:
            result.update(OrderedDict([
                ('tunnel_src', str(self.tunnel_src)),
                ('tunnel_dst', str(self.tunnel_dst)),
            ]))
        return result

_ip_proto_names = {
    TrafficSelector.IpProtocol.TCP: 'tcp',
    TrafficSelector.IpProtocol.UDP: 'udp',
    TrafficSelector.IpProtocol.ANY: 'any',
}
_ipsec_proto_names = {
    Proposal.Protocol.ESP: 'esp',
    Proposal.Protocol.AH: 'ah',
}
_cipher_names = {
    Cipher.Id.ENCR_AES_CBC: 'aes'
}
_auth_names = {
    Integrity.Id.AUTH_HMAC_MD5_96: 'md5',
    Integrity.Id.AUTH_HMAC_SHA1_96: 'sha1'
}
_mode_names = {
    Policy.Mode.TUNNEL: 'tunnel',
    Policy.Mode.TRANSPORT: 'transport',
}

def _run_command(command):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        outs, errs = proc.communicate(timeout=1)
    except:
        proc.kill()
        raise IpsecError('Timeout sending ip xfrm command')
    if proc.poll() != 0:
        raise IpsecError(errs)


def _ip_xfrm_add_policy(src, dst, ip_proto, sport, dport, dir,
                        ipsec_proto, mode, tsrc, tdst):
    command = [
        'ip', 'xfrm', 'policy', 'add', 'src', src, 'dst', dst, 'proto', ip_proto,
        'sport', sport, 'dport', dport, 'dir', dir, 'action', 'allow', 'tmpl'
    ]
    if mode == 'tunnel':
        command += ['src', tsrc, 'dst', tdst]
    command += ['proto', ipsec_proto, 'mode', mode]
    _run_command(command)

# intentionally no support for selectors yet
# this can generate problem. Should not support narrowing.
def _ip_xfrm_add_state(src, dst, ipsec_proto, spi, enc_algo, enc_key,
                       auth_algo, auth_key, mode):
    command = [
        'ip', 'xfrm', 'state', 'add', 'src', src, 'dst', dst, 'proto',
        ipsec_proto, 'spi', spi
    ]
    if ipsec_proto == 'esp':
        command += ['enc', enc_algo, enc_key]
    command += ['auth', auth_algo, auth_key, 'mode', mode]
    _run_command(command)

def _ip_xfrm_del_state(spi):
    command = [
        'ip', 'xfrm', 'state', 'deleteall', 'spi', spi
    ]
    _run_command(command)

def create_policy(policy):
    """ Creates all the directions of a Policy object
    """
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

def create_child_sa(src, dst, ipsec_protocol, spi, enc_algorith, sk_e,
        auth_algorithm, sk_a, mode):
    _ip_xfrm_add_state(
        str(src), str(dst), _ipsec_proto_names[ipsec_protocol],
        '0x{}'.format(hexstring(spi)), _cipher_names[enc_algorith],
        '0x{}'.format(hexstring(sk_e)), _auth_names[auth_algorithm],
        '0x{}'.format(hexstring(sk_a)), _mode_names[mode]
    )

def delete_child_sa(spi):
    _ip_xfrm_del_state('0x{}'.format(hexstring(spi)))

def flush_policies():
    subprocess.call(['ip', 'xfrm', 'policy', 'flush'])

def flush_ipsec_sa():
    subprocess.call(['ip', 'xfrm', 'state', 'flush'])

