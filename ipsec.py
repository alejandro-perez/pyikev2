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

class Mode(SafeIntEnum):
    TRANSPORT = 1
    TUNNEL = 2

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
    Mode.TUNNEL: 'tunnel',
    Mode.TRANSPORT: 'transport',
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
        'ip', 'xfrm', 'policy', 'add', 'src', src, 'dst', dst, 'proto', ip_proto
    ]
    if ip_proto in ('tcp', 'udp'):
        command += ['sport', sport, 'dport', dport]
    command += ['dir', dir, 'action', 'allow', 'tmpl']
    command += ['src', tsrc, 'dst', tdst]
    command += ['proto', ipsec_proto, 'mode', mode]
    _run_command(command)

def _ip_xfrm_add_state(src, dst, ipsec_proto, src_net, src_port, dst_net,
                        dst_port, ip_proto, spi, enc_algo, enc_key,
                        auth_algo, auth_key, mode):
    command = [
        'ip', 'xfrm', 'state', 'add', 'src', src, 'dst', dst, 'proto',
        ipsec_proto, 'spi', spi
    ]
    if ipsec_proto == 'esp':
        command += ['enc', enc_algo, enc_key]
    command += ['auth', auth_algo, auth_key, 'mode', mode]
    command += ['sel', 'src', str(src_net), 'dst', str(dst_net), 'proto', ip_proto]

    if ip_proto in ('tcp', 'udp'):
        command += ['sport', str(src_port), 'dport', str(dst_port)]
    _run_command(command)

def _ip_xfrm_del_state(spi):
    command = [
        'ip', 'xfrm', 'state', 'deleteall', 'spi', spi
    ]
    _run_command(command)

def create_policies(my_addr, peer_addr, ike_conf):
    """ Creates all the IPsec policies associated to a ike_configuration
    """
    for ipsec_conf in ike_conf['protect']:
        if ipsec_conf['mode'] == Mode.TUNNEL:
            src_selector = ipsec_conf['my_subnet']
            dst_selector = ipsec_conf['peer_subnet']
        else:
            src_selector = my_addr
            dst_selector = peer_addr

        # add outbound
        _ip_xfrm_add_policy(
            str(src_selector), str(dst_selector),
            _ip_proto_names[ipsec_conf['ip_proto']], str(ipsec_conf['my_port']),
            str(ipsec_conf['peer_port']), 'out', _ipsec_proto_names[ipsec_conf['ipsec_proto']],
            _mode_names[ipsec_conf['mode']], str(my_addr), str(peer_addr))

        # add inbound
        _ip_xfrm_add_policy(
            str(dst_selector), str(src_selector),
            _ip_proto_names[ipsec_conf['ip_proto']], str(ipsec_conf['peer_port']),
            str(ipsec_conf['my_port']), 'in', _ipsec_proto_names[ipsec_conf['ipsec_proto']],
            _mode_names[ipsec_conf['mode']], str(peer_addr), str(my_addr))

        # add fwd
        _ip_xfrm_add_policy(
            str(dst_selector), str(src_selector),
            _ip_proto_names[ipsec_conf['ip_proto']], str(ipsec_conf['peer_port']),
            str(ipsec_conf['my_port']), 'fwd', _ipsec_proto_names[ipsec_conf['ipsec_proto']],
            _mode_names[ipsec_conf['mode']], str(peer_addr), str(my_addr))

def create_child_sa(src, dst, src_sel, dst_sel, ipsec_protocol, spi, enc_algorith, sk_e,
        auth_algorithm, sk_a, mode):
    _ip_xfrm_add_state(
        str(src), str(dst), _ipsec_proto_names[ipsec_protocol],
        src_sel.get_network(), src_sel.get_port(), dst_sel.get_network(),
        dst_sel.get_port(), _ip_proto_names[src_sel.ip_proto],
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

