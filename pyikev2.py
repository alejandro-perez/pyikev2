#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'

import socket
from message import Message
from protocol import IkeSaController

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 500))

# create IkeSaController
ike_sa_contorller = IkeSaController()

# do server
while True:
    data, addr = sock.recvfrom(4096)
    print("\n\nFrom {} I received {} bytes:".format(addr, len(data)))
    ike_sa_contorller.dispatch_message(data)
