#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
__author__ = 'Alejandro Perez <alex@um.es>'

import socket
from message import Message

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 500))
while True:
    data, addr = sock.recvfrom(4096)
    print("\n\nFrom {} I received {} bytes:".format(addr, len(data)))
    message = Message(data)
    print(message)
