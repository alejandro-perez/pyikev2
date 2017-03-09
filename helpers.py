#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines some helper functions.
"""
import codecs

def hexstring(data):
    return codecs.encode(data, 'hex').decode()
