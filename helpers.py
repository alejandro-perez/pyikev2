#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This module defines some helper functions.
"""
import codecs
from enum import Enum


def hexstring(data):
    return codecs.encode(data, 'hex').decode()


class SafeEnum(Enum):
    @classmethod
    def safe_name(cls, value):
        try:
            return cls(value).name
        except ValueError:
            return '{} (not registered)'.format(value)


class SafeIntEnum(int, SafeEnum):
    pass
