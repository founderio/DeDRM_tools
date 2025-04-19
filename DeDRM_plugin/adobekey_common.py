#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Common code shared between wine and native version.
"""

__license__ = "GPL v3"
__version__ = "7.5"


class ADEPTError(Exception):
    pass


class Key:
    def __init__(self):
        self.encrypted_private_key: bytes = bytes()
        self.uuid_name: str = ""


class KeyMaterial:
    def __init__(self):
        self.keykey: bytes = bytes()
        self.keys: list[Key] = []
