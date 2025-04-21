#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Common code shared between wine and native version.
"""

__license__ = "GPL v3"
__version__ = "3.2"


class KeyData:
    """Data use to transfer to/from kindley_windows_cud.py"""

    def __init__(self):
        self.encrypted: bytes = bytes()
        self.entropy: bytes = bytes()
        self.flags: int = 1
        self.plaintext: bytes = bytes()


class KeyEnvData:
    def __init__(self):
        self.username: bytes = bytes()
        self.idstrings: list[bytes] = []


class KeyMaterial:
    def __init__(self):
        self.env: KeyEnvData = KeyEnvData()
        self.filenames: list[str] = []
