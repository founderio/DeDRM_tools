#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Wrapper to call CryptUnprotectData natively (on Windows) or via wine (on Linux).
"""

__license__ = "GPL v3"
__version__ = "3.1"

import getopt
import pickle
from kindlekey_common import KeyData
from utilities import SafeUnbuffered
from argv_utils import unicode_argv

from ctypes import (
    windll,
    c_wchar_p,
    c_uint,
    POINTER,
    byref,
    create_string_buffer,
    string_at,
    Structure,
    c_void_p,
    cast,
)
import os
import sys

crypt32 = windll.crypt32


# interface with Windows OS Routines
class DataBlob(Structure):
    _fields_ = [("cbData", c_uint), ("pbData", c_void_p)]


DataBlob_p = POINTER(DataBlob)


def CryptUnprotectData():
    _CryptUnprotectData = crypt32.CryptUnprotectData
    _CryptUnprotectData.argtypes = [
        DataBlob_p,
        c_wchar_p,
        DataBlob_p,
        c_void_p,
        c_void_p,
        c_uint,
        DataBlob_p,
    ]
    _CryptUnprotectData.restype = c_uint

    def CryptUnprotectData(indata, entropy, flags):
        indatab = create_string_buffer(indata)
        indata = DataBlob(len(indata), cast(indatab, c_void_p))
        entropyb = create_string_buffer(entropy)
        entropy = DataBlob(len(entropy), cast(entropyb, c_void_p))
        outdata = DataBlob()
        if not _CryptUnprotectData(
            byref(indata), None, byref(entropy), None, None, flags, byref(outdata)
        ):
            # raise DrmException("Failed to Unprotect Data")
            return b"failed"
        return string_at(outdata.pbData, outdata.cbData)

    return CryptUnprotectData


CryptUnprotectData = CryptUnprotectData()


def usage(progname):
    print("Unprotects the data in the given file via CryptUnprotectData.")
    print(
        "Reads the given file, decrypts the data, then writes it back to the same file."
    )
    print("Usage:")
    print("    {0:s} [-h] [<filepath>]".format(progname))


def cli_main():
    sys.stdout = SafeUnbuffered(sys.stdout)
    sys.stderr = SafeUnbuffered(sys.stderr)
    argv = unicode_argv("kindlekey_windows_cud.py")
    progname = os.path.basename(argv[0])
    print(
        "{0} v{1}\nCopyright © 2009-2020 i♥cabbages, Apprentice Harper et al.".format(
            progname, __version__
        )
    )

    try:
        opts, args = getopt.getopt(argv[1:], "h")
    except getopt.GetoptError as err:
        print("Error in options or arguments: {0}".format(err.args[0]))
        usage(progname)
        sys.exit(2)

    for o, a in opts:
        if o == "-h":
            usage(progname)
            sys.exit(0)

    if len(args) != 1:
        usage(progname)
        sys.exit(2)

    # read from and save to the specified file
    filepath = args[0]
    if not os.path.isabs(filepath):
        filepath = os.path.abspath(filepath)

    with open(filepath, "rb") as datafile:
        keydata: KeyData = pickle.load(datafile)

    keydata.plaintext = CryptUnprotectData(
        keydata.encrypted, keydata.entropy, keydata.flags
    )

    with open(filepath, "wb") as datafile:
        pickle.dump(keydata, datafile)
    sys.exit(0)


if __name__ == "__main__":
    sys.exit(cli_main())
