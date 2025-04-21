#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Retrieve Kindle for PC user key (encrypted).
This script is only responsible for retrieving the key material,
decryption and further processing is handled by the calling script kindlekey.py.

This is a separate script so it can be called inside wine on Linux
without having to install crypto libraries and by extension
MSVC++ components inside Wine which is a major hassle.
"""

__license__ = "GPL v3"
__version__ = "3.1"


import pickle
from kindlekey_common import KeyEnvData, KeyMaterial
from utilities import SafeUnbuffered
from argv_utils import unicode_argv

try:
    RegError
except NameError:

    class RegError(Exception):
        pass


from ctypes import (
    windll,
    c_wchar_p,
    c_uint,
    POINTER,
    byref,
    create_unicode_buffer,
    Structure,
    c_void_p,
)
import getopt
import os
import sys

try:
    import winreg
except ImportError:
    import _winreg as winreg

MAX_PATH = 255
kernel32 = windll.kernel32
advapi32 = windll.advapi32
crypt32 = windll.crypt32


# interface with Windows OS Routines
class DataBlob(Structure):
    _fields_ = [("cbData", c_uint), ("pbData", c_void_p)]


DataBlob_p = POINTER(DataBlob)


def GetSystemDirectory():
    GetSystemDirectoryW = kernel32.GetSystemDirectoryW
    GetSystemDirectoryW.argtypes = [c_wchar_p, c_uint]
    GetSystemDirectoryW.restype = c_uint

    def GetSystemDirectory():
        buffer = create_unicode_buffer(MAX_PATH + 1)
        GetSystemDirectoryW(buffer, len(buffer))
        return buffer.value

    return GetSystemDirectory


GetSystemDirectory = GetSystemDirectory()


def GetVolumeSerialNumber():
    GetVolumeInformationW = kernel32.GetVolumeInformationW
    GetVolumeInformationW.argtypes = [
        c_wchar_p,
        c_wchar_p,
        c_uint,
        POINTER(c_uint),
        POINTER(c_uint),
        POINTER(c_uint),
        c_wchar_p,
        c_uint,
    ]
    GetVolumeInformationW.restype = c_uint

    def GetVolumeSerialNumber(path=GetSystemDirectory().split("\\")[0] + "\\"):
        vsn = c_uint(0)
        GetVolumeInformationW(path, None, 0, byref(vsn), None, None, None, 0)
        return str(vsn.value)

    return GetVolumeSerialNumber


GetVolumeSerialNumber = GetVolumeSerialNumber()


def GetIDString():
    vsn = GetVolumeSerialNumber()
    # print('Using Volume Serial Number for ID: '+vsn)
    return vsn


def getLastError():
    GetLastError = kernel32.GetLastError
    GetLastError.argtypes = None
    GetLastError.restype = c_uint

    def getLastError():
        return GetLastError()

    return getLastError


getLastError = getLastError()


def GetUserName():
    GetUserNameW = advapi32.GetUserNameW
    GetUserNameW.argtypes = [c_wchar_p, POINTER(c_uint)]
    GetUserNameW.restype = c_uint

    def GetUserName():
        buffer = create_unicode_buffer(2)
        size = c_uint(len(buffer))
        while not GetUserNameW(buffer, byref(size)):
            errcd = getLastError()
            if errcd == 234:
                # bad wine implementation up through wine 1.3.21
                return "AlternateUserName"
            # double the buffer size
            buffer = create_unicode_buffer(len(buffer) * 2)
            size.value = len(buffer)

        # replace any non-ASCII values with 0xfffd
        for i in range(0, len(buffer)):
            if sys.version_info[0] == 2:
                if buffer[i] > "\u007f":
                    # print "swapping char "+str(i)+" ("+buffer[i]+")"
                    buffer[i] = "\ufffd"
            else:
                if buffer[i] > "\u007f":
                    # print "swapping char "+str(i)+" ("+buffer[i]+")"
                    buffer[i] = "\ufffd"
        # return utf-8 encoding of modified username
        # print "modified username:"+buffer.value
        return buffer.value.encode("utf-8")

    return GetUserName


GetUserName = GetUserName()


# Returns Environmental Variables that contain unicode
# name must be unicode string, not byte string.
def getEnvironmentVariable(name):
    import ctypes

    n = ctypes.windll.kernel32.GetEnvironmentVariableW(name, None, 0)
    if n == 0:
        return None
    buf = ctypes.create_unicode_buffer("\0" * n)
    ctypes.windll.kernel32.GetEnvironmentVariableW(name, buf, n)
    return buf.value


# Locate all of the kindle-info style files and return as list
def getKindleInfoFiles() -> KeyMaterial:
    keymaterial = KeyMaterial()
    keymaterial.env.idstrings = [GetIDString()]
    keymaterial.env.username = GetUserName()

    # some 64 bit machines do not have the proper registry key for some reason
    # or the python interface to the 32 vs 64 bit registry is broken
    path = ""
    if "LOCALAPPDATA" in os.environ.keys():
        # Python 2.x does not return unicode env. Use Python 3.x
        if sys.version_info[0] == 2:
            path = winreg.ExpandEnvironmentStrings("%LOCALAPPDATA%")
        else:
            path = winreg.ExpandEnvironmentStrings("%LOCALAPPDATA%")
        # this is just another alternative.
        # path = getEnvironmentVariable('LOCALAPPDATA')
        if not os.path.isdir(path):
            path = ""
    else:
        # User Shell Folders show take precedent over Shell Folders if present
        try:
            # this will still break
            regkey = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\",
            )
            path = winreg.QueryValueEx(regkey, "Local AppData")[0]
            if not os.path.isdir(path):
                path = ""
                try:
                    regkey = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\",
                    )
                    path = winreg.QueryValueEx(regkey, "Local AppData")[0]
                    if not os.path.isdir(path):
                        path = ""
                except RegError:
                    pass
        except RegError:
            pass

    found = False
    if path == "":
        print("Could not find the folder in which to look for kinfoFiles.")
    else:
        # Probably not the best. To Fix (shouldn't ignore in encoding) or use utf-8
        print("searching for kinfoFiles in " + path)

        # look for (K4PC 1.25.1 and later) .kinf2018 file
        kinfopath = path + "\\Amazon\\Kindle\\storage\\.kinf2018"
        if os.path.isfile(kinfopath):
            found = True
            print("Found K4PC 1.25+ kinf2018 file: " + kinfopath)
            keymaterial.filenames.append(kinfopath)

        # look for (K4PC 1.9.0 and later) .kinf2011 file
        kinfopath = path + "\\Amazon\\Kindle\\storage\\.kinf2011"
        if os.path.isfile(kinfopath):
            found = True
            print("Found K4PC 1.9+ kinf2011 file: " + kinfopath)
            keymaterial.filenames.append(kinfopath)

        # look for (K4PC 1.6.0 and later) rainier.2.1.1.kinf file
        kinfopath = path + "\\Amazon\\Kindle\\storage\\rainier.2.1.1.kinf"
        if os.path.isfile(kinfopath):
            found = True
            print("Found K4PC 1.6-1.8 kinf file: " + kinfopath)
            keymaterial.filenames.append(kinfopath)

        # look for (K4PC 1.5.0 and later) rainier.2.1.1.kinf file
        kinfopath = path + "\\Amazon\\Kindle For PC\\storage\\rainier.2.1.1.kinf"
        if os.path.isfile(kinfopath):
            found = True
            print("Found K4PC 1.5 kinf file: " + kinfopath)
            keymaterial.filenames.append(kinfopath)

        # look for original (earlier than K4PC 1.5.0) kindle-info files
        kinfopath = (
            path
            + "\\Amazon\\Kindle For PC\\{AMAwzsaPaaZAzmZzZQzgZCAkZ3AjA_AY}\\kindle.info"
        )
        if os.path.isfile(kinfopath):
            found = True
            print("Found K4PC kindle.info file: " + kinfopath)
            keymaterial.filenames.append(kinfopath)

    if not found:
        print("No K4PC kindle.info/kinf/kinf2011 files have been found.")
    return keymaterial


def usage(progname):
    print(
        "Finds, and saves the default Adobe Adept (encrypted) encryption key material."
    )
    print(
        "Keys are saved to keymaterial.pickle in the current directory, or a specified output file."
    )
    print("Usage:")
    print("    {0:s} [-h] [<outpath>]".format(progname))


def cli_main():
    sys.stdout = SafeUnbuffered(sys.stdout)
    sys.stderr = SafeUnbuffered(sys.stderr)
    argv = unicode_argv("kindlekey_windows.py")
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

    if len(args) > 1:
        usage(progname)
        sys.exit(2)

    if len(args) == 1:
        # save to the specified file or directory
        outpath = args[0]
        if not os.path.isabs(outpath):
            outpath = os.path.abspath(outpath)
    else:
        # save to the same directory as the script
        outpath = os.path.join(os.path.dirname(argv[0]), "keymaterial.pickle")

    keymaterial = getKindleInfoFiles()

    with open(outpath, "wb") as keymaterialfile:
        pickle.dump(keymaterial, keymaterialfile)
    sys.exit(0)


if __name__ == "__main__":
    sys.exit(cli_main())
