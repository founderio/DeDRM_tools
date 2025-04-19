#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Retrieve Adobe ADEPT user key material (encrypted).
This script is only responsible for retrieving the key material,
decryption and further processing is handled by the calling script adobekey.py.

This is a separate script so it can be called inside wine on Linux
without having to install crypto libraries and by extension
MSVC++ components inside Wine which is a major hassle.
"""

__license__ = "GPL v3"
__version__ = "7.5"

from adobekey_common import Key, KeyMaterial, ADEPTError
from utilities import SafeUnbuffered
from argv_utils import unicode_argv

import struct, sys, os.path, pickle, getopt

from ctypes import (
    windll,
    c_char_p,
    c_wchar_p,
    c_uint,
    POINTER,
    byref,
    create_unicode_buffer,
    create_string_buffer,
    CFUNCTYPE,
    addressof,
    string_at,
    Structure,
    c_void_p,
    cast,
    c_size_t,
    memmove,
    CDLL,
    c_int,
    c_long,
    c_ulong,
)

from ctypes.wintypes import LPVOID, DWORD, BOOL

try:
    import winreg
except ImportError:
    import _winreg as winreg


DEVICE_KEY_PATH = r"Software\Adobe\Adept\Device"
PRIVATE_LICENCE_KEY_PATH = r"Software\Adobe\Adept\Activation"

MAX_PATH = 255

kernel32 = windll.kernel32
advapi32 = windll.advapi32
crypt32 = windll.crypt32


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

    def GetVolumeSerialNumber(path):
        vsn = c_uint(0)
        GetVolumeInformationW(path, None, 0, byref(vsn), None, None, None, 0)
        return vsn.value

    return GetVolumeSerialNumber


GetVolumeSerialNumber = GetVolumeSerialNumber()


def GetUserName():
    GetUserNameW = advapi32.GetUserNameW
    GetUserNameW.argtypes = [c_wchar_p, POINTER(c_uint)]
    GetUserNameW.restype = c_uint

    def GetUserName():
        buffer = create_unicode_buffer(32)
        size = c_uint(len(buffer))
        while not GetUserNameW(buffer, byref(size)):
            buffer = create_unicode_buffer(len(buffer) * 2)
            size.value = len(buffer)
        return buffer.value.encode("utf-16-le")[::2]

    return GetUserName


GetUserName = GetUserName()


def GetUserName2():
    try:
        from winreg import OpenKey, QueryValueEx, HKEY_CURRENT_USER
    except ImportError:
        # We're on Python 2
        try:
            # The default _winreg on Python2 isn't unicode-safe.
            # Check if we have winreg_unicode, a unicode-safe alternative.
            # Without winreg_unicode, this will fail with Unicode chars in the username.
            from adobekey_winreg_unicode import (
                OpenKey,
                QueryValueEx,
                HKEY_CURRENT_USER,
            )
        except:
            from _winreg import OpenKey, QueryValueEx, HKEY_CURRENT_USER

    try:
        DEVICE_KEY_PATH = r"Software\Adobe\Adept\Device"
        regkey = OpenKey(HKEY_CURRENT_USER, DEVICE_KEY_PATH)
        userREG = QueryValueEx(regkey, "username")[0].encode("utf-16-le")[::2]
        return userREG
    except:
        return None


PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000


def VirtualAlloc():
    _VirtualAlloc = kernel32.VirtualAlloc
    _VirtualAlloc.argtypes = [LPVOID, c_size_t, DWORD, DWORD]
    _VirtualAlloc.restype = LPVOID

    def VirtualAlloc(
        addr,
        size,
        alloctype=(MEM_COMMIT | MEM_RESERVE),
        protect=PAGE_EXECUTE_READWRITE,
    ):
        return _VirtualAlloc(addr, size, alloctype, protect)

    return VirtualAlloc


VirtualAlloc = VirtualAlloc()

MEM_RELEASE = 0x8000


def VirtualFree():
    _VirtualFree = kernel32.VirtualFree
    _VirtualFree.argtypes = [LPVOID, c_size_t, DWORD]
    _VirtualFree.restype = BOOL

    def VirtualFree(addr, size=0, freetype=MEM_RELEASE):
        return _VirtualFree(addr, size, freetype)

    return VirtualFree


VirtualFree = VirtualFree()


class NativeFunction(object):
    def __init__(self, restype, argtypes, insns):
        self._buf = buf = VirtualAlloc(None, len(insns))
        memmove(buf, insns, len(insns))
        ftype = CFUNCTYPE(restype, *argtypes)
        self._native = ftype(buf)

    def __call__(self, *args):
        return self._native(*args)

    def __del__(self):
        if self._buf is not None:
            try:
                VirtualFree(self._buf)
                self._buf = None
            except TypeError:
                # Apparently this sometimes gets cleared on application exit
                # Causes a useless exception in the log, so let's just catch and ignore that.
                pass


if struct.calcsize("P") == 4:
    CPUID0_INSNS = (
        b"\x53"  # push   %ebx
        b"\x31\xc0"  # xor    %eax,%eax
        b"\x0f\xa2"  # cpuid
        b"\x8b\x44\x24\x08"  # mov    0x8(%esp),%eax
        b"\x89\x18"  # mov    %ebx,0x0(%eax)
        b"\x89\x50\x04"  # mov    %edx,0x4(%eax)
        b"\x89\x48\x08"  # mov    %ecx,0x8(%eax)
        b"\x5b"  # pop    %ebx
        b"\xc3"  # ret
    )
    CPUID1_INSNS = (
        b"\x53"  # push   %ebx
        b"\x31\xc0"  # xor    %eax,%eax
        b"\x40"  # inc    %eax
        b"\x0f\xa2"  # cpuid
        b"\x5b"  # pop    %ebx
        b"\xc3"  # ret
    )
else:
    CPUID0_INSNS = (
        b"\x49\x89\xd8"  # mov    %rbx,%r8
        b"\x49\x89\xc9"  # mov    %rcx,%r9
        b"\x48\x31\xc0"  # xor    %rax,%rax
        b"\x0f\xa2"  # cpuid
        b"\x4c\x89\xc8"  # mov    %r9,%rax
        b"\x89\x18"  # mov    %ebx,0x0(%rax)
        b"\x89\x50\x04"  # mov    %edx,0x4(%rax)
        b"\x89\x48\x08"  # mov    %ecx,0x8(%rax)
        b"\x4c\x89\xc3"  # mov    %r8,%rbx
        b"\xc3"  # retq
    )
    CPUID1_INSNS = (
        b"\x53"  # push   %rbx
        b"\x48\x31\xc0"  # xor    %rax,%rax
        b"\x48\xff\xc0"  # inc    %rax
        b"\x0f\xa2"  # cpuid
        b"\x5b"  # pop    %rbx
        b"\xc3"  # retq
    )

def cpuid0():
    _cpuid0 = NativeFunction(None, [c_char_p], CPUID0_INSNS)
    buf = create_string_buffer(12)

    def cpuid0():
        _cpuid0(buf)
        return buf.raw

    return cpuid0

cpuid0 = cpuid0()

cpuid1 = NativeFunction(c_uint, [], CPUID1_INSNS)

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

    def CryptUnprotectData(indata, entropy):
        indatab = create_string_buffer(indata)
        indata = DataBlob(len(indata), cast(indatab, c_void_p))
        entropyb = create_string_buffer(entropy)
        entropy = DataBlob(len(entropy), cast(entropyb, c_void_p))
        outdata = DataBlob()
        if not _CryptUnprotectData(
            byref(indata), None, byref(entropy), None, None, 0, byref(outdata)
        ):
            raise ADEPTError("Failed to decrypt user key key (sic)")
        return string_at(outdata.pbData, outdata.cbData)

    return CryptUnprotectData

CryptUnprotectData = CryptUnprotectData()


def obtain_key_material() -> KeyMaterial:
    root = GetSystemDirectory().split("\\")[0] + "\\"
    serial = GetVolumeSerialNumber(root)
    vendor = cpuid0()
    signature = struct.pack(">I", cpuid1())[1:]
    user = GetUserName2()
    if user is None:
        user = GetUserName()
    entropy = struct.pack(">I12s3s13s", serial, vendor, signature, user)
    cuser = winreg.HKEY_CURRENT_USER
    try:
        regkey = winreg.OpenKey(cuser, DEVICE_KEY_PATH)
        device = winreg.QueryValueEx(regkey, "key")[0]
    except (WindowsError, FileNotFoundError):
        raise ADEPTError("Adobe Digital Editions not activated")

    keymaterial = KeyMaterial()

    keymaterial.keykey = CryptUnprotectData(device, entropy)
    try:
        plkroot = winreg.OpenKey(cuser, PRIVATE_LICENCE_KEY_PATH)
    except (WindowsError, FileNotFoundError):
        raise ADEPTError("Could not locate ADE activation")

    i = -1
    while True:
        i = i + 1  # start with 0
        try:
            plkparent = winreg.OpenKey(plkroot, "%04d" % (i,))
        except:
            # No more keys
            break

        ktype = winreg.QueryValueEx(plkparent, None)[0]
        if ktype != "credentials":
            continue

        key = Key()

        name_components = []
        for j in range(0, 16):
            try:
                plkkey = winreg.OpenKey(plkparent, "%04d" % (j,))
            except (WindowsError, FileNotFoundError):
                break

            ktype = winreg.QueryValueEx(plkkey, None)[0]
            if ktype == "user":
                # Add Adobe UUID to key name
                name_components.append(winreg.QueryValueEx(plkkey, "value")[0][9:])
            if ktype == "username":
                # Add account type & email to key name, if present
                try:
                    name_components.append(winreg.QueryValueEx(plkkey, "method")[0])
                except:
                    pass
                try:
                    name_components.append(winreg.QueryValueEx(plkkey, "value")[0])
                except:
                    pass
            if ktype == "privateLicenseKey":
                key.encrypted_private_key = winreg.QueryValueEx(plkkey, "value")[0]

        if len(key.encrypted_private_key) > 0:
            if len(name_components) == 0:
                key.uuid_name = "Unknown"
            else:
                key.uuid_name = "_".join(name_components)

        keymaterial.keys.append(key)

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
    argv = unicode_argv("adobekey_windows.py")
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

    keymaterial = obtain_key_material()

    with open(outpath, "wb") as keymaterialfile:
        pickle.dump(keymaterial, keymaterialfile)
    sys.exit(0)


if __name__ == "__main__":
    sys.exit(cli_main())
