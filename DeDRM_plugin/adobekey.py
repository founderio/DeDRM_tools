#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# adobekey.pyw, version 7.4
# Copyright © 2009-2022 i♥cabbages, Apprentice Harper et al.

# Released under the terms of the GNU General Public Licence, version 3
# <http://www.gnu.org/licenses/>

# Revision history:
#   1 - Initial release, for Adobe Digital Editions 1.7
#   2 - Better algorithm for finding pLK; improved error handling
#   3 - Rename to INEPT
#   4 - Series of changes by joblack (and others?) --
#   4.1 - quick beta fix for ADE 1.7.2 (anon)
#   4.2 - added old 1.7.1 processing
#   4.3 - better key search
#   4.4 - Make it working on 64-bit Python
#   5  -  Clean up and improve 4.x changes;
#         Clean up and merge OS X support by unknown
#   5.1 - add support for using OpenSSL on Windows in place of PyCrypto
#   5.2 - added support for output of key to a particular file
#   5.3 - On Windows try PyCrypto first, OpenSSL next
#   5.4 - Modify interface to allow use of import
#   5.5 - Fix for potential problem with PyCrypto
#   5.6 - Revised to allow use in Plugins to eliminate need for duplicate code
#   5.7 - Unicode support added, renamed adobekey from ineptkey
#   5.8 - Added getkey interface for Windows DeDRM application
#   5.9 - moved unicode_argv call inside main for Windows DeDRM compatibility
#   6.0 - Work if TkInter is missing
#   7.0 - Python 3 for calibre 5
#   7.1 - Fix "failed to decrypt user key key" error (read username from registry)
#   7.2 - Fix decryption error on Python2 if there's unicode in the username
#   7.3 - Fix OpenSSL in Wine
#   7.4 - Remove OpenSSL support to only support PyCryptodome
#   7.5 - Move Windows-specific code to a separate script to call inside wine, instead of calling the whole script in wine

"""
Retrieve Adobe ADEPT user key.
"""

__license__ = 'GPL v3'
__version__ = '7.4'

import sys, os, struct, getopt
from base64 import b64decode

# @@CALIBRE_COMPAT_CODE@@


from utilities import SafeUnbuffered
from argv_utils import unicode_argv
from adobekey_common import ADEPTError

try:
    from calibre.constants import iswindows, isosx
except:
    iswindows = sys.platform.startswith('win')
    isosx = sys.platform.startswith('darwin')
use_wine = not iswindows and not isosx


if iswindows or use_wine:

    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        from Crypto.Cipher import AES

    def unpad(data, padding=16):
        if sys.version_info[0] == 2:
            pad_len = ord(data[-1])
        else:
            pad_len = data[-1]

        return data[:-pad_len]

    if use_wine:
        from adobekey_common import KeyMaterial

        def obtain_key_material(alfdir: str, wineprefix: str) -> KeyMaterial:
            scriptpath = os.path.join(alfdir, "adobekey_windows.py")

            from __init__ import PLUGIN_NAME, PLUGIN_VERSION
            from wineutils import WinePythonCLI, NoWinePython3Exception
            import pickle

            try:
                pyexec = WinePythonCLI(wineprefix)
            except NoWinePython3Exception:
                print('{0} v{1}: Unable to find python3 executable in WINEPREFIX="{2}"'.format(PLUGIN_NAME, PLUGIN_VERSION, wineprefix))
                return KeyMaterial()

            basepath, script = os.path.split(scriptpath)
            print(
                "{0} v{1}: Running {2} under Wine".format(
                    PLUGIN_NAME, PLUGIN_VERSION, scriptpath
                )
            )

            outdirpath = os.path.join(basepath, "winekeysdir")
            outpath = os.path.join(outdirpath, "keymaterial.pickle")
            if not os.path.exists(outdirpath):
                os.makedirs(outdirpath)

            try:
                pyexec.check_call([scriptpath, outpath])
            except Exception as e:
                print("{0} v{1}: Wine subprocess call error: {2}".format(PLUGIN_NAME, PLUGIN_VERSION, e.args[0]))

            try:
                with open(outpath, "rb") as keymaterialfile:
                    keymaterial: KeyMaterial = pickle.load(keymaterialfile)
            finally:
                # Make sure to always remove the keymaterial from disk
                os.remove(outpath)

            return keymaterial

    else:
        from adobekey_windows import obtain_key_material as _obtain_key_material
        def obtain_key_material(alfdir: str, wineprefix: str) -> KeyMaterial:
            return _obtain_key_material()

    def adeptkeys(alfdir: str, wineprefix: str):
        """ alfdir and wineprefix are only used when using Wine."""

        keymaterial = obtain_key_material(alfdir, wineprefix)

        if len(keymaterial.keykey) == 0:
            raise ADEPTError('Could not locate privateLicenseKey')

        keys = []
        names = []

        for key in keymaterial.keys:
            decrypted = unpad(
                AES.new(keymaterial.keykey, AES.MODE_CBC, b"\x00" * 16).decrypt(
                    b64decode(key.encrypted_private_key)
                )
            )[26:]
            keys.append(decrypted)
            names.append(key.uuid_name)

        print("Found {0:d} keys".format(len(keys)))
        return keys, names


elif isosx:
    import xml.etree.ElementTree as etree
    import subprocess

    NSMAP = {'adept': 'http://ns.adobe.com/adept',
             'enc': 'http://www.w3.org/2001/04/xmlenc#'}

    def findActivationDat():
        import warnings
        warnings.filterwarnings('ignore', category=FutureWarning)

        home = os.getenv('HOME')
        cmdline = 'find "' + home + '/Library/Application Support/Adobe/Digital Editions" -name "activation.dat"'
        cmdline = cmdline.encode(sys.getfilesystemencoding())
        p2 = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
        out1, out2 = p2.communicate()
        reslst = out1.split(b'\n')
        cnt = len(reslst)
        ActDatPath = b"activation.dat"
        for j in range(cnt):
            resline = reslst[j]
            pp = resline.find(b'activation.dat')
            if pp >= 0:
                ActDatPath = resline
                break
        if os.path.exists(ActDatPath):
            return ActDatPath
        return None

    def adeptkeys():
        # TODO: All the code to support extracting multiple activation keys
        # TODO: seems to be Windows-only currently, still needs to be added for Mac.
        actpath = findActivationDat()
        if actpath is None:
            raise ADEPTError("Could not find ADE activation.dat file.")
        tree = etree.parse(actpath)
        adept = lambda tag: '{%s}%s' % (NSMAP['adept'], tag)
        expr = '//%s/%s' % (adept('credentials'), adept('privateLicenseKey'))
        userkey = tree.findtext(expr)

        exprUUID = '//%s/%s' % (adept('credentials'), adept('user'))
        keyName = ""
        try:
            keyName = tree.findtext(exprUUID)[9:] + "_"
        except:
            pass

        try:
            exprMail = '//%s/%s' % (adept('credentials'), adept('username'))
            keyName = keyName + tree.find(exprMail).attrib["method"] + "_"
            keyName = keyName + tree.findtext(exprMail) + "_"
        except:
            pass

        if keyName == "":
            keyName = "Unknown"
        else:
            keyName = keyName[:-1]

        userkey = b64decode(userkey)
        userkey = userkey[26:]
        return [userkey], [keyName]

else:
    def adeptkeys():
        raise ADEPTError("This script only supports Windows (or Wine) and Mac OS X.")
        return [], []

# interface for Python DeDRM
def getkey(outpath):
    keys, names = adeptkeys()
    if len(keys) > 0:
        if not os.path.isdir(outpath):
            outfile = outpath
            with open(outfile, 'wb') as keyfileout:
                keyfileout.write(keys[0])
            print("Saved a key to {0}".format(outfile))
        else:
            keycount = 0
            name_index = 0
            for key in keys:
                while True:
                    keycount += 1
                    outfile = os.path.join(outpath,"adobekey{0:d}_uuid_{1}.der".format(keycount, names[name_index]))
                    if not os.path.exists(outfile):
                        break
                with open(outfile, 'wb') as keyfileout:
                    keyfileout.write(key)
                print("Saved a key to {0}".format(outfile))
                name_index += 1
        return True
    return False

def usage(progname):
    print("Finds, decrypts and saves the default Adobe Adept encryption key(s).")
    print("Keys are saved to the current directory, or a specified output directory.")
    print("If a file name is passed instead of a directory, only the first key is saved, in that file.")
    print("Usage:")
    print("    {0:s} [-h] [<outpath>]".format(progname))

def cli_main():
    sys.stdout=SafeUnbuffered(sys.stdout)
    sys.stderr=SafeUnbuffered(sys.stderr)
    argv=unicode_argv("adobekey.py")
    progname = os.path.basename(argv[0])
    print("{0} v{1}\nCopyright © 2009-2020 i♥cabbages, Apprentice Harper et al.".format(progname,__version__))

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
        outpath = os.path.dirname(argv[0])

    # make sure the outpath is the
    outpath = os.path.realpath(os.path.normpath(outpath))

    if use_wine:
        keys, names = adeptkeys(".", "")
    else:
        keys, names = adeptkeys()
    if len(keys) > 0:
        if not os.path.isdir(outpath):
            outfile = outpath
            with open(outfile, 'wb') as keyfileout:
                keyfileout.write(keys[0])
            print("Saved a key to {0}".format(outfile))
        else:
            keycount = 0
            name_index = 0
            for key in keys:
                while True:
                    keycount += 1
                    outfile = os.path.join(outpath,"adobekey{0:d}_uuid_{1}.der".format(keycount, names[name_index]))
                    if not os.path.exists(outfile):
                        break
                with open(outfile, 'wb') as keyfileout:
                    keyfileout.write(key)
                print("Saved a key to {0}".format(outfile))
                name_index += 1
    else:
        print("Could not retrieve Adobe Adept key.")
    return 0


def gui_main():
    try:
        import tkinter
        import tkinter.constants
        import tkinter.messagebox
        import traceback
    except:
        return cli_main()

    class ExceptionDialog(tkinter.Frame):
        def __init__(self, root, text):
            tkinter.Frame.__init__(self, root, border=5)
            label = tkinter.Label(self, text="Unexpected error:",
                                  anchor=tkinter.constants.W, justify=tkinter.constants.LEFT)
            label.pack(fill=tkinter.constants.X, expand=0)
            self.text = tkinter.Text(self)
            self.text.pack(fill=tkinter.constants.BOTH, expand=1)

            self.text.insert(tkinter.constants.END, text)

    argv=unicode_argv("adobekey.py")
    root = tkinter.Tk()
    root.withdraw()
    progpath, progname = os.path.split(argv[0])
    success = False
    try:
        if use_wine:
            keys, names = adeptkeys(".", "")
        else:
            keys, names = adeptkeys()
        print(keys)
        print(names)
        keycount = 0
        name_index = 0
        for key in keys:
            while True:
                keycount += 1
                outfile = os.path.join(progpath,"adobekey{0:d}_uuid_{1}.der".format(keycount, names[name_index]))
                if not os.path.exists(outfile):
                    break

            with open(outfile, 'wb') as keyfileout:
                keyfileout.write(key)
            success = True
            tkinter.messagebox.showinfo(progname, "Key successfully retrieved to {0}".format(outfile))
            name_index += 1
    except ADEPTError as e:
        tkinter.messagebox.showerror(progname, "Error: {0}".format(str(e)))
    except Exception:
        root.wm_state('normal')
        root.title(progname)
        text = traceback.format_exc()
        ExceptionDialog(root, text).pack(fill=tkinter.constants.BOTH, expand=1)
        root.mainloop()
    if not success:
        return 1
    return 0

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(cli_main())
    sys.exit(gui_main())
