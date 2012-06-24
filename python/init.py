#!/usr/bin/env python
# -----------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler
#
# Copyright (c) The IDAPython Team <idapython@googlegroups.com>
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
# -----------------------------------------------------------------------
# init.py - Essential init routines
# -----------------------------------------------------------------------
import os
import sys
import time
import warnings
import _idaapi

# __EA64__ is set if IDA is running in 64-bit mode
__EA64__ = _idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL

# -----------------------------------------------------------------------
# Take over the standard text outputs
# -----------------------------------------------------------------------
class IDAPythonStdOut:
    """
    Dummy file-like class that receives stout and stderr
    """
    def write(self, text):
        # Swap out the unprintable characters
        text = text.decode('ascii', 'replace').encode('ascii', 'replace')
        # Print to IDA message window
        _idaapi.msg(text)

    def flush(self):
        pass

    def isatty(self):
        return False

# -----------------------------------------------------------------------
def runscript(script):
    """
    Executes a script.
    This function is present for backward compatiblity. Please use idaapi.IDAPython_ExecScript() instead

    @param script: script path

    @return: Error string or None on success
    """

    import idaapi
    return idaapi.IDAPython_ExecScript(script, globals())

# -----------------------------------------------------------------------
def print_banner():
    banner = [
      "Python %s " % sys.version,
      "IDAPython" + (" 64-bit" if __EA64__ else "") + " v%d.%d.%d %s (serial %d) (c) The IDAPython Team <idapython@googlegroups.com>" % IDAPYTHON_VERSION
    ]
    sepline = '-' * (max([len(s) for s in banner])+1)

    print(sepline)
    print("\n".join(banner))
    print(sepline)

# -----------------------------------------------------------------------

# Redirect stderr and stdout to the IDA message window
_orig_stdout = sys.stdout;
_orig_stderr = sys.stderr;
sys.stdout = sys.stderr = IDAPythonStdOut()

# Assign a default sys.argv
sys.argv = [""]

# Have to make sure Python finds our modules
sys.path.append(_idaapi.idadir("python"))

# Remove current directory from the top of the patch search
if '' in sys.path: # On non Windows, the empty path is added
    sys.path.remove('')

if os.getcwd() in sys.path:
    sys.path.remove(os.getcwd())

# ...and add it to the end if needed
if not IDAPYTHON_REMOVE_CWD_SYS_PATH:
    sys.path.append(os.getcwd())

# Import all the required modules
from idaapi import Choose, get_user_idadir, cvar, Choose2, Appcall, Form
from idc      import *
from idautils import *
import idaapi

# Load the users personal init file
userrc = os.path.join(get_user_idadir(), "idapythonrc.py")
if os.path.exists(userrc):
    idaapi.IDAPython_ExecScript(userrc, globals())

# All done, ready to rock.