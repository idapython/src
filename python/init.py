#!/usr/bin/env python
# -----------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler Pro
#
# Copyright (c) 2004-2010 Gergely Erdelyi <gergely.erdelyi@d-dome.net>
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
        _idaapi.msg(text.replace("%", "%%"))

    def flush(self):
        pass

    def isatty(self):
        return False

# -----------------------------------------------------------------------
def print_banner():
    banner = [
      "Python interpreter version %d.%d.%d %s (serial %d)" % sys.version_info,
      "Copyright (c) 1990-2010 Python Software Foundation - http://www.python.org/",
      "",
      "IDAPython" + (" 64-bit" if __EA64__ else "") + " version %d.%d.%d %s (serial %d)" % IDAPYTHON_VERSION,
      "Copyright (c) 2004-2010 Gergely Erdelyi - http://code.google.com/p/idapython/"
    ]
    sepline = '-' * max([len(s) for s in banner])

    print sepline
    print "\n".join(banner)
    print sepline

# -----------------------------------------------------------------------

# Redirect stderr and stdout to the IDA message window
sys.stdout = sys.stderr = IDAPythonStdOut()

# Assign a default sys.argv
sys.argv = [""]

# Have to make sure Python finds our modules
sys.path.append(_idaapi.idadir("python"))

# Import all the required modules
from idaapi import Choose, get_user_idadir, cvar, Choose2, Appcall
from idc import *
from idautils import *
import idaapi

# Load the users personal init file
userrc = get_user_idadir() + os.sep + "idapythonrc.py"
if os.path.exists(userrc):
    idaapi.IDAPython_ExecScript(userrc, globals())

# All done, ready to rock.