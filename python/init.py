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

# Prepare sys.path so loading of the shared objects works
lib_dynload = os.path.join(
    sys.executable,
    IDAPYTHON_DYNLOAD_BASE,
    "python", "lib", "python2.7", "lib-dynload")

is_x64 = sys.maxint >= 0x100000000L
if is_x64:
    # x64 python requires our lib_dynload to be added; sys.path seems
    # to be composed differently than x86 builds.
    # In addition, we always want our own lib-dynload to come first:
    # the PyQt (& sip) modules that might have to be loaded, should
    # be the ones shipped with IDA and not those possibly available
    # on the system.
    sys.path.insert(0, os.path.join(lib_dynload, IDAPYTHON_DYNLOAD_RELPATH))
    sys.path.insert(0, lib_dynload)
else:
    # for non-x64 platforms, make sure everything works as it used to,
    # by appending our own lib-dynload to sys.argv..
    sys.path.append(os.path.join(lib_dynload, IDAPYTHON_DYNLOAD_RELPATH))

try:
    import ida_idaapi
    import ida_kernwin
    import ida_diskio
except ImportError as e:
    print "Import failed: %s. Current sys.path:" % str(e)
    for p in sys.path:
        print "\t%s" % p
    raise

# __EA64__ is set if IDA is running in 64-bit mode
__EA64__ = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL

# -----------------------------------------------------------------------
# Take over the standard text outputs
# -----------------------------------------------------------------------
class IDAPythonStdOut:
    """
    Dummy file-like class that receives stout and stderr
    """
    def write(self, text):
        # NB: in case 'text' is Unicode, msg() will decode it
        # and call msg() to print it
        ida_kernwin.msg(text)

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

    import ida_idaapi
    return ida_idaapi.IDAPython_ExecScript(script, globals())

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

# -----------------------------------------------------------------------
# Initialize the help, with our own stdin wrapper, that'll query the user
# -----------------------------------------------------------------------
import pydoc
class IDAPythonHelpPrompter:
    def readline(self):
        return ida_kernwin.ask_str('', 0, 'Help topic?')
help = pydoc.Helper(input = IDAPythonHelpPrompter(), output = sys.stdout)

# Assign a default sys.argv
sys.argv = [""]

# Have to make sure Python finds our modules
sys.path.append(ida_diskio.idadir("python"))

# Remove current directory from the top of the patch search
if '' in sys.path: # On non Windows, the empty path is added
    sys.path.remove('')

if os.getcwd() in sys.path:
    sys.path.remove(os.getcwd())

# ...and add it to the end if needed
if not IDAPYTHON_REMOVE_CWD_SYS_PATH:
    sys.path.append(os.getcwd())

if IDAPYTHON_COMPAT_AUTOIMPORT_MODULES:
    # Import all the required modules
    from idaapi import get_user_idadir, cvar, Appcall, Form
    if IDAPYTHON_COMPAT_695_API:
        from idaapi import Choose2
    from idc      import *
    from idautils import *
    import idaapi

# Load the users personal init file
userrc = os.path.join(ida_diskio.get_user_idadir(), "idapythonrc.py")
if os.path.exists(userrc):
    ida_idaapi.IDAPython_ExecScript(userrc, globals())

# All done, ready to rock.
