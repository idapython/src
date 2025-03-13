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
from __future__ import print_function
import os
import sys
import time
import warnings
import os
import os.path

if os.name == 'nt' and \
    sys.version_info.major == 3 and \
    sys.version_info.minor >= 11:
    # Python 3.11 has a bug with DLLs directory missing from sys.path
    # so add it if it's not there
    base = sys.base_exec_prefix
    dllspath = os.path.join(base, sys.platlibdir)
    if os.path.exists(dllspath) and dllspath not in sys.path:
        i = sys.path.index(base) if base in sys.path else len(sys.path)
        sys.path.insert(i, dllspath)


if not os.path.isabs(IDAPYTHON_DYNLOAD_BASE):
    IDAPYTHON_DYNLOAD_BASE = os.path.abspath(IDAPYTHON_DYNLOAD_BASE);

# Prepare sys.path so loading of the shared objects works
lib_dynload = os.path.join(IDAPYTHON_DYNLOAD_BASE, "python")

# We always want our own lib-dynload to come first:
# the PyQt (& sip) modules that might have to be loaded, should
# be the ones shipped with IDA and not those possibly available
# on the system.
sys.path.insert(0, os.path.join(lib_dynload, "lib-dynload"))
sys.path.insert(0, lib_dynload)

# We want all ida_* modules to be available
all_mods = "${MODULES}"

for mod in all_mods.split(","):
    try:
        # Import module and make it visible at global scope
        globals()[f"ida_{mod}"] = __import__(f"ida_{mod}")
    except ImportError as e:
        print("Import failed: %s. Current sys.path:" % str(e))
        for p in sys.path:
            print("\t%s" % p)
        raise
    except Exception as e:
        print("Cannot load module ida_%s: %s" % (mod, str(e)))
        import traceback
        traceback.print_exc()
        raise
    except ModuleNotFoundError as e:
        # Silently skip modules not present in current installation
        continue

# -----------------------------------------------------------------------
# Take over the standard text outputs
# -----------------------------------------------------------------------
class IDAPythonStdOut:
    """
    Dummy file-like class that receives stdout and stderr
    """
    encoding = "UTF-8"

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
      "IDAPython" + (" 64-bit" if ida_idaapi.__EA64__ else "") + " v%d.%d.%d (c) The IDAPython Team <idapython@googlegroups.com>" % IDAPYTHON_VERSION
    ]
    sepline = '-' * (max([len(s) for s in banner])+1)

    print(sepline)
    print("\n".join(banner))
    print(sepline)

# -----------------------------------------------------------------------

# Redirect stderr and stdout to the IDA message window
if IDAPYTHON_OWNING_INTERPRETER:
  _orig_stdout = sys.stdout
  _orig_stderr = sys.stderr
  sys.stdout = sys.stderr = IDAPythonStdOut()

# -----------------------------------------------------------------------
# Initialize the help, with our own stdin wrapper, that'll query the user
# -----------------------------------------------------------------------
import pydoc
class IDAPythonHelpPrompter(object):
    def readline(self):
        return ida_kernwin.ask_str('', 0, 'Help topic?')

class IDAPythonHelp(pydoc.Helper):
    def __init__(self):
        super().__init__(input = IDAPythonHelpPrompter(), output = sys.stdout)
    def help(self, *args):
        try:
            return super().help(*args)
        except ImportError as e:
            print(e)

help = IDAPythonHelp()

# Assign a default sys.argv
if IDAPYTHON_OWNING_INTERPRETER:
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

# Additional IDAUSR-derived paths
if IDAPYTHON_IDAUSR_SYSPATH:
    idausr_python_list = ida_diskio.get_ida_subdirs("python")
    for one in idausr_python_list:
        if one not in sys.path and os.path.exists(one):
            sys.path.append(one)

if IDAPYTHON_COMPAT_AUTOIMPORT_MODULES:
    # Import all the required modules
    from idaapi import get_user_idadir, cvar, Appcall, Form
    from idc      import *
    from idautils import *
    import idaapi

# Load the users personal init file
userrc = os.path.join(ida_diskio.get_user_idadir(), "idapythonrc.py")
if os.path.exists(userrc):
    ida_idaapi.IDAPython_ExecScript(userrc, globals())

# In Python3, some modules (e.g., subprocess) will load the 'signal'
# module which, upon loading, will registers default handlers for some
# signals. In particular, for SIGINT, which we don't want to handle
# since it'll prevent us from killing IDA with Ctrl+C on a TTY.
if sys.version_info.major >= 3:
    import signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # Also, embedded Python3 will not include the 'site packages' by
    # default, which means many packages provided by the distribution
    # would not be reachable. Let's provide a way to load them.
    import site
    for sp in site.getsitepackages():
        if sp not in sys.path:
            sys.path.append(sp)


# Prepare PySide6 path, if found
def prepare_PySide6_import():
    python_name = f"python{sys.version_info[0]}.{sys.version_info[1]}"
    pyside_subdir = f"PySide6-{python_name}"
    candidate_PySide6_dist = os.path.join(IDAPYTHON_DYNLOAD_BASE, "python", pyside_subdir)
    if os.path.isdir(candidate_PySide6_dist):
        candidate_PySide6_dir = os.path.join(candidate_PySide6_dist, python_name, "site-packages")
        if os.path.isdir(candidate_PySide6_dir):
            if "linux" in sys.platform:
                import ctypes
                try:
                    # preload libraries
                    ctypes.cdll.LoadLibrary(os.path.join(candidate_PySide6_dist, "libshiboken6.abi3.so.6.8"))
                    ctypes.cdll.LoadLibrary(os.path.join(candidate_PySide6_dist, "libpyside6.abi3.so.6.8"))
                except:
                    import traceback
                    traceback.print_exc()
            sys.path.append(candidate_PySide6_dir)

if sys.version_info[:2] >= (3, 9):
    prepare_PySide6_import()

# All done, ready to rock.
