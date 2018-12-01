#!/usr/bin/env python
#---------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler
#
# (c) The IDAPython Team <idapython@googlegroups.com>
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#---------------------------------------------------------------------
# build.py - Makefile wrapper script
#---------------------------------------------------------------------
from __future__ import print_function
import os, sys, argparse

parser = argparse.ArgumentParser(epilog="""
A very specific version of SWiG is expected in order to produce reliable
bindings. If your platform doesn't provide that version by default and you
had to build/install it yourself, you will have to specify '--swig-home'.

What follows, are example build commands

### Windows (assume SWiG is installed in C:\swigwin-2.0.12, and IDA is in C:\Program Files\IDA7)

  python build.py \\
      --with-hexrays \\
      --swig-home C:/swigwin-2.0.12 \\
      --idc "c:/Program\ Files/IDA_7.0-171130-tests/idc/idc.idc"


### Linux/OSX (assume SWiG is installed in /opt/swiglinux-2.0.12, and IDA is in /opt/my-ida-install)

  python build.py \\
      --with-hexrays \\
      --swig-home /opt/swiglinux-2.0.12 \\
      --idc /opt/my-ida-install/idc/idc.idc
""",
                        formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("--swig-home", type=str, help="Path to the SWIG installation", default=None)
parser.add_argument("--with-hexrays", help="Build Hex-Rays decompiler bindings (requires the 'hexrays.hpp' header to be present in the SDK's include/ directory)", default=False, action="store_true")
parser.add_argument("--debug", help="Build debug version of the plugin", default=False, action="store_true")
if "linux" in sys.platform:
    parser.add_argument("--python-home", help="Python home, where the 'include' directory can be found", default=None)
parser.add_argument("-j", "--parallel", action="store_true", help="Build in parallel", default=False)
parser.add_argument("-v", "--verbose", help="Verbose mode", default=False, action="store_true")
parser.add_argument("-I", "--idc", required=True, help="IDA's idc.idc file (necessary for generating 6.95 compat API layer)", type=str)
args = parser.parse_args()

_probe = os.path.join("..", "..", "include", "pro.h")
assert os.path.exists(_probe), "Could not find IDA SDK include path (looked for: \"%s\")" % _probe


def run(proc_argv, env=None):
    import subprocess
    print("Running: \"%s\", with additional environment: \"%s\"" % (" ".join(proc_argv), str(env)))
    full_env = os.environ.copy()
    full_env.update(env)
    subprocess.check_call(proc_argv, env=full_env)
    return 0

# -----------------------------------------------------------------------
def main():

    argv = ["make"]
    if args.parallel:
        argv.append("-j")
    env = {
        "OUT_OF_TREE_BUILD" : "1"
    }
    if args.swig_home:
        env["SWIG_HOME"] = args.swig_home
    if args.with_hexrays:
        env["HAS_HEXRAYS"] = "1"
    if args.debug:
        env["__NT__"] = "1" # to enable PDB flags
    else:
        env["NDEBUG"] = "1"
    try:
        if args.python_home:
            env["LINUX_PYTHON_HOME"] = args.python_home
    except:
        pass
    if args.verbose:
        argv.append("-d")
    env["IDC_BC695_IDC_SOURCE"] = args.idc
    for ea64 in [False, True]:
        if ea64:
            env["__EA64__"] = "1"
        else:
            if "__EA64__" in env:
                del env["__EA64__"]
        print("\n### Building EAsize=%d(bit) version of the plugin" % (64 if ea64 else 32))
        run(argv, env=env)

# -----------------------------------------------------------------------
if __name__ == "__main__":
    main()
