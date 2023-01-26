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

### Windows (assume SWiG is installed in C:\swigwin-4.0.1, and IDA is in C:\Program Files\IDA8)

  python3 build.py \\
      --with-hexrays \\
      --swig-home C:/swigwin-4.0.1 \\
      --ida-install "c:/Program\ Files/IDA_8.0"


### Linux/OSX (assume SWiG is installed in /opt/swiglinux-4.0.1, and IDA is in /opt/my-ida-install)

  python3 build.py \\
      --with-hexrays \\
      --swig-home /opt/swiglinux-4.0.1 \\
      --ida-install /opt/my-ida-install
""",
                        formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("--swig-home", type=str, help="Path to the SWIG installation", default=None)
parser.add_argument("--with-hexrays", help="Build Hex-Rays decompiler bindings (requires the 'hexrays.hpp' header to be present in the SDK's include/ directory)", default=False, action="store_true")
parser.add_argument("--debug", help="Build debug version of the plugin", default=False, action="store_true")
parser.add_argument("-j", "--parallel", action="store_true", help="Build in parallel", default=False)
parser.add_argument("-v", "--verbose", help="Verbose mode", default=False, action="store_true")
parser.add_argument("-I", "--ida-install", required=True, help="IDA's installation directory", type=str)
args = parser.parse_args()

sdk_relpath = os.path.join("..", "..")
_probe = os.path.join(sdk_relpath, "include", "pro.h")
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
        env["SWIG_HOME"] = args.swig_home.replace('\\', '/')
    if args.with_hexrays:
        env["HAS_HEXRAYS"] = "1"
    if args.debug:
        env["__NT__"] = "1" # to enable PDB flags
    else:
        env["NDEBUG"] = "1"
    if args.verbose:
        argv.append("-d")
    env["IDA_INSTALL"] = args.ida_install.replace('\\', '/')
    env["SDK_BIN_PATH"] = os.path.abspath(os.path.join(sdk_relpath, "bin")).replace('\\', '/')
    for ea64 in [True, False]:
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
