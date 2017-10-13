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
import os, argparse

parser = argparse.ArgumentParser(epilog="""
A very specific version of SWiG is expected in order to produce reliable
bindings. If your platform doesn't provide that version by default and you
had to build/install it yourself, you will have to specify '--swig-bin' and
'--swig-inc' arguments.

For example, this is how to build against IDA 6.9 on linux, with a SWiG 2.0.12
installation located in /opt/my-swig/:

python build.py \\
    --swig-bin /opt/my-swig/bin/swig \\
    --swig-inc /opt/my-swig/share/swig/2.0.12/python/:/opt/my-swig/share/swig/2.0.12

Notes:
 * '--swig-inc' here has 2 path components, separated by the platform's
   path separator; i.e., ':' in this case (if you were building on Windows,
   you would have to use ';'.)
 * SWiG can be tricky to deal with when specifying input paths. The path
   to the '.../2.0.12/python/' subdirectory should be placed before the
   more global '.../2.0.12/' directory.
""",
                        formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("--swig-bin", type=str, help="Path to the SWIG binary", default=None)
parser.add_argument("--swig-inc", type=str, help="Path(s) to the SWIG includes directory(ies)", default=None)
parser.add_argument("--with-hexrays", help="Build Hex-Rays decompiler bindings (requires the 'hexrays.hpp' header to be present in the SDK's include/ directory)", default=False, action="store_true")
parser.add_argument("--debug", help="Build debug version of the plugin", default=False, action="store_true")
parser.add_argument("--python-home", help="Python home, where the 'include' directory can be found (linux only)", default=None)
parser.add_argument("-j", "--parallel", action="store_true", help="Build in parallel", default=False)
parser.add_argument("-v", "--verbose", help="Verbose mode", default=False, action="store_true")
parser.add_argument("-I", "--idc", required=True, help="IDA's idc.idc file (necessary for generating 6.95 compat API layer)", type=str)
args = parser.parse_args()

_probe = os.path.join("..", "..", "include", "pro.h")
assert os.path.exists(_probe), "Could not find IDA SDK include path (looked for: \"%s\")" % _probe


def run(proc_argv, env=None):
    import subprocess
    if args.verbose:
        print "Running subprocess with argv: %s (env=%s)" % (proc_argv, env)
    subprocess.check_call(proc_argv, env=env)
    return 0

# -----------------------------------------------------------------------
def main():

    argv = ["make"]
    if args.parallel:
        argv.append("-j")
    env = os.environ.copy()
    env["OUT_OF_TREE_BUILD"] = "1"
    if args.swig_bin:
        env["SWIG"] = args.swig_bin
    if args.swig_inc:
        env["SWIGINCLUDES"] = " ".join(map(lambda p: "-I%s" % p, args.swig_inc.split(os.pathsep)))
    if args.with_hexrays:
        env["HAS_HEXRAYS"] = "1"
    if args.debug:
        env["__VC__"] = "1" # to enable PDB flags
    else:
        env["NDEBUG"] = "1"
    if args.python_home:
        env["LINUX_PYTHON_HOME"] = args.python_home
    if args.verbose:
        argv.append("-d")
    env["IDC_BC695_IDC_SOURCE"] = args.idc
    for ea64 in [False, True]:
        if ea64:
            env["__EA64__"] = "1"
        else:
            if "__EA64__" in env:
                del env["__EA64__"]
        print "\n### Building EAsize=%d(bit) version of the plugin" % (64 if ea64 else 32)
        run(argv, env=env)

# -----------------------------------------------------------------------
if __name__ == "__main__":
    main()
