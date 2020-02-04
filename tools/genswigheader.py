from __future__ import print_function

import sys
import os
import glob

try:
    from argparse import ArgumentParser
except:
    print("Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'")
    raise

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--modules", required=True)
parser.add_argument("-s", "--sdk", required=True)
args = parser.parse_args()

with open(args.input) as fin:
    with open(args.output, "w") as fout:
        parts = []

        def add_imports_from_dep(depname):
            DEPNAME = depname.upper()
            for dep in glob.glob(os.path.join(args.sdk, "%s.*" % depname)):
                parts.append("  #ifndef HAS_DEP_ON_INTERFACE_%s" % DEPNAME)
                parts.append("  %import \"{0}\"".format(os.path.basename(dep)))
                parts.append("  #endif")
                parts.append("")

        parts.append("#if defined(IDA_MODULE_PRO)")
        parts.append("// nothing; has to be handled in pro.i")
        parts.append("#else")
        required_headers = ["pro", "ida", "xref", "typeinf", "enum", "netnode", "range", "lines", "kernwin", "bytes", "auto", "nalt"]
        for rh in required_headers:
            add_imports_from_dep(rh)
        parts.append("#endif")

        # Can't use string.Template here, because it's a nightmare
        # to use with a file that has many '$' is it.
        template = fin.read()
        result = template.replace("${ALL_IMPORTS}", "\n".join(parts))
        fout.write(result)
