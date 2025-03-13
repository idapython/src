from __future__ import print_function

import sys
import string
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--modules", required=True)
args = parser.parse_args()

# Hack to force ida_idaapi to be loaded as first element
mods = args.modules.split(",")
mods.insert(0, mods.pop(mods.index("idaapi")))

with open(args.input) as fin:
    with open(args.output, "w") as fout:
        template = string.Template(fin.read())
        kvps = {
            "MODULES" : ",".join(mods),
            "IMPORTS" : "\n".join([(f"from ida_{mod} import *") for mod in mods ])
            }
        fout.write(template.substitute(kvps))
