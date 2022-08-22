from __future__ import print_function

import sys
import string
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--modules", required=True)
args = parser.parse_args()

with open(args.input) as fin:
    with open(args.output, "w") as fout:
        template = string.Template(fin.read())
        kvps = {
            "MODULES" : args.modules,
            "IMPORTS" : "\n".join([("from ida_%s import *" % mod) for mod in args.modules.split(",")])
            }
        fout.write(template.substitute(kvps))
