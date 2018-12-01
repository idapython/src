from __future__ import print_function

import re
import string

try:
    from argparse import ArgumentParser
except:
    print("Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'")
    raise

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-d", "--decls", required=True)
args = parser.parse_args()

with open(args.input) as fin:
    template = string.Template(fin.read())

with open(args.decls) as fin:
    raw = fin.read()
pat = re.compile(r"^#\s*define\s+(PLFM_[A-Za-z0-9_]*)\s+([0-9x]*)\s*(.*)$")
decls = []
for line in raw.split("\n"):
    m = pat.match(line)
    if m:
        proc = m.group(1)
        value = m.group(2)
        cmt = None
        rest = m.group(3)
        rest_cmt = rest.find("///<")
        if rest_cmt > -1:
            cmt = rest[rest_cmt+4:].strip()
        decls.append("{:20s} = {:8s} # {:s}".format(proc, value, cmt or "?"))
kvps = {
    "PLFM_DECLS" : "\n".join(decls)
}

with open(args.output, "wt") as fout:
    fout.write(template.substitute(kvps))

