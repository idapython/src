from __future__ import print_function

import os
from argparse import ArgumentParser

parser = ArgumentParser(description='Patch some Python code generation, so it builds')
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-p", "--patches", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
parser.add_argument("-m", "--module", required=True)
args = parser.parse_args()

if os.path.isfile(args.patches):
    with open(args.file) as fin:
        lines = map(str.rstrip, fin.readlines())

    patches = {}
    with open(args.patches) as fin:
        patches = eval(fin.read())

    all_lines = []
    for l in lines:
        for patch_kind, patch_data in patches.iteritems():
            if patch_kind == "repl_line":
                for from_, to in patch_data:
                    if l == from_:
                        l = to
        all_lines.append(l)

    import tempfile
    temp = tempfile.NamedTemporaryFile(delete=False)
    temp.write("\n".join(all_lines))
    temp.close()

    import shutil
    shutil.move(temp.name, args.file)
