from __future__ import print_function

import sys
import re

from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--metadata", required=True)
args = parser.parse_args()

forbidden_data_exports = [
    "idaman processor_t ida_export_data ph;",
    "idaman asm_t ida_export_data ash;"
]

def acceptable_line(l):
    for forbidden in forbidden_data_exports:
        if l.find(forbidden) > -1:
            return False
    return True

collected_nonnul = []

def is_arg_type_char(c):
    return c in " *" or is_arg_name_char(c)

def is_arg_name_char(c):
    return c == "_" or (c >= "a" and c <= "z") or (c >= "A" and c <= "Z")

def handle_nonnul(l):
    idx = l.find("NONNULL")
    if idx > -1 and l.find("define NONNULL") < 0:

        # Get type
        type_start, type_end = idx - 1, idx
        while type_start > 0 and is_arg_type_char(l[type_start - 1]):
            type_start -= 1
        type_str = l[type_start:type_end].strip()

        # Get identifier
        id_start = idx + 7
        while not is_arg_name_char(l[id_start]):
            id_start += 1
        id_end = id_start
        while id_end < (len(l) - 1) and is_arg_name_char(l[id_end]):
            id_end += 1
        id_str = l[id_start:id_end].strip()

        nonnul_id_str = "NONNULL_" + id_str
        l = l[0:idx] + nonnul_id_str + l[id_end:].replace(id_str, nonnul_id_str)
        collected_nonnul.append((type_str, nonnul_id_str))

    return l

def process(clob):
    lines = clob.split("\n")
    lines = list(map(handle_nonnul, lines))
    lines = list(filter(acceptable_line, lines))
    out = "\n".join(lines).encode("UTF-8")
    with open(args.output, "wb") as fout:
        fout.write(out)
    if collected_nonnul:
        with open(args.metadata, "wb") as fout:
            fout.write(str(collected_nonnul).encode("UTF-8"))
            fout.write("\n".encode("UTF-8"))

if args.input == "-":
    process(sys.stdin.read())
else:
    with open(args.input, "rb") as fin:
        raw = fin.read()
    process(raw.decode("UTF-8"))
