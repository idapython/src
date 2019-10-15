
import string

from argparse import ArgumentParser
p = ArgumentParser()
p.add_argument("-i", "--input",    required=True,  dest="input",         help="Input file")
p.add_argument("-o", "--output",   required=True,  dest="output",        help="Output file")
p.add_argument("-I", "--includes", required=True)
args = p.parse_args()

with open(args.input) as fin:
    with open(args.output, "w") as fout:
        template = string.Template(fin.read())
        kvps = {
            "INCLUDES" : " ".join(args.includes.split(",")),
            }
        fout.write(template.safe_substitute(kvps))
