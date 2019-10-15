
from argparse import ArgumentParser
p = ArgumentParser()
p.add_argument("-i", "--input", required=True)
p.add_argument("--out-templates", required=True)
p.add_argument("--out-body", required=True)
args = p.parse_args()

templates = []
body = []

with open(args.input) as fin:
    lines = fin.readlines()

in_template=False
for line in lines:
    if not in_template:
        if line.startswith("template <"):
            in_template=True
        else:
            body.append(line)
    if in_template:
        templates.append(line)
        if line.startswith("};"):
            in_template = False

with open(args.out_templates, "w") as fout:
    fout.write("".join(templates))
with open(args.out_body, "w") as fout:
    fout.write("".join(body))
