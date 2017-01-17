
import os, re

try:
  from argparse import ArgumentParser
except:
  print "Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'"
  raise

parser = ArgumentParser(description='Patch some code generation, so it builds')
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-p", "--patches", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()


if os.path.isfile(args.patches):
    with open(args.patches, "r") as fin:
        patches = eval(fin.read())

    regex = re.compile(r"SWIGINTERN PyObject \*_wrap_([a-zA-Z0-9_]*)\(.*")
    lines = []
    with open(args.file, "rb") as f:
        STAT_UNKNOWN = {}
        STAT_IN_FUNCTION = {}
        stat = STAT_UNKNOWN
        func_patches = []
        for line in f:
            m = regex.match(line)
            if m:
                stat = STAT_IN_FUNCTION
                fname = m.group(1)
                func_patches = patches.get(fname, [])
            else:
                for patch_kind, patch_data in func_patches:
                    if patch_kind == "va_copy":
                        dst_va, src_va = patch_data
                        target = "%s = *%s;" % (dst_va, src_va)
                        if line.strip() == target:
                            line = "set_vva(%s, *%s); // patched by patch_codegen.py\n" % (dst_va, src_va)
                    else:
                        raise Exception("Unknown patch kind: %s" % patch_kind)
            lines.append(line)

    tmp_file = "%s.tmp" % args.file
    with open(tmp_file, "w") as f:
        f.writelines(lines)
    os.unlink(args.file)
    os.rename(tmp_file, args.file)
