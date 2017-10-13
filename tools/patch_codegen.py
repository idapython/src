
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
parser.add_argument("-V", "--apply-valist-patches", default=False, action="store_true")
args = parser.parse_args()

patched_cmt = "// patched by patch_codegen.py"

if os.path.isfile(args.patches):
    with open(args.patches, "r") as fin:
        patches = eval(fin.read())

    wrap_regex = re.compile(r"SWIGINTERN PyObject \*_wrap_([a-zA-Z0-9_]*)\(.*")
    director_method_regex = re.compile(r".*(SwigDirector_[a-zA-Z0-9_]*::[a-zA-Z0-9_]*)\(.*")
    swig_clink_var_get_regex = re.compile(r"SWIGINTERN PyObject \*(Swig_var_[a-zA-Z0-9_]*_get).*")
    swig_clink_var_set_regex = re.compile(r"SWIGINTERN int (Swig_var_[a-zA-Z0-9_]*_set).*")

    lines = []
    with open(args.file, "rb") as f:
        STAT_UNKNOWN = {}
        STAT_IN_FUNCTION = {}
        stat = STAT_UNKNOWN
        func_patches = []
        entered_function = False
        for line in f:
            m = wrap_regex.match(line)
            if not m:
                m = director_method_regex.match(line)
            if not m:
                m = swig_clink_var_get_regex.match(line)
            if not m:
                m = swig_clink_var_set_regex.match(line)
            if m:
                stat = STAT_IN_FUNCTION
                fname = m.group(1)
                entered_function = True
                func_patches = patches.get(fname, [])
            else:
                for patch_kind, patch_data in func_patches:
                    if patch_kind == "va_copy":
                        if args.apply_valist_patches:
                            dst_va, src_va = patch_data
                            target = "%s = *%s;" % (dst_va, src_va)
                            if line.strip() == target:
                                line = "set_vva(%s, *%s); %s\n" % (dst_va, src_va, patched_cmt)
                    elif patch_kind == "acquire_gil":
                        if entered_function:
                            line = "  PYW_GIL_GET; %s\n%s" % (patched_cmt, line)
                    elif patch_kind == "repl_text":
                        idx = line.find(patch_data[0])
                        if idx > -1:
                            line = line.rstrip().replace(patch_data[0], patch_data[1])
                            line = "%s %s\n" % (line, patched_cmt)
                    else:
                        raise Exception("Unknown patch kind: %s" % patch_kind)
                entered_function = False
            lines.append(line)

    tmp_file = "%s.tmp" % args.file
    with open(tmp_file, "w") as f:
        f.writelines(lines)
    os.unlink(args.file)
    os.rename(tmp_file, args.file)
