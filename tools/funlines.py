from __future__ import print_function

import os, sys, pickle, subprocess
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-l", "--left", required=True)
parser.add_argument("-r", "--right", required=True)
args = parser.parse_args()

with open(args.left, "rb") as forig:
    with open(args.right, "rb") as fthen:
        orig = pickle.load(forig)
        then = pickle.load(fthen)

sk_orig = sorted(orig.keys())
sk_then = sorted(then.keys())
for key in sk_orig:
    if not key in sk_then:
        print("Missing expected key: %s" % key)

for key in sk_then:
    if not key in sk_orig:
        print("Unexpected key found: %s" % key)

subprocess.check_call(["rm", "-r", "-f", "/tmp/diffs"])
subprocess.check_call(["mkdir", "/tmp/diffs"])
for key in sk_orig:
    if not key in sk_then:
        continue

    lines_orig = orig[key]
    # sanitize lines_orig
    def san(l):
        l = l.replace("raise_python_stl_bad_alloc", "__raise_ba")
        l = l.replace("raise_python_out_of_range_exception", "__raise_oor")
        l = l.replace("raise_python_stl_exception", "__raise_e")
        l = l.replace("raise_python_swig_director_exception", "__raise_de")
        l = l.replace("raise_python_unknown_exception", "__raise_u")
        return l
    lines_orig = map(san, lines_orig)

    lines_then = then[key]
    if lines_orig != lines_then:
        left_path = "/tmp/left_%s" % key
        right_path = "/tmp/right_%s" % key
        with open(left_path, "wb") as fleft:
            fleft.write("\n".join(lines_orig))
        with open(right_path, "wb") as fright:
            fright.write("\n".join(lines_then))
        patch_path = "/tmp/diffs/%s.patch" % key
        with open(patch_path, "wb") as fout:
            subprocess.call(["diff", "-u", "-w", left_path, right_path], stdout=fout)
        # Now, let's see if the patch isn't trivial/acceptable. If it is,
        # then we just delete that file
        trivial_crap = [
"""-  {
-    Py_INCREF(Py_None);
-    resultobj = Py_None;
-  }
+  resultobj = SWIG_Py_Void();""",

"""-      result = (bool)__init_hexrays_plugin(arg1);
+      result = (bool)py_init_hexrays_plugin(arg1);""",

"""-      result = (bool)__install_hexrays_callback(arg1);
+      result = (bool)py_install_hexrays_callback(arg1);""",

"""-      __add_custom_viewer_popup_item(arg1,(char const *)arg2,(char const *)arg3,arg4);
+      py_add_custom_viewer_popup_item(arg1,(char const *)arg2,(char const *)arg3,arg4);""",

        ]

        with open(patch_path, "rb") as fin:
            lines = fin.readlines()
        diff_lines = filter(lambda l: (l.startswith("-") and not l.startswith("---")) or (l.startswith("+") and not l.startswith("+++")), lines)
        diff_clob = "".join(diff_lines)
        # print "\"%s\"" % diff_clob
        if diff_clob.strip() in trivial_crap:
            # print "Removing trivial patch: %s" % patch_path
            os.remove(patch_path)
