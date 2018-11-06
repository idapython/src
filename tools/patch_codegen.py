
import os
import re
import sys
import xml.etree.ElementTree as ET

try:
    from argparse import ArgumentParser
except:
    print "Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'"
    raise

parser = ArgumentParser(description='Patch some code generation, so it builds')
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-p", "--patches", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
parser.add_argument("-x", "--xml-doc-directory", required=True)
parser.add_argument("-m", "--module", required=True)
parser.add_argument("-V", "--apply-valist-patches", default=False, action="store_true")
args = parser.parse_args()

this_dir, _ = os.path.split(__file__)
sys.path.append(this_dir)
import doxygen_utils

patched_cmt = "// patched by patch_codegen.py"

# Load specific patches
patches = {}
if os.path.isfile(args.patches):
    with open(args.patches, "r") as fin:
        patches = eval(fin.read())

def add_thread_unsafe(fun_name):
    pset = patches.get(fun_name, None)
    if pset is None:
        pset = []
        patches[fun_name] = pset
    # avoid duplicates
    exists = False
    for thing in pset:
        if thing[0] == "thread_unsafe":
            exists = True
            break
    if not exists:
        pset.append(("thread_unsafe", True))

# Generate thread unsafe patches
xml_tree = doxygen_utils.load_xml_for_module(args.xml_doc_directory, args.module, or_dummy=False)
if xml_tree is not None:
    all_functions = doxygen_utils.get_toplevel_functions(xml_tree)
    for fun_node in all_functions:
        fun_name = doxygen_utils.get_single_child_element_text_contents(fun_node, "name")
        fun_defn = doxygen_utils.get_single_child_element_text_contents(fun_node, "definition")
        #print("##### %s | %s" % (fun_name, fun_defn))
        if fun_name and fun_defn and fun_defn.find("THREAD_SAFE") < 0:
            add_thread_unsafe(fun_name)
else:
    if args.module not in ["idaapi", "idc"]:
        raise Exception("Missing XML file for module '%s'" % args.module)

# Handle manually added thread unsafe patches
add_tu = patches.get("__additional_thread_unsafe__", None)
if add_tu is not None:
    del patches["__additional_thread_unsafe__"]
    for one_add_tu in add_tu:
        add_thread_unsafe(one_add_tu)

# Patch the code
wrap_regex = re.compile(r"SWIGINTERN PyObject \*_wrap_([a-zA-Z0-9_]*)\(.*")
director_method_regex = re.compile(r".*(SwigDirector_[a-zA-Z0-9_]*::[a-zA-Z0-9_]*)\(.*")
swig_clink_var_get_regex = re.compile(r"SWIGINTERN PyObject \*(Swig_var_[a-zA-Z0-9_]*_get).*")
swig_clink_var_set_regex = re.compile(r"SWIGINTERN int (Swig_var_[a-zA-Z0-9_]*_set).*")

all_lines = []
with open(args.file, "rb") as f:
    STAT_UNKNOWN = {}
    STAT_IN_FUNCTION = {}
    stat = STAT_UNKNOWN
    func_patches = []
    entered_function = False
    for line in f:
        subst = None
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
                            subst = "set_vva(%s, *%s); %s" % (dst_va, src_va, patched_cmt)
                elif patch_kind == "acquire_gil":
                    if entered_function:
                        subst = [
                            "  PYW_GIL_GET; %s" % patched_cmt,
                            line,
                        ]
                elif patch_kind == "repl_text":
                    idx = line.find(patch_data[0])
                    if idx > -1:
                        subst = line.rstrip().replace(patch_data[0], patch_data[1])
                        subst = "%s %s" % (subst, patched_cmt)
                elif patch_kind == "insert_before_text":
                    idx = line.find(patch_data[0])
                    if idx > -1:
                        subst = ["%s %s" % (patch_data[1], patched_cmt), line]
                elif patch_kind == "thread_unsafe":
                    if entered_function:
                        subst = [
                            "  if ( !__chkthr() ) return NULL; %s" % patched_cmt,
                            line,
                        ]
                elif patch_kind == "director_method_call_arity_cap":
                    method_name, args_cfoa, args_cmoa = patch_data
                    if entered_function:
                        subst = [
                            "  %s" % patched_cmt,
                            "  newref_t __method(PyObject_GetAttrString(swig_get_self(), \"%s\"));" % method_name,
                            "  ssize_t __argcnt = get_callable_arg_count(__method);",
                            "  QASSERT(0, __argcnt >= 0);",
                            line,
                        ]
                    else:
                        add_error = False
                        call_args = None
                        if line.find("result = PyObject_CallFunctionObjArgs") > -1:
                            call_args = args_cfoa
                            add_error = True
                        elif line.find("result = PyObject_CallMethodObjArgs") > -1:
                            call_args = args_cmoa
                        if call_args:
                            subst = re.sub("\(.*\);", call_args + ";", line)
                            if add_error:
                                subst = ["#error CHECK_THAT_THIS_WORKS", subst]
                else:
                    raise Exception("Unknown patch kind: %s" % patch_kind)
            entered_function = False
        if subst is not None:
            if isinstance(subst, basestring):
                subst = [subst]
            all_lines.extend(map(lambda l: "%s\n" % l, subst))
        else:
            all_lines.append(line)

tmp_file = "%s.tmp" % args.file
with open(tmp_file, "wb") as f:
    f.writelines(all_lines)
os.unlink(args.file)
os.rename(tmp_file, args.file)
