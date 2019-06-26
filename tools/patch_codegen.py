from __future__ import print_function

import os
import re
import sys
import xml.etree.ElementTree as ET

try:
    from argparse import ArgumentParser
except:
    print("Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'")
    raise

parser = ArgumentParser(description='Patch some code generation, so it builds')
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-p", "--patches", required=True)
parser.add_argument("-b", "--batch-patches", required=True)
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

class batch_patches_t:
    def __init__(self, data):
        self.data = data
    def requires_idb(self, func_name):
        req = False
        if func_name in api_function_names:
            for one in self.data.get("requires_idb", []):
                negate = one.startswith("-")
                if negate:
                    one = one[1:]
                m = re.match(one, func_name)
                if m:
                    req = not negate
        return req

batch_patches_data = {}
if os.path.isfile(args.batch_patches):
    with open(args.batch_patches, "r") as fin:
        batch_patches_data = eval(fin.read())
batch_patches = batch_patches_t(batch_patches_data)


def _add_specific(fun_name, patch_kind, patch_data):
    pset = patches.get(fun_name, None)
    if pset is None:
        pset = []
        patches[fun_name] = pset
    # avoid duplicates
    exists = False
    for thing in pset:
        if thing[0] == patch_kind:
            exists = True
            break
    if not exists:
        pset.append((patch_kind, patch_data))

def add_thread_unsafe(fun_name):
    return _add_specific(fun_name, "thread_unsafe", True)

def add_requires_idb(fun_name):
    return _add_specific(fun_name, "requires_idb", True)

api_function_names = []

# Generate thread unsafe + requires idb patches
xml_tree = doxygen_utils.load_xml_for_module(args.xml_doc_directory, args.module, or_dummy=False)
if xml_tree is not None:
    all_functions = doxygen_utils.get_toplevel_functions(xml_tree)
    for fun_node in all_functions:
        fun_name = doxygen_utils.get_single_child_element_text_contents(fun_node, "name")
        api_function_names.append(fun_name)
        fun_defn = doxygen_utils.get_single_child_element_text_contents(fun_node, "definition")
        #print("##### %s | %s" % (fun_name, fun_defn))
        if fun_name:
            if batch_patches.requires_idb(fun_name):
                pset = patches.get(fun_name, [])
                pset.append(("requires_idb", True))
                patches[fun_name] = pset
            if fun_defn \
               and fun_defn.find("THREAD_SAFE") < 0 \
               and fun_defn.find("constexpr") < 0:
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

# Handle manually added requires_idb patches
add_ridb = patches.get("__additional_requires_idb__", None)
if add_ridb is not None:
    del patches["__additional_requires_idb__"]
    for one_add_ridb in add_ridb:
        add_requires_idb(one_add_ridb)

# Patch the code
wrap_regex = re.compile(r"SWIGINTERN PyObject \*_wrap_([a-zA-Z0-9_]*)\(.*")
director_method_regex = re.compile(r".*((SwigDirector_([a-zA-Z0-9_]*))::([a-zA-Z0-9_]*))\(.*")
swig_clink_var_get_regex = re.compile(r"SWIGINTERN PyObject \*(Swig_var_[a-zA-Z0-9_]*_get).*")
swig_clink_var_set_regex = re.compile(r"SWIGINTERN int (Swig_var_[a-zA-Z0-9_]*_set).*")

all_lines = [
    "#ifdef __NT__\n",
    "#  define SWIG_NORETURN __declspec(noreturn)\n",
    "#else\n",
    "#  define SWIG_NORETURN __attribute__((noreturn))\n",
    "#endif\n",
]
with open(args.input, "rb") as f:
    STAT_UNKNOWN = {}
    STAT_IN_FUNCTION = {}
    stat = STAT_UNKNOWN
    func_patches = []
    entered_function = False
    current_function = None
    current_function_proto = None
    current_function_uses_args = False
    current_function_uses_varargs = False

    def prepend_subst(subst, to_prepend, orig_line):
        if not isinstance(to_prepend, list):
            to_prepend = [to_prepend]
        if subst is None:
            subst = to_prepend + [orig_line]
        else:
            subst = to_prepend + subst
        return subst

    def append_subst(subst, to_append, orig_line):
        if not isinstance(to_append, list):
            to_append = [to_append]
        if subst is None:
            subst = [orig_line] + to_append
        else:
            subst = subst + to_append
        return subst

    for line in f:
        if line.startswith("    static void raise"):
            all_lines.append(line.replace("static", "SWIG_NORETURN static"))
            continue

        subst = None
        m = wrap_regex.match(line)
        is_simple_wrapper = m
        if not m:
            m = director_method_regex.match(line)
            if m:
                director_method_name = m.group(1)
                swig_director_class_name = m.group(2)
                hooks_class_name = m.group(3)
                hooks_method_name = m.group(4)
        if not m:
            m = swig_clink_var_get_regex.match(line)
        if not m:
            m = swig_clink_var_set_regex.match(line)
        if m:
            stat = STAT_IN_FUNCTION
            entered_function = True
            current_function = m.group(1)
            current_function_proto = line
            current_function_uses_args = False
            current_function_uses_varargs = False
            func_patches = patches.get(current_function, [])[:]
            line = line.replace(", ...arg0)", ", ...)")
        else:
            if line.find("PyArg_UnpackTuple(args") > -1:
                current_function_uses_args = True
            elif line.find("varargs") > -1:
                current_function_uses_varargs = True
            for patch_kind, patch_data in func_patches:
                if patch_kind == "va_copy":
                    if args.apply_valist_patches:
                        dst_va, src_va = patch_data
                        target = "%s = *%s;" % (dst_va, src_va)
                        if line.strip() == target:
                            subst = "set_vva(%s, *%s); %s" % (dst_va, src_va, patched_cmt)
                elif patch_kind == "spontaneous_callback_call":
                    if line.lstrip().startswith("return "):
                        subst = prepend_subst(
                            subst,
                            "  }\n" +
                            "  catch ( Swig::DirectorException &e )\n" +
                            "  {\n" +
                            "    msg(\"Exception in %s (%%s)\\n\", e.getMessage());\n" % director_method_name +
                            "    if ( PyErr_Occurred() )\n" +
                            "      PyErr_Print();\n"
                            "  }\n",
                            line)
                    elif line.rstrip().endswith("c_result;"):
                        vtype = line.strip().split()[0]
                        init_line = "  %s c_result = %s(0);" % (vtype, vtype)
                        subst = append_subst(
                            subst,
                            "  PYW_GIL_GET; %s\n" % patched_cmt +
                            "  try {",
                            init_line)

                elif patch_kind == "repl_text":
                    idx = line.find(patch_data[0])
                    if idx > -1:
                        subst = line.rstrip().replace(patch_data[0], patch_data[1])
                        subst = "%s %s" % (subst, patched_cmt)
                elif patch_kind == "insert_before_text":
                    idx = line.find(patch_data[0])
                    if idx > -1:
                        subst = ["%s %s" % (patch_data[1], patched_cmt), line]
                elif patch_kind == "maybe_collect_director_fixed_method_set":
                    if entered_function:
                        subst = [
                            line,
                            "if ( has_fixed_method_set() ) %s" % patched_cmt,
                            "  init_director_hooks(self, %s::mappings, %s::mappings_size);" % (
                                hooks_class_name, hooks_class_name),
                        ]
                elif patch_kind == "thread_unsafe":
                    if entered_function:
                        subst = prepend_subst(subst, "  if ( !__chkthr() ) return NULL; %s" % patched_cmt, line)
                elif patch_kind == "requires_idb":
                    if entered_function:
                        subst = prepend_subst(subst, "  if ( !__chkreqidb() ) return NULL; %s" % patched_cmt, line)
                elif patch_kind == "director_method_call_arity_cap":
                    method_name, args_cfoa, args_cmoa = patch_data
                    if entered_function:
                        subst = prepend_subst(
                            subst,
                            [
                                "  %s" % patched_cmt,
                                "  newref_t __method(PyObject_GetAttrString(swig_get_self(), \"%s\"));" % method_name,
                                "  ssize_t __argcnt = get_callable_arg_count(__method);",
                                "  if ( __argcnt < 0 )",
                                "    Swig::DirectorMethodException::raise(\"Error detected when calling '%s.%s'\");" % (hooks_class_name, method_name),
                            ],
                            line)
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
        if line.rstrip() == "}":
            if stat is STAT_IN_FUNCTION:
                if current_function_proto.find("PyObject *args") > -1 \
                   and not current_function_uses_args:
                    subst = prepend_subst(subst, "  qnotused(args); %s" % patched_cmt, line)
                if current_function_proto.find("PyObject *varargs") > -1 \
                   and not current_function_uses_varargs:
                    subst = prepend_subst(subst, "  qnotused(varargs); %s" % patched_cmt, line)
            stat = STAT_UNKNOWN
            current_function = None
            current_function_uses_args = False
            current_function_proto = None

        if subst is not None:
            if isinstance(subst, basestring):
                subst = [subst]
            all_lines.extend(map(lambda l: "%s\n" % l, subst))
        else:
            all_lines.append(line)

import tempfile
temp = tempfile.NamedTemporaryFile(delete=False)
temp.writelines(all_lines)
temp.close()

import shutil
shutil.move(temp.name, args.output)
