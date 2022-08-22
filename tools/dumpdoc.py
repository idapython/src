
import re
import sys
import inspect
import types
import ast
import os
import argparse

sys.stdout.write("### dumpdoc here!\n")
for key in os.environ:
    sys.stdout.write("### %s = \"%s\"\n" % (key, os.environ[key]))

if sys.version_info[0] == 3:
    # for Python3, we always use the same pydoc module from Python3.5. this keeps the output consistent across different Python3 versions.
    import imp
    inspect = imp.load_source('inspect', os.path.join("tools", "inspect.py"))
    pydoc   = imp.load_source('pydoc',   os.path.join("tools", "pydoc.py"))

import inspect
import pydoc

import idc
output, wrappers_dir, is_64 = idc.ARGV[1], idc.ARGV[2], idc.ARGV[3] == "True"

sys.stdout.write("### Parameter \"output\"       = \"%s\"\n" % output)
sys.stdout.write("### Parameter \"wrappers_dir\" = \"%s\"\n" % wrappers_dir)
sys.stdout.write("### Parameter \"is_64\"        = \"%s\"\n" % is_64)

try:
    from cStringIO import StringIO
except:
    from io import StringIO

ignore_types = (int, float, str, bool, dict, list, tuple, bytes, types.ModuleType)
TRANSLATED_MARKER = b"\xE2\x86\x97"

if sys.version_info.major < 3:
    string_types = (str, unicode)
    ignore_types = ignore_types + (long, types.NoneType)
else:
    string_types = (str,)
    ignore_types = ignore_types + (type(None),)
    TRANSLATED_MARKER = TRANSLATED_MARKER.decode("UTF-8")

ignore_names = [
    "_IDCFUNC_CB_T",
    "call_idc_func__",
    "_BUTTONCB_T",
    "_FORMCHGCB_T",
    "__ask_form_callable",
    "__open_form_callable",
    "_notify_when_dispatcher",
    "_make_badattr_property",
    "long_type",
    "cvar",
    "__spec__",
    "SourceFileLoader",
    "__loader__",
    "_make_badattr_property",
    re.compile("_Swig.*"),
    re.compile("_swig.*"),
    "SWIG_PyInstanceMethod_New",
    "svalvec_t", # aliased with intvec_t or int64vec_t
    "uvalvec_t", # aliased with uintvec_t or uint64vec_t
    "eavec_t", # aliased with uvalvec_t
    ("ida_ida", "__getattr__"),
    ("idc", "__getattr__"),
]

def should_ignore_name(namespace_name, name):
    for ign in ignore_names:
        if isinstance(ign, tuple):
            if ign == (namespace_name, name):
                return True
        elif isinstance(ign, string_types):
            if ign == name:
                return True
        else:
            if ign.match(name):
                return True
    return False

def apply_translations(translations, input):
    lines = input.split("\n")
    out = []
    for l in lines:
        for all_frm, dst, marker in translations:
            assert(isinstance(all_frm, tuple))
            for frm in all_frm:
                idx = l.find(frm)
                if idx > -1:
                    # sys.stderr.write("SPOTTED '%s' in '%s', position %s\n" % (frm, l, idx))
                    l = l[0:idx] + dst + l[idx+len(frm):]
                    if marker:
                        l += TRANSLATED_MARKER
        # sys.stderr.write("ADDING '%s'\n" % l)
        out.append(l)
    return '\n'.join(out)

all_specific_translations = {
    "ida_hexrays.casm_t" : [
        ((
            "uintvec_t",
            "uint64vec_t"
        ), "eavec_t", True),
        ((
            "unsigned int *",
            "unsigned long long *"
        ), "unsigned-ea-like-numeric-type *", True),
        ((
            "unsigned int &",
            "unsigned long long &"
        ), "unsigned-ea-like-numeric-type &", True),
        ((
            "unsigned int const &",
            "unsigned long long const &"
        ), "unsigned-ea-like-numeric-type const &", True),
        ((
            "qvector< unsigned int >::",
            "qvector< unsigned long long >::"
        ), "qvector< unsigned-ea-like-numeric-type >::", True),
        ((
            "qvector< unsigned int > &",
            "qvector< unsigned long long > &"
        ), "qvector< unsigned-ea-like-numeric-type > &", True),
    ],
    "ida_hexrays.ivl_t" : [
        ((
            ") -> 'unsigned int'",
            ") -> 'unsigned long long'", # py3
        ), ") -> 'unsigned-ea-like-numeric-type'", True),
        ((
            ") -> unsigned int",
            ") -> unsigned long long", # py3
        ), ") -> unsigned-ea-like-numeric-type", True),
    ],
    "ida_hexrays.uval_ivl_t" : [
        ((
            ") -> 'unsigned int'",
            ") -> 'unsigned long long'", # py3
        ), ") -> 'unsigned-ea-like-numeric-type'", True),
        ((
            ") -> unsigned int",
            ") -> unsigned long long", # py3
        ), ") -> unsigned-ea-like-numeric-type", True),
        ((
            "_off: unsigned int",
            "_off: unsigned long long", # py3
        ), "_off: unsigned-ea-like-numeric-type", True),
        ((
            "_size: unsigned int",
            "_size: unsigned long long", # py3
        ), "_size: unsigned-ea-like-numeric-type", True),
    ],
    "ida_hexrays.ivlset_t" : [
        ((
            "ivlset_tpl< ivl_t,unsigned int >::",
            "ivlset_tpl< ivl_t,unsigned long long >::", # py3
        ), "ivlset_tpl< ivl_t,unsigned-ea-like-numeric-type >::", True),
        ((
            "v: unsigned int",
            "v: unsigned long long"
        ), "v: unsigned-ea-like-numeric-type", True),
    ],
    "ida_hexrays.uval_ivl_ivlset_t" : [
        ((
            "ivlset_tpl< ivl_t,unsigned int >::",
            "ivlset_tpl< ivl_t,unsigned long long >::",
        ), "ivlset_tpl< ivl_t,unsigned-ea-like-numeric-type >::", True),
        ((
            "v: unsigned int",
            "v: unsigned long long"
        ), "v: unsigned-ea-like-numeric-type", True),
    ],
    "ida_segment.segment_defsr_array" : [
        ((
            "unsigned int const &",
            "unsigned long long const &",
        ), "unsigned-ea-like-numeric-type const &", True),
        ((
            "data: unsigned int (&)",
            "data: unsigned long long (&)",
        ), "data: unsigned-ea-like-numeric-type (&)", True),
    ],
    "ida_nalt.strpath_ids_array" : [
        # py3
        ((
            "unsigned int const &",
            "unsigned long long const &",
        ), "unsigned-ea-like-numeric-type const &", True),
        # py3
        ((
            "data: unsigned int (&)",
            "data: unsigned long long (&)",
        ), "data: unsigned-ea-like-numeric-type (&)", True),
    ],
    "idc.add_func" : [
        (("add_func(start, end=4294967295)",
          "add_func(start, end=4294967295L)",
          "add_func(start, end=18446744073709551615)", # py3
          "add_func(start, end=18446744073709551615L)",
        ), "add_func(start, end=BADADDR)", True),
    ],
    "idc.next_head" : [
        (("next_head(ea, maxea=4294967295)",
          "next_head(ea, maxea=4294967295L)",
          "next_head(ea, maxea=18446744073709551615)", # py3
          "next_head(ea, maxea=18446744073709551615L)",
        ), "next_head(ea, maxea=BADADDR)", True),
    ],
    "ida_xref.casevec_t" : [
        ((
            "qvector< int >",
            "qvector< long long >",
        ), "qvector< signed-ea-like-numeric-type >", True),
    ],

    # all that follows is for py3
    "ida_dbg.dbg_bin_search" : [
        ((
            "'uint32 *, qstring *'",
            "'uint64 *, qstring *'",
        ), "'unsigned-ea-like-numeric-type *, qstring *'", True),
    ],
    "ida_dbg.get_ip_val" : [
        ((
            "'uint32 *'",
            "'uint64 *'",
        ), "'unsigned-ea-like-numeric-type *'", True),
    ],
    "ida_dbg.get_sp_val" : [
        ((
            "'uint32 *'",
            "'uint64 *'",
        ), "'unsigned-ea-like-numeric-type *'", True),
    ],
    "ida_funcs.dyn_ea_array" : [
        ((
            "-> unsigned int const &",
            "-> unsigned long long const &",
        ), "-> unsigned-ea-like-numeric-type const &", True),
        ((
            "-> unsigned int *",
            "-> unsigned long long *",
        ), "-> unsigned-ea-like-numeric-type *", True),
        ((
            "_data: unsigned int *",
            "_data: unsigned long long *",
        ), "_data: unsigned-ea-like-numeric-type *", True),
        ((
            "v: unsigned int const &",
            "v: unsigned long long const &",
        ), "v: unsigned-ea-like-numeric-type const &", True),
        # Python3
        ((
            "-> 'unsigned int const &'",
            "-> 'unsigned long long const &'",
        ), "-> 'unsigned-ea-like-numeric-type const &'", True),
    ],
    "ida_idp.ph_find_op_value" : [
        ((
            "uint32",
            "uint64",
        ), "unsigned-ea-like-numeric-type", True),
    ],
    "ida_idp.ph_find_reg_value" : [
        ((
            "uint32",
            "uint64",
        ), "unsigned-ea-like-numeric-type", True),
    ],
    "ida_hexrays.user_iflags_t" : [
        ((
            "int([x]) -> integer",
        ), "int(x=0) -> integer", False),
    ],
    "ida_hexrays.eamap_t" : [
        ((
            "int([x]) -> integer",
        ), "int(x=0) -> integer", False),
        ((
            "_Keyval: unsigned int const &",
            "_Keyval: unsigned long long const &"
        ), "_Keyval: unsigned-ea-like-numeric-type const &", True),
    ],
    "ida_hexrays.user_unions_t" : [
        ((
            "_Keyval: unsigned int const &",
            "_Keyval: unsigned long long const &"
        ), "_Keyval: unsigned-ea-like-numeric-type const &", True),
    ],
    "ida_hexrays.DecompilationFailure" : [
        ((
            "Helper for pickle.",
        ), "helper for pickle", False),
    ],
    "idc.DeprecatedIDCError" : [
        ((
            "Helper for pickle.",
        ), "helper for pickle", False),
    ],
}

if is_64:
    all_specific_translations["ida_dirtree.direntry_t"] = [
        ((
            "BADIDX = 18446744073709551615L",
            "BADIDX = 18446744073709551615",
        ), "BADIDX = unsigned-ea-like-numeric-type(-1)", False),
    ]
else:
    all_specific_translations["ida_dirtree.direntry_t"] = [
        ((
            "BADIDX = 4294967295L",
            "BADIDX = 4294967295",
        ), "BADIDX = unsigned-ea-like-numeric-type(-1)", False),
    ]

def dump_namespace(namespace, namespace_name, keys, vec_info=None):
    spotted_things = []
    for thing_name in keys:
        # sys.stderr.write("THING NAME: %s\n" % thing_name)
        if should_ignore_name(namespace_name, thing_name):
            continue
        thing = getattr(namespace, thing_name)
        if isinstance(thing, ignore_types):
            continue
        if thing in spotted_things:
            continue
        specific_translations = all_specific_translations.get(
            "%s.%s" % (namespace_name, thing_name),
            None)
        if specific_translations:
            was_stdout = sys.stdout
            sys.stdout = StringIO()
            pydoc.help(thing)
            # sys.stderr.write("VALUE FOR %s.%s: %s" % (namespace_name, thing_name, sys.stdout.getvalue()))
            translated = apply_translations(specific_translations, sys.stdout.getvalue())
            # sys.stderr.write("TRANSLATED %s.%s: %s" % (namespace_name, thing_name, translated))
            sys.stdout = was_stdout
            sys.stdout.write(translated)
        else:
            pydoc.help(thing)
        spotted_things.append(thing)

class variable_collector_t(ast.NodeVisitor):
    OUTSIDE     = 0
    IN_CLASS    = 1
    IN_FUNCTION = 2

    def __init__(self, variables, module_name):
        self.variables        = variables
        self.module_name      = module_name
        self.context          = self.OUTSIDE
        self.class_name       = ""
        self.assign_last_line = -1

        super(variable_collector_t, self).__init__()

    def visit_FunctionDef(self, node):
        old_context  = self.context
        self.context = self.IN_FUNCTION
        self.generic_visit(node)
        self.context = old_context

    def visit_ClassDef(self, node):
        if self.context == self.IN_FUNCTION:
            return
        if self.context == self.IN_CLASS:
            prefix = self.class_name + "."
        else:
            prefix = ""
        self.class_name = prefix + node.name

        old_context  = self.context
        self.context = self.IN_CLASS
        self.generic_visit(node)
        self.context = old_context

    def visit_Assign(self, node):
        if self.context == self.IN_FUNCTION:
            return
        if self.context == self.IN_CLASS:
            prefix = self.class_name + "."
        else:
            prefix = ""

        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                self.assign_variable  = prefix + target.id
                self.assign_last_line = self._highest_lineno(node)

    def _highest_lineno(self, node):
        if hasattr(node, "end_lineno"):
            return node.end_lineno

        highest = node.lineno
        for child in ast.walk(node):
            if hasattr(child, "lineno") and child.lineno > highest:
                highest = child.lineno
        return highest

    def visit_Expr(self, node):
        if not isinstance(node.value, ast.Str):
            return

        if hasattr(node, "end_lineno"):
            line_before = node.lineno - 1   # in this case, lineno = start
        else:
            # hack until Python 3.8; if <3.8, lineno = end
            line_before = node.lineno - len(node.value.s.split("\n"))

        if line_before == self.assign_last_line:
            self.variables.append(
                "\nDocumentation on variable %s in module %s:\n\n%s\n" \
                % (self.assign_variable,
                   self.module_name,
                   self._cleandoc(node.value.s)))

    def _cleandoc(self, docstring):
        if docstring:
            docstring = inspect.cleandoc(docstring)

            # 4-blanks indent
            docstring = "\n".join("    " + line for line in docstring.split("\n"))

        return docstring

def collect_variables(variables, module_name, filename):
    with open(filename, "r") as f:
        tree = ast.parse(f.read())

    visitor = variable_collector_t(variables, module_name)
    visitor.visit(tree)

# By default, pydoc.help() hides members that start with "_"
# unless they start and end with "__" (with an exception for
# __doc__ and __module__)
# We want those "_" members, since there are important
# things such as tinfo_t._print in there.
orig_visiblename = pydoc.visiblename
def my_visiblename(name, all=None, obj=None):
    v = orig_visiblename(name, all=all, obj=obj)
    if not v and name.startswith("_") and name not in ["__doc__", "__module__"]:
        v = True
    return v
pydoc.visiblename = my_visiblename

def iter_modules():
    for mname in sorted(sys.modules):
        if mname.startswith("ida_") or mname == "idc":
            yield mname, sys.modules[mname]

sys.stdout.write("### Before collecting help\n")
old_stdout = sys.stdout ### debug

sys.stdout = StringIO()
for mname, module in iter_modules():
    print("Module \"%s\"s docstring:\n\"\"\"%s\"\"\"\n" % (mname, module.__doc__))
    dump_namespace(module, mname, sorted(dir(module)))

old_stdout.write("### After collecting help\n")

final = apply_translations([], sys.stdout.getvalue())

old_stdout.write("### After applying translations\n")

def module_file(module):
    name, ext = os.path.splitext(module.__file__)
    if ext == ".pyc":
        ext = ".py"
    return name + ext

old_stdout.write("### Before collecting variables\n")

variables = ["\n=== DOCUMENTATION FOR VARIABLES ===\n"]
for mname, module in iter_modules():
    collect_variables(variables, mname, module_file(module))

old_stdout.write("### After collecting variables (%d of them)\n" % len(variables))

final += "".join(variables)

with open(output, "wb") as f:
    if sys.version_info.major <= 2:
        f.write(final)
    else:
        f.write(final.encode("utf-8"))

old_stdout.write("### Wrote output (%d chars), end of script\n" % len(final))

idaapi.qexit(0)
