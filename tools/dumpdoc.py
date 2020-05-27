
import re
import sys
import inspect
import types
import argparse

if sys.version_info[0] == 3:
    # for Python3, we always use the same pydoc module from Python3.5. this keeps the output consistent across different Python3 versions.
    import imp
    inspect = imp.load_source('inspect', os.path.join("tools", "inspect.py"))
    pydoc   = imp.load_source('pydoc',   os.path.join("tools", "pydoc.py"))

import inspect
import pydoc

import idc
output, wrappers_dir, is_64 = idc.ARGV[1], idc.ARGV[2], idc.ARGV[3] == "True"

try:
    from cStringIO import StringIO
except:
    from io import StringIO

ignore_types = (int, float, str, bool, dict, list, tuple, types.ModuleType)
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
    "svalvec_t", # aliased with intvec_t or longlongvec_t
    "uvalvec_t", # aliased with uintvec_t or ulonglongvec_t
    "eavec_t", # aliased with uvalvec_t
]

def should_ignore_name(name):
    for ign in ignore_names:
        if isinstance(ign, tuple):
            if ".".join(ign) == name:
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
            "ulonglongvec_t"
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
            "uval_ivl_t_off_get(self) -> unsigned int",
            "uval_ivl_t_off_get(self) -> unsigned long long",
        ), "uval_ivl_t_off_get(self) -> unsigned-ea-like-numeric-type", True),
        ((
            "uval_ivl_t_size_get(self) -> unsigned int",
            "uval_ivl_t_size_get(self) -> unsigned long long",
        ), "uval_ivl_t_size_get(self) -> unsigned-ea-like-numeric-type", True),
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
            "uval_ivl_t_off_get(self) -> unsigned int",
            "uval_ivl_t_off_get(self) -> unsigned long long",
        ), "uval_ivl_t_off_get(self) -> unsigned-ea-like-numeric-type", True),
        ((
            "uval_ivl_t_size_get(self) -> unsigned int",
            "uval_ivl_t_size_get(self) -> unsigned long long",
        ), "uval_ivl_t_size_get(self) -> unsigned-ea-like-numeric-type", True),
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
    "ida_nalt.strpath_ids_array" : [
        ((
            "strpath_ids_array_data_get(self) -> unsigned int",
            "strpath_ids_array_data_get(self) -> unsigned long long"
        ), "strpath_ids_array_data_get(self) -> unsigned-ea-like-numeric-type", True),
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

    #
    # The following is a kludge: IDA 7.5 ships with
    # release_pydoc_injections*.txt and ida_nalt.py files that have
    # a very slightly different wrapping. We want to prevent this
    # from building IDAPython under the SDK.
    #
    "ida_nalt.set_outfile_encoding_idx" : [
        ((
            "the encoding index idx can be 0 to use the IDB's default 1",
            "the encoding index idx can be 0 to use the IDB's default",
        ), "<snipped>", False ),
        ((
            "1-byte-per-unit encoding (C++: int)",
            "-byte-per-unit encoding (C++: int)",
        ), "<snipped>", False ),
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
        if should_ignore_name(thing_name):
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

sys.stdout = StringIO()
for mname in sorted(sys.modules):
    if mname.startswith("ida_") or mname == "idc":
        module = sys.modules[mname]
        dump_namespace(module, mname, sorted(dir(module)))
        epydoc_path = os.path.join(wrappers_dir, "%s.epydoc_injection" % mname)
        if os.path.isfile(epydoc_path):
            with open(epydoc_path) as epydoc_f:
                epydoc_injections = epydoc_f.read()
            epydoc_injections = epydoc_injections.strip()
            if epydoc_injections:
                print("=== %s EPYDOC INJECTIONS ===" % mname)
                print(epydoc_injections)
                print("=== %s EPYDOC INJECTIONS END ===" % mname)

final = apply_translations([], sys.stdout.getvalue())
with open(output, "wb") as f:
    if sys.version_info.major <= 2:
        f.write(final)
    else:
        f.write(final.encode("utf-8"))

idaapi.qexit(0)
