
import sys
import inspect

import idc

ignore_python_builtin_docs = [
    int.__doc__,
    long.__doc__,
    float.__doc__,
    str.__doc__,
    bool.__doc__,
    dict.__doc__,
    list.__doc__,
    tuple.__doc__,
]

def dump_thing(f, label, thing):
    try:
        doc = thing.__doc__
        if doc and not doc in ignore_python_builtin_docs:
            doc_lines = doc.split("\n")
            doc_lines = map(lambda l: "\t%s" % l, doc_lines)
            f.write("%s:\n%s\n\n" % (label, "\n".join(doc_lines)))
    except:
        pass

def lexicographical_compare(s0, s1):
    if s0 < s1:
        return -1
    elif s0 > s1:
        return 1
    else:
        return 0

ignore_names = [
    "weakref_proxy",
    "thisown",
    ("ida_nalt", "strpath_ids_array", "data"),
    ("ida_pro", "uvalvec_t", "at"),
    ("ida_pro", "uvalvec_t", "begin"),
    ("ida_pro", "uvalvec_t", "end"),
    ("ida_pro", "uvalvec_t", "erase"),
    ("ida_pro", "uvalvec_t", "extract"),
    ("ida_pro", "uvalvec_t", "find"),
    ("ida_pro", "uvalvec_t", "insert"),
    ("ida_pro", "uvalvec_t", "push_back"),
    ("ida_xref", "casevec_t", "at"),
    ("ida_xref", "casevec_t", "begin"),
    ("ida_xref", "casevec_t", "end"),
    ("ida_xref", "casevec_t", "erase"),
    ("ida_xref", "casevec_t", "extract"),
    ("ida_xref", "casevec_t", "find"),
    ("ida_xref", "casevec_t", "grow"),
    ("ida_xref", "casevec_t", "insert"),
    ("ida_xref", "casevec_t", "push_back"),
    ("ida_funcs", "compute_func_sig"),
    ("ida_funcs", "extract_func_md"),
    ("ida_funcs", "func_md_t"),
    ("ida_funcs", "func_pat_t"),
]
def should_ignore_name(namespace_name, name):
    for ign in ignore_names:
        if isinstance(ign, tuple):
            if ".".join(ign) == ".".join((namespace_name, name)):
                return True
        elif ign == name:
            return True
    return False

def dump_namespace(f, namespace, namespace_name, keys):
    for thing_name in keys:
        if thing_name.startswith("_") and not thing_name in ["_print", "_free"]:
            continue
        if should_ignore_name(namespace_name, thing_name):
            continue
        thing = getattr(namespace, thing_name)
        if inspect.isclass(thing):
            dump_thing(f, "class %s.%s()" % (namespace_name, thing_name), thing)
            members = map(lambda t: t[0], inspect.getmembers(thing))
            dump_namespace(f, thing, "%s.%s" % (namespace_name, thing_name), members)
        elif callable(thing):
            dump_thing(f, "%s.%s()" % (namespace_name, thing_name), thing)
        elif not inspect.ismodule(thing):
            dump_thing(f, "%s.%s" % (namespace_name, thing_name), thing)

output = idc.ARGV[1]
wrappers_dir = idc.ARGV[2]
with open(output, "wb") as f:
    for mname in sorted(sys.modules):
        if mname.startswith("ida_") or mname == "idc":
            module = sys.modules[mname]
            dump_namespace(f, module, mname, sorted(dir(module)))
            epydoc_path = os.path.join(wrappers_dir, "%s.epydoc_injection" % mname)
            if os.path.isfile(epydoc_path):
                with open(epydoc_path) as epydoc_f:
                    epydoc_injections = epydoc_f.read()
                epydoc_injections = epydoc_injections.strip()
                if epydoc_injections:
                    f.write("\n=== %s EPYDOC INJECTIONS ===\n" % mname)
                    f.write(epydoc_injections)
                    f.write("\n=== %s EPYDOC INJECTIONS END ===\n" % mname)

idaapi.qexit(0)
