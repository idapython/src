
import re
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

def dump_thing(f, label, thing, vec_info=None):
    try:
        doc = thing.__doc__
        if doc and not doc in ignore_python_builtin_docs:
            doc_lines = doc.split("\n")
            doc_lines = map(lambda l: "\t%s" % l, doc_lines)
            if vec_info:
                doc_lines = map(vec_info["process_line"], doc_lines)
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
    re.compile(".*dump_state$"),
]
def should_ignore_name(namespace_name, name):
    for ign in ignore_names:
        if isinstance(ign, tuple):
            if ".".join(ign) == ".".join((namespace_name, name)):
                return True
        elif isinstance(ign, basestring):
            if ign == name:
                return True
        else:
            if ign.match(".".join((namespace_name, name))):
                return True
    return False

def make_eavec_lines_processor(directives):
    def f(l):
        for tokens, replacement in directives:
            for token in tokens:
                l = l.replace(token, replacement)
        return l
    return f

classes = {
    "svalvec_t" :
    {
        "process_line" : make_eavec_lines_processor(
            [
                (("<(int)>", "<(long long)>"), "<(signed-ea-like-numeric-type)>"),
                (("qvector< int >", "qvector< long long >"), "qvector< signed-ea-like-numeric-type >"),
                (("-> int &", "-> long long &"), "-> signed-ea-like-numeric-type &"),
                (("-> int *", "-> long long *"), "-> signed-ea-like-numeric-type *"),
                (("-> int const &", "-> long long const &"), "-> signed-ea-like-numeric-type &"),
            ])
    },
    "uvalvec_t" :
    {
        "process_line" : make_eavec_lines_processor(
            [
                (("<(unsigned int)>", "<(unsigned long long)>"), "<(unsigned-ea-like-numeric-type)>"),
                (("qvector< unsigned int >", "qvector< unsigned long long >"), "qvector< unsigned-ea-like-numeric-type >"),
                (("-> unsigned int &", "-> unsigned long long &"), "-> unsigned-ea-like-numeric-type &"),
                (("-> unsigned int *", "-> unsigned long long *"), "-> unsigned-ea-like-numeric-type *"),
                (("-> unsigned int const &", "-> unsigned long long const &"), "-> unsigned-ea-like-numeric-type &"),
            ])
    },
    "uval_ivl_t" : {
        "process_line" : make_eavec_lines_processor(
            [
                (("-> unsigned int", "-> unsigned long long"), "-> unsigned-ea-like-numeric-type"),
            ])
    },
    "uval_ivl_ivlset_t" : {
        "process_line" : make_eavec_lines_processor(
            [
                (("-> ivlset_tpl< ivl_t,unsigned int >",
                  "-> ivlset_tpl< ivl_t,unsigned long long >"),
                 "-> ivlset_tpl< ivl_t,unsigned-ea-like-numeric-type >"),
            ])
    },
}
classes["casevec_t"] = classes["svalvec_t"]
classes["eavec_t"] = classes["uvalvec_t"]
classes["casm_t"] = classes["eavec_t"]
classes["ivl_t"] = classes["uval_ivl_t"]
classes["ivlset_t"] = classes["uval_ivl_ivlset_t"]

def dump_namespace(f, namespace, namespace_name, keys, vec_info=None):
    for thing_name in keys:
        if thing_name.startswith("_") and not thing_name in ["_print", "_free"]:
            continue
        if should_ignore_name(namespace_name, thing_name):
            continue
        thing = getattr(namespace, thing_name)
        if inspect.isclass(thing):
            vec_info = classes.get(thing_name, None)
            dump_thing(f, "class %s.%s()" % (namespace_name, thing_name), thing, vec_info)
            members = map(lambda t: t[0], inspect.getmembers(thing))
            dump_namespace(f, thing, "%s.%s" % (namespace_name, thing_name), members, vec_info)
        elif callable(thing):
            dump_thing(f, "%s.%s()" % (namespace_name, thing_name), thing, vec_info)
        elif not inspect.ismodule(thing):
            dump_thing(f, "%s.%s" % (namespace_name, thing_name), thing, vec_info)

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
