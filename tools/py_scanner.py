
import sys
import ast
import inspect
import argparse
import os

p = argparse.ArgumentParser()
p.add_argument("-p", "--paths", type=str, required=True, help="Path(s) to the file(s) to parse")
p.add_argument("-c", "--dump-doc", default=False, action="store_true", help="Dump python docstrings")
p.add_argument("-k", "--dump-kind", default=False, action="store_true", help="Dump scopes kinds (class, method, ...)")
args = p.parse_args()

class scope_t(object):
    def __init__(self, node, scope):
        self.node = node
        self.parent = None
        self.children = []
        self.doc = None

    def _new_scope(self, _type, node):
        scope = _type(node, self)
        self.children.append(scope)
        scope.parent = self
        return scope

    def kind(self):
        return self.__class__.__name__.replace("_t", "")

    def new_class(self, node):
        return self._new_scope(class_t, node)

    def new_method(self, node):
        return self._new_scope(method_t, node)

    def new_function(self, node):
        return self._new_scope(function_t, node)

    def new_variable(self, node, variable_name):
        s = self._new_scope(variable_t, node)
        s.variable_name = variable_name
        return s

    def get_name(self):
        return self.node.name

    def get_full_name_parts(self):
        parts = []
        s = self
        while s is not None:
            parts.append(s.get_name())
            s = s.parent
        return reversed(parts)

    def get_full_name(self):
        return ".".join(self.get_full_name_parts())

    def set_doc(self, doc):
        self.doc = doc

class module_t(scope_t):
    pass

class class_t(scope_t):
    pass

class method_t(scope_t):
    pass

class function_t(scope_t):
    pass

class variable_t(scope_t):
    def get_name(self):
        return self.variable_name


DF_DOC  = 0x1
DF_KIND = 0x2

def dump(scope, flags=0, sort=True):
    lines = []
    def dump1(s):
        name = s.get_full_name()
        line = [name]
        if (flags & DF_KIND) != 0:
            line.append("(%s)" % s.kind())
        lines.append(" ".join(line))
        if (flags & DF_DOC) != 0:
            if s.doc is not None:
                lines.extend(s.doc.split("\n"))
            lines.append("")
        children = s.children[:]
        if sort:
            children = sorted(children, key=lambda n: n.get_name())
        for c in children:
            dump1(c)
    dump1(scope)
    return "\n".join(lines)

class collector_t(ast.NodeVisitor):

    class temp_scope_t(object):
        def __init__(self, collector, scope):
            self.collector = collector
            self.scope = scope

        def __enter__(self):
            old_scope = self.collector.scope
            self.collector.scope = self.scope
            self.scope = old_scope # swoop in the old context

        def __exit__(self, tp, value, traceback):
            self.collector.scope = self.scope
            if value:
                raise

    def __init__(self, module_name):
        class module_node_t(object):
            def __init__(self, name):
                self.name = name
        self.scope = module_t(module_node_t(module_name), None)
        self.assign_last_line = -1

        super(collector_t, self).__init__()

    def in_function(self):
        return isinstance(self.scope, function_t)

    def in_class(self):
        return isinstance(self.scope, class_t)

    def accept(self, node):
        return True

    def visit_FunctionDef(self, node):
        if self.accept(node):
            if self.in_class():
                s = self.scope.new_method(node)
            else:
                s = self.scope.new_function(node)
            with self.temp_scope_t(self, s):
                self.generic_visit(node)

    def visit_ClassDef(self, node):
        if self.in_function():
            return
        if self.accept(node):
            with self.temp_scope_t(self, self.scope.new_class(node)):
                self.generic_visit(node)

    def visit_Assign(self, node):
        if self.in_function():
            return
        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                self.assign_variable  = target.id
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
        # print("%d: %s" % (node.lineno, ast.dump(node.value)))
        if not isinstance(node.value, ast.Str):
            return

        if hasattr(node, "end_lineno"):
            line_before = node.lineno - 1   # in this case, lineno = start
        else:
            # hack until Python 3.8; if <3.8, lineno = end
            line_before = node.lineno - len(node.value.s.split("\n"))

        clean_doc = self._cleandoc(node.value.s)
        if line_before == self.assign_last_line:
            self.scope.new_variable(node, self.assign_variable).set_doc(clean_doc)
        else:
            self.scope.set_doc(clean_doc)
            # self.variables.append(
            #     "\nDocumentation on variable %s in module %s:\n\n%s\n" \
            #     % (self.assign_variable,
            #        self.module_name,
            #        self._cleandoc(node.value.s)))

    def _cleandoc(self, docstring):
        if docstring:
            docstring = inspect.cleandoc(docstring)

            # 4-blanks indent
            docstring = "\n".join("    " + line for line in docstring.split("\n"))

        return docstring


class docfixing_collector_t(collector_t):

    IGNORE = [
        "ida_kernwin.__ask_form_callable",
        "ida_kernwin.__call_form_callable",
        "ida_kernwin.__open_form_callable",
        "*._SwigNonDynamicMeta",
        "*._swig_add_metaclass",
        "*._swig_add_metaclass.wrapper",
        "*._swig_repr",
        "*._swig_setattr_nondynamic_class_variable",
        "*._swig_setattr_nondynamic_class_variable.set_class_attr",
        "*._swig_setattr_nondynamic_instance_variable",
        "*._swig_setattr_nondynamic_instance_variable.set_instance_attr",
        "*.*.dump_state",
    ]

    def accept(self, node):
        full_name_parts = list(self.scope.get_full_name_parts()) + [node.name]
        for ign in self.IGNORE:
            ign_parts = ign.split(".")
            if len(full_name_parts) == len(ign_parts):
                match = True
                for got, against in zip(full_name_parts, ign_parts):
                    if against != "*" and got != against:
                        match = False
                        break
                if match:
                    return False
        return True

    TRANSLATIONS = {
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
        "ida_regfinder.find_reg_value" : [
            ((
                "'uint32 *'",
                "'uint64 *'",
            ), "unsigned-ea-like-numeric-type", True),
        ],
        "ida_regfinder.find_sp_value" : [
            ((
                "'int32 *'",
                "'int64 *'",
            ), "signed-ea-like-numeric-type", True),
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
        "ida_idp._processor_t" : [
            ((
                "'uint32 *'",
                "'uint64 *'",
            ), "'unsigned-ea-like-numeric-type *'", True),
        ],
        "ida_idp._processor_t_find_op_value" : [
            ((
                "'uint32 *'",
                "'uint64 *'",
            ), "'unsigned-ea-like-numeric-type *'", True),
        ],
        "ida_idp._processor_t_find_reg_value" : [
            ((
                "'uint32 *'",
                "'uint64 *'",
            ), "'unsigned-ea-like-numeric-type *'", True),
        ],
        "ida_kernwin.atoea" : [
            ((
                "-> 'uint32 *'",
                "-> 'uint64 *'",
            ), "'unsigned-ea-like-numeric-type *'", True),
        ],
        "ida_kernwin.str2ea" : [
            ((
                "-> 'uint32 *'",
                "-> 'uint64 *'",
            ), "'unsigned-ea-like-numeric-type *'", True),
        ],
        "ida_kernwin.str2ea_ex" : [
            ((
                "-> 'uint32 *'",
                "-> 'uint64 *'",
            ), "'unsigned-ea-like-numeric-type *'", True),
        ],
        "ida_kernwin.PluginForm" : [
            ((
                "module '__main__' from 'tools/dumpdoc.py'",
                "module '__main__' (built-in)",
            ), "module 'main'", False),
        ],
    }

    def _cleandoc(self, docstring):
        docstring = super(docfixing_collector_t, self)._cleandoc(docstring)
        name = self.scope.get_full_name()
        translations = None
        while name:
            translations = self.TRANSLATIONS.get(name, None)
            if translations:
                break
            name_parts = name.split(".")
            name = ".".join(name_parts[:-1])
        if translations:
            out = []
            for l in docstring.split("\n"):
                for all_frm, dst, _ in translations:
                    assert(isinstance(all_frm, tuple))
                    for frm in all_frm:
                        idx = l.find(frm)
                        if idx > -1:
                            # sys.stderr.write("SPOTTED '%s' in '%s', position %s\n" % (frm, l, idx))
                            l = l[0:idx] + dst + l[idx+len(frm):]
                # sys.stderr.write("ADDING '%s'\n" % l)
                out.append(l)
            docstring = '\n'.join(out)
        return docstring


toplevel_scopes = []
for path in args.paths.split(","):
    with open(path, "r") as f:
        tree = ast.parse(f.read())
    _, fname = os.path.split(path)
    module_name = fname[:fname.index(".")]
    vc = docfixing_collector_t(module_name)
    vc.visit(tree)
    toplevel_scopes.append(vc.scope)

flags = (DF_DOC if args.dump_doc else 0) \
      | (DF_KIND if args.dump_kind else 0)
for s in toplevel_scopes:
    print(dump(s, flags=flags))
