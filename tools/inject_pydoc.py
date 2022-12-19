
# A program to combine docstrings from multiple sources (Python, C++)
# into the final docstrings in the IDAPython sources.
# Called from the idapython makefile.
#
# Bird's eye view:
#
# main()                          Input from idapython/obj/.../*.py,
#   Various inputs                Output to current/bin/.../*.py
#   ------------------------      -----------------------
#   swig_pydoc_collector_t  \
#   cpp_wrapper_parser_t     |--> pydoc_patcher_t
#   doxygen_info_t          /
#   ------------------------      -----------------------
#
# pydoc_visitor_t __/ swig_pydoc_collector_t  \__
#    used by both   \ pydoc_patcher_t         /   to read Python's AST
#
# doc_info_t      \
# class_info_t     |
# cpp_fun_info_t   |-- (mostly) data objects
# location_t       |
# repo_t           |
# hook_info_t     /
#
# prototype_t           \
# structured_comment_t   |-- split docs in parts (prototype, parameters, text)
# assembled_comment_t   /    and help to reassemble these from multiple sources
#
# call_traces_t  --  runtime info collected from uitests,
#                    used to fix prototypes (f.i. return values)
#
# cases_t \__ allow special exceptions to the general rules;
# case_t  /   special cases are read from the file given by the --cases argument
#
# inspect_importer_t    \__ helper classes used resp. by __/ pydoc_visitor_t
# cpp_patterns_t        /                                  \ pydoc_patcher_t


from __future__ import print_function

import ast
import re
import sys
import os
import xml.etree.ElementTree as ET
import textwrap
from argparse import ArgumentParser

genhooks_dir = os.path.join(os.path.dirname(__file__), "genhooks")
if genhooks_dir not in sys.path:
    sys.path.append(genhooks_dir)
import all_recipes

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-s", "--interface", required=True)
parser.add_argument("-w", "--cpp-wrapper", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-x", "--xml-doc-directory", required=True)
parser.add_argument("-m", "--module", required=True)
parser.add_argument("-t", "--traces", required=False)
parser.add_argument("-c", "--cases", required=False)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
parser.add_argument("-d", "--debug", default=False, action="store_true")
parser.add_argument("-D", "--debug-name", type=str, default="")
args = parser.parse_args()

# --------------------------------------------------------------------------
class pysyntax_exception_t(Exception):
    def __init__(self, message, text):
        super(pysyntax_exception_t, self).__init__(
            "%s\n  %s" % (message, text))

# --------------------------------------------------------------------------
class cppsyntax_exception_t(Exception):
    def __init__(self, parser, message):
        super(cppsyntax_exception_t, self).__init__(
            "%s\n  Path: %s\n  Func: %s"
            % (message, parser.path, parser.fun_name))

# --------------------------------------------------------------------------
class process_exception_t(Exception):
    pass

selective_debug = False

# --------------------------------------------------------------------------
def pyver():
    return sys.version_info.major

LOG_LEVEL_DEBUG = 1
LOG_LEVEL_VERB = 2
LOG_LEVEL_INFO = 3
log_level_pfx = {
    LOG_LEVEL_DEBUG : "DEBUG",
    LOG_LEVEL_VERB : "VERB",
    LOG_LEVEL_INFO : "INFO",
}

log_level = LOG_LEVEL_INFO
log_indent = 0
class new_log_indent_t(object):
    def __enter__(self):
        global log_indent
        log_indent += 1
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        global log_indent
        log_indent -= 1
        if exc_value:
            raise


# --------------------------------------------------------------------------
def log(level, msg):
    if log_level >= level:
        pfx = log_level_pfx[level]
        if isinstance(msg, bytes):
            msg = msg.decode("utf-8")
        lines = msg.split("\n")
        for line in lines:
            print("%s: %s%s" % (pfx, log_indent * "    ", line))

# --------------------------------------------------------------------------
def log_debug(msg):
    return log(LOG_LEVEL_DEBUG, msg)

# --------------------------------------------------------------------------
def log_verb(msg):
    return log(LOG_LEVEL_VERB, msg)

# --------------------------------------------------------------------------
def log_info(msg):
    return log(LOG_LEVEL_INFO, msg)

# --------------------------------------------------------------------------
# TL;DR: we need the proper "inspect" module,
#        and this class ensures that we import the right one.
#
# Long story:
#
# pydoc_visitor_t (below) uses ast.get_docstring(..., False)
#    ("True" would have cleaned the docstring by calling
#     the "cleandoc" function in the "inspect" module).
#
# We chose to read without cleaning, and clean manually later
# (by a call to "inspect.cleandoc"), because other docstrings
# do not come from ast.get_docstring() - namely, the ones we
# pcik up manually after assignments, as docstrings for a variable.
#
# For that manual cleaning, we need the inspect module;
# this class ensures that we load the correct one
# (why is there a "correct" or an "incorrect" inspect module,
#  is explaned in another comment below).

class inspect_importer_t(object):

    singleton = None

    @staticmethod
    def get_singleton():
        klass = inspect_importer_t

        if not klass.singleton:
            klass.singleton = inspect_importer_t()

        return klass.singleton

    def __init__(self):
        self.imported_inspect = False
        self.saved_sys_path   = None
        self.is_python_2      = pyver() == 2

    def ensure_imported_inspect(self):
        if self.imported_inspect:
            return
        self.imported_inspect = True

        if self.is_python_2:
            self._modify_sys_path()

        import inspect
        self.inspect = inspect

        if self.is_python_2:
            self._restore_sys_path()

    def _modify_sys_path(self):
        # We need to use the "inspect" module after "ast.get_docstring()".
        # (See pydoc_visitor_t.) And...
        #
        # ... there is an "inspect.py" module next to this program, that
        # is used (as per CL 101338) to ensure a consistent documentation
        # regardless of the minor version of Python 3.
        #
        # However, it's useless when running on Python 2,
        # in which case we temporarily remove dirname(__file__) from sys.path
        # in order to use Python 2's own "inspect" module.

        self.saved_sys_path = sys.path[:]

        executable_dir = os.path.abspath(os.path.dirname(__file__))
        while True:
            try:
                sys.path.remove(executable_dir)
            except:
                break

    def _restore_sys_path(self):
        sys.path = self.saved_sys_path[:]

# --------------------------------------------------------------------------
# Keeps track of where a docstring appears in the source code,
# so that the text can be replaced later.

class location_t(object):
    def __init__(self, *args):
        if len(args) == 1:
            reference = args[0]

            # used when there is no comment to be removed from the source;
            # we just need a line to insert a comment if needed

            line_after_ref = self.last_line(reference) + 1

            self.start_line = self.end_line = line_after_ref
            self.start_col  = self.end_col  = reference.col_offset

        elif len(args) == 2:
            node, reference = args

            # the docstring's lineno/col_offset mark the end
            # for multiline comments (end_col for single-line comments
            # is not available, so the rest of the code will not use it);
            # we use a "reference node" (the class or function, or
            # the assigment before the string) to guess the start
            # and assume that there is nothing else in between.
            # The initial column is assumed 4 if class/function,
            # or 0 if variable assignment (plus the reference indent).

            is_variable = isinstance(reference, ast.Assign)

            if hasattr(node, "end_lineno"):
                self.start_line = node.lineno
                self.end_line   = node.end_lineno
            else:
                self.start_line = self.last_line(reference) + 1
                self.end_line   = node.lineno

            self.end_col   = node.col_offset # only for multi-line comments
            self.start_col = reference.col_offset + (0 if is_variable else 4)

        else:
            raise process_exception_t("Internal error, location_t with %d args" \
                                      % len(args))

    @staticmethod
    def last_line(node):
        if hasattr(node, "end_lineno"):
            return node.end_lineno

        # hack, until Python 3.8 (where nodes have both lineno and end_lineno)

        last_line = node.lineno

        if isinstance(node, ast.ClassDef):
            # note: no class body, just the header
            last_line = max(last_line,
                            last_line + len(node.decorator_list),
                            location_t._max_lineno(node.bases))

        elif isinstance(node, ast.FunctionDef):
            # note: no function body, just the header
            last_line = max(last_line,
                            last_line + len(node.decorator_list),
                            location_t._max_lineno(node.args))

        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            last_line = max(last_line,
                            location_t._max_lineno(node))

        return last_line

    @staticmethod
    def _max_lineno(subtree):
        # can return 0

        if isinstance(subtree, list):
            return max(location_t._max_lineno(item) for item in subtree) \
                   if len(subtree) > 0 else 0

        linenos = [node.lineno for node in ast.walk(subtree) \
                   if hasattr(node, "lineno")]
        return max(linenos) if len(linenos) > 0 else 0

# --------------------------------------------------------------------------
# Containers for docstrings

class doc_info_t(object):
    # for both functions and variables; classes use a specialization

    def __init__(self, name, doc, location, extra=None):
        self.name     = name
        self.doc      = doc if doc else ""
        self.location = location
        self.extra    = extra
        self.parent   = None     # filled in later

# --------------------------------------------------------------------------
class class_info_t(doc_info_t):
    def __init__(self, name, doc, location):
        super(class_info_t, self).__init__(name, doc, location)
        self.classes   = {}
        self.functions = {}
        self.variables = {}

# --------------------------------------------------------------------------
# C++ functions with body text

class cpp_fun_info_t(object):
    def __init__(self, name, body):
        self.name    = name
        self.body    = body

# --------------------------------------------------------------------------
# In this context, "storage" is an object with dictionaries
# named "classes", "functions" and "variables".
# This class implement common lookups for all such containers.

KIND_CLASS = "class"
KIND_UNION = "union"
KIND_STRUCT = "struct"
KIND_FUNCTION = "function"
KIND_VARIABLE = "variable"
KIND_DEFINE = "define"
KIND_FILE = "module"

class repo_t(object):
    def __init__(self, storage, ident):
        self.storage = storage
        self.ident = ident

    def match(self, kind, long_name):
        return self._match(kind, long_name.split("."), self.storage)

    def _match(self, kind, chain, storage):
        name = chain[0]

        if len(chain) > 1:
            # only classes left of dots
            if name not in storage.classes:
                return None

            return self._match(kind, chain[1:], storage.classes[name])

        # right terminal

        if kind == KIND_CLASS:
            return storage.classes.get(name, None)
        elif kind == KIND_FUNCTION:
            return storage.functions.get(name, None)
        elif kind == KIND_VARIABLE:
            return storage.variables.get(name, None)

        return None

# --------------------------------------------------------------------------
# AST navigation common to wrappers/*.py files
#              and <pydoc>s in swig/*.i files
# (they are both Python code)

class pydoc_visitor_t(ast.NodeVisitor):

    WARN_ON_VARIABLE = "Docstring on assignment not recognized"

    ADD_CLASS    = 1
    ADD_FUNCTION = 2
    ADD_VARIABLE = 3

    def __init__(self, classes, functions, variables):
        self.super = super(pydoc_visitor_t, self)
        self.super.__init__()

        self.classes   = classes
        self.functions = functions
        self.variables = variables

        self.assign_line = -1

    def collect_from(self, tree):
        self.in_class = []
        self.in_func  = []
        self.generic_visit(tree)

    def visit_ClassDef(self, node):
        info = self._info_class_or_func(node, class_info_t, self.in_func)
        if info is None:
            return

        self._add(info, self.ADD_CLASS)

        self.in_class.append(info)
        self.super.generic_visit(node)
        self.in_class.pop()

    def visit_FunctionDef(self, node):
        # ignore "replfun"-decorated functions
        for dec in node.decorator_list:
            if isinstance(dec, ast.Attribute) and dec.attr == "replfun":
                return

        info = self._info_class_or_func(node, doc_info_t, self.in_func)
        if info is None:
            return

        self._add(info, self.ADD_FUNCTION)

        self.in_func.append(info)
        self.super.generic_visit(node)
        self.in_func.pop()

    def visit_If(self, node):
        # ignore declarations in block (formerly, if _BC695)

        pass # no call to generic_visit into its body

    def visit_Assign(self, node):
        if self.in_func:
            return

        self.assign_line = location_t.last_line(node)
        # unless stated otherwise
        self.assign_warn = self.WARN_ON_VARIABLE

        # only syntax accepted: var = expr or self.member = expr
        # (as opposed to v1 = v2 = expr, or var += expr, or obj.member = expr)

        if len(node.targets) != 1:
            return
        target = node.targets[0]

        if isinstance(target, ast.Attribute):
            if not isinstance(target.value, ast.Name):
                return
            if target.value.id != "self":
                return
            if not self.in_class:
                self.assign_warn = "\"self.%s\" not inside a class" \
                                   % target.attr
                return

            name = target.attr

        elif isinstance(target, ast.Name):
            name = target.id
        else:
            return

        # success

        self.assign_node = node
        self.assign_var  = name
        self.assign_warn = None

        # aim to add a comment after this line, if there isn't one
        info = doc_info_t(self.assign_var, "", location_t(node))
        self._add(info, self.ADD_VARIABLE)

    def visit_AugAssign(self, node):
        if self.in_func:
            return

        # unaccepted syntax, f.i. var += expr
        self.assign_line = location_t.last_line(node)
        self.assign_warn = self.WARN_ON_VARIABLE

    def visit_Expr(self, node):
        if self.in_func:
            return

        if isinstance(node.value, ast.Str):
            if hasattr(node, "end_lineno"):
                line_before = node.lineno - 1   # "lineno" is the start line
            else:
                # hack until Python 3.8
                num_lines   = len(node.value.s.split("\n"))
                line_before = node.lineno - num_lines   # "lineno" is the end line

            if line_before == self.assign_line:
                # the string follows an assignment
                # (as opposed to a class or function)

                if self.assign_warn:
                    log_verb("%s, line %d: %s"
                         % (self.path, node.lineno, self.assign_warn))
                    return

                docstring = self._clean_docstring(node.value.s)

                # update the info structure already collected on Assign

                storage = self.in_class[-1] if self.in_class else self
                info    = storage.variables[self.assign_var]

                info.doc      = docstring
                info.location = location_t(node, self.assign_node)

    def _info_class_or_func(self, node, info_type, nested):
        private = node.name[0] == "_" and node.name[:2] != "__"
        if private or nested:
            # ignore internals
            if not private:
                log_verb("Ignoring nested (%s): %s"
                     % (nested[-1].name, node.name))
            return None

        docstring = self._get_docstring(node)

        return info_type(node.name, docstring,
                         location_t(node.body[0], node))

    def _add(self, info, add_type):
        target = self.in_class[-1] if self.in_class else self

        if add_type == self.ADD_CLASS:
            storage = target.classes
            msg     = KIND_CLASS
        elif add_type == self.ADD_FUNCTION:
            storage = target.functions
            msg     = KIND_FUNCTION
        else:
            storage = target.variables
            msg     = KIND_VARIABLE

        if info.name in storage:
            if self.in_class:
                if msg == KIND_FUNCTION:
                    msg = "method"
                msg = "%s in class %s" % (msg, target.name)

            log_verb("Duplicate %s: %s" % (msg, info.name))
            return # keep the first

        storage[info.name] = info

        info.parent = None if target is self else target

    def _get_docstring(self, node):
        # clean a docstring manually, as we would for strings after a variable
        return self._clean_docstring(ast.get_docstring(node, False))

    def _clean_docstring(self, docstring):
        if docstring:
            inspect_importer = inspect_importer_t.get_singleton()
            inspect_importer.ensure_imported_inspect()

            docstring = inspect_importer.inspect.cleandoc(docstring)

        return docstring

# --------------------------------------------------------------------------
# for <pydoc>s in swig/*.i files

class swig_pydoc_collector_t(object):
    def __init__(self):
        super(swig_pydoc_collector_t, self).__init__()

        self.re_pydoc = re.compile(r"^#<pydoc>.*?$"
                                   r"(.*?)"
                                   r"^#</pydoc>.*?$", re.MULTILINE | re.DOTALL)

    def collect(self, path):
        # collect <pydoc>...</pydoc> texts

        with open(path, "r") as f:
            text = f.read()

        pydocs = []
        start  = 0
        while text:
            m = self.re_pydoc.search(text, start)
            if not m:
                break
            pydocs.append(m.group(1))
            start = m.end()

        # parse the pydocs for docstrings

        self.classes   = {}
        self.functions = {}
        self.variables = {}

        visitor = pydoc_visitor_t(self.classes, self.functions, self.variables)

        for pydoc in pydocs:
            try:
                log_verb("swig_pydoc_collector_t: parsing clob %s" % pydoc)
                tree = ast.parse(pydoc)
            except Exception as ex:
                message = ex.__class__.__name__ + ": " + str(ex)
                raise pysyntax_exception_t(message, pydoc)

            visitor.collect_from(tree)

# --------------------------------------------------------------------------
# for wrappers/*.cpp files

class cpp_wrapper_parser_t(object):
    def __init__(self):
        self.re_wrap   = re.compile(r".*PyObject *\*_wrap_([^\(]*)\(.*\) *{")
        self.re_string = re.compile(r"([\"'])(?:\\?.)*?\1")
        self.re_curly  = re.compile(r"[{}]")

    def collect(self, path):
        # only "functions" filled in
        self.classes   = {}
        self.functions = {}
        self.variables = {}

        self.path = path # for cppsyntax_exception_t

        with open(path, "r") as f:
            text = f.read()

        # remove strings
        # (to avoid being confused by "{" "}" inside strings)
        text = self.re_string.sub("", text)
        # no need to remove comments
        # because these _wrap_* functions are computer-generated code,
        # they contain no comments

        start = 0
        while text:
            m = self.re_wrap.search(text, start)
            if not m:
                break
            self.fun_name = m.group(1) # for cppsyntax_exception_t
            start, end    = self._find_body(text, m.start())
            body          = text[start:end]

            self.functions[self.fun_name] = cpp_fun_info_t(self.fun_name, body)
            start = end

    def _find_body(self, text, pos):
        count = 0
        while True:
            m = self.re_curly.search(text, pos)
            if not m:
                break

            if m.group()[0] == "{":
                if count == 0:
                    start = m.start()
                count += 1
            else:
                if count == 0:
                    break
                count -= 1
                if count == 0:
                    return start, m.end()

            pos = m.end()

        raise cppsyntax_exception_t(self, "Cannot find body")

# --------------------------------------------------------------------------
# get return types from patterns in the C++ body

class cpp_patterns_t(object):
    PATTERNS = (
        ("resultobj = _maybe_sized_cstring_result(", "str"),
        ("resultobj = _maybe_cstring_result(", "str"),
        ("resultobj = _maybe_binary_result(", "str"),
        ("resultobj = _maybe_cstring_result_on_charptr_using_allocated_buf(", "str"),
        ("resultobj = _maybe_cstring_result_on_charptr_using_qbuf(", "str"),
        ("resultobj = _maybe_byte_array_as_hex_or_none_result(", "str"),
        ("resultobj = _maybe_byte_array_or_none_result(", "bytes"),
        ("resultobj = _sized_cstring_result(", "str")
    )

    def from_pattern(self, fun_info):
        have_type = None

        for pattern, ret_type in cpp_patterns_t.PATTERNS:
            if fun_info.body.find(pattern) >= 0:
                if have_type:
                    log_verb("C++ function \"%s\", multiple patterns match"
                         % fun_info.name)
                have_type = ret_type

        return have_type

# --------------------------------------------------------------------------
class hook_info_t(object):
    def __init__(self, storage, data):
        self.filename,         \
        self.enum_name,        \
        self.discard_prefixes, \
        self.discard_doc,      \
        self.strip_prefixes,   \
        recipe_module = data

        self.storage           = storage
        self.discard_prefixes  = tuple(self.discard_prefixes)
        self.recipe            = recipe_module.recipe
        self.default_rtype     = recipe_module.default_rtype
        self.ignore_parameters = {}

    def add_fun(self, klass, fun, doc):
        if klass in self.storage.classes:
            info = self.storage.classes[klass]
        else:
            info = self.storage.classes[klass] = class_info_t(klass, "", None)

        if fun in info.functions:
            log_verb("%s: existing function collides with hook callback \"%s\""
                 % (klass, fun))

        info.functions[fun] = fun_info = doc_info_t(fun, doc, None)

    def ignore_parameter(self, fun, param):
        if fun not in self.ignore_parameters:
            self.ignore_parameters[fun] = set()

        self.ignore_parameters[fun].add(param)

# --------------------------------------------------------------------------
class doxygen_info_t(object):
    def __init__(self, xml_dir):
        self.xml_dir = xml_dir

        self.module = None
        self.classes = {}
        self.functions = {}
        self.variables = {}

        self.hook_recipes = {}

    # hook (callback) functions from C++ enumerations

    def get_hook_info(self, klass):
        return self.hook_recipes.get(klass)

    def load_hooks(self):
        file_index = {}

        for klass in all_recipes.hooks:
            hook = all_recipes.hooks[klass]

            self.hook_recipes[klass] = info = hook_info_t(self, hook)

            if info.filename in file_index:
                index_entry = file_index[info.filename]
            else:
                index_entry = file_index[info.filename] = {}
            index_entry[info.enum_name] = klass

        for filename in file_index:
            pathname = os.path.join(self.xml_dir, filename)
            if not os.path.exists(pathname):
                log_verb("A hook recipe calls for XML file \"%s\","
                     " which does not exist!"
                     % filename)
                continue

            with open(pathname, "r") as f:
                xml = ET.fromstring(f.read())

            for compound_kind, section_kind, member_kind, name, _, _, _, enum_nodes \
                in self._enumerate_names(xml):

                if member_kind != "enum" or name not in file_index[filename]:
                    continue
                klass = file_index[filename][name]
                info  = self.hook_recipes[klass]

                if enum_nodes is None:
                    log_verb("Hooks recipe \"%s\" calls for enum \"%s\""
                         " in file \"%s\", which has no data!"
                         % (klass, info.enum_name, filename))
                    continue

                for node in enum_nodes:
                    data = self._candidate_value(node, compound_kind, section_kind, member_kind, name)
                    if data:
                        _, _, _, \
                        value_name, brief_node, detailed_node, _, _ = data

                        if value_name.startswith(info.discard_prefixes):
                            continue

                        brief_doc    = self._outer_paragraphs(brief_node)
                        detailed_doc = self._outer_paragraphs(detailed_node)
                        doc          = self._join_paragraphs( (brief_doc, detailed_doc) )

                        if info.discard_doc and doc.startswith(info.discard_doc):
                            continue
                        if doc.startswith("cb:"):
                            doc = doc[3:].lstrip()

                        for prefix in info.strip_prefixes:
                            if value_name.startswith(prefix):
                                value_name = value_name[len(prefix):]
                                break

                        if not self._follow_recipe(info, value_name):
                            continue

                        info.add_fun(klass, value_name, doc)

    def _follow_recipe(self, info, fun_name):
        if fun_name not in info.recipe:
            return True

        recipe = info.recipe[fun_name]

        if recipe.get("ignore", False):
            return False

        if "params" in recipe:
            params = recipe["params"]
            for param_name in params:
                param = params[param_name]

                if param.get("suppress_for_call", False):
                    info.ignore_parameter(fun_name, param_name)

        return True

    # recover comments from C++ classes / functions / variables

    def load(self, module):
        xmodule = self._load_module(module)
        if xmodule is None:
            return False
        log_verb("Loading module %s" % module)
        self._examine_xml(xmodule, module, self)
        return True

    def _examine_xml(self, xml, module_name, storage):
        for name in self._enum_classes(xml):
            if name not in storage.classes:
                storage.classes[name] = class_info_t(name, "", None)

            xclass = self._load_class(xml, name)
            self._examine_xml(xclass, module_name, storage.classes[name])

        for compound_kind, section_kind, member_kind, name, brief_node, detailed_node, plist, enum_nodes \
            in self._enumerate_names(xml):

            brief_doc    = self._outer_paragraphs(brief_node)
            detailed_doc = self._outer_paragraphs(detailed_node)
            doc          = self._join_paragraphs( (brief_doc, detailed_doc) )

            # log_verb("section_kind=%s, compound_kind=%s, member_kind=%s, name=%s, brief_doc=%s" % (
            #     section_kind,
            #     compound_kind,
            #     member_kind,
            #     name,
            #     brief_doc))

            if section_kind == "":
                if compound_kind in (KIND_CLASS, KIND_STRUCT, KIND_UNION):
                    if name in storage.classes:
                        storage.classes[name].doc = doc
                    else:
                        storage.classes[name] = class_info_t(name, doc, None)
                elif compound_kind == "file" and name.startswith("%s.h" % module_name):
                    storage.module = self._join_paragraphs( (brief_doc, detailed_doc) )
                continue

            if member_kind == KIND_FUNCTION:
                storage.functions[name] = doc_info_t(name, doc, None, plist)
            elif member_kind in (KIND_DEFINE, KIND_VARIABLE):
                storage.variables[name] = doc_info_t(name, doc, None)

            # add enum values as variables definitions

            if enum_nodes is None:
                continue

            for node in enum_nodes:
                data = self._candidate_value(node, compound_kind, section_kind, member_kind, name)
                if data:
                    _, _, _, \
                    value_name, brief_node, detailed_node, _, _ = data

                    brief_doc    = self._outer_paragraphs(brief_node)
                    detailed_doc = self._outer_paragraphs(detailed_node)
                    doc          = self._join_paragraphs( (brief_doc, detailed_doc) )

                    storage.variables[value_name] = doc_info_t(value_name, doc, None)

    def _enumerate_names(self, xml):
        for compound in xml.findall("compounddef"):
            compound_kind = compound.attrib["kind"]

            data = self._candidate_value(compound,
                                         compound_kind)
            if data:
                yield data

            for section in compound.findall("sectiondef"):
                section_kind = section.attrib["kind"]

                if section_kind.startswith("private-") or \
                   section_kind.startswith("protected-") or \
                   section_kind in ("friend"):
                    continue

                data = self._candidate_value(section,
                                             compound_kind,
                                             section_kind)
                if data:
                    yield data

                for member in section.findall("memberdef"):
                    member_kind = member.attrib["kind"]

                    data = self._candidate_value(member,
                                                 compound_kind,
                                                 section_kind,
                                                 member_kind,
                                                 "",
                                                 True)
                    if data:
                        yield data

    def _candidate_value(self, node, compound_kind, section_kind="", member_kind="", enum="", get_enums=False):
        brief_node    = node.find("briefdescription")
        detailed_node = node.find("detaileddescription")
        enum_nodes    = node.findall("enumvalue") if get_enums else None

        if brief_node    is None and \
           detailed_node is None and \
           enum_nodes    is None:
            return None

        plist = []
        for pnode in node.findall("param"):
            plist.append(self._parse_param_node(pnode))

        name_node = node.find("name" if section_kind else "compoundname")
        name      = ""
        if name_node is not None:
            name = name_node.text
        if not name:
            log_verb("Doxygen xml: compound \"%s\", section \"%s\","
                 " member \"%s\"%s has no name but has content!"
                 % (compound_kind, section_kind, member_kind,
                  (", enum \"%s\"" % enum) if enum else ""))
            return None

        return compound_kind, section_kind, member_kind, name, brief_node, detailed_node, plist, enum_nodes

    def _parse_param_node(self, pnode):
        name_child = pnode.find("declname")
        type_child = pnode.find("type")

        ret = ["", ""]
        if name_child is not None:
            ret[0] = name_child.text
        if type_child is not None:
            ret[1] = self._clean(type_child)
        return ret

    def _outer_paragraphs(self, node):
        return self._paragraphs(node, True)

    def _paragraphs(self, node, wrap=False):
        if node is None:
            return ""

        texts = [self._nul(node.text)]
        for para in node.findall("para"):
            clean = self._clean(para)
            if wrap:
                clean = self._wrap(clean)
            texts.append(clean)

        return self._join_paragraphs(texts)

    def _wrap(self, text):
        lines = text.split("\n")

        out = []
        for line in lines:
            subsequent_indent = ""

            clean = line.lstrip()
            if clean and clean[0] == "@":
                # compute indent for @tags
                pos_colon = line.find(":")
                if pos_colon >= 0:
                    subsequent_indent = (pos_colon + 2) * " "

            # wrapping at 80; if left at 70,
            # texts from C++/Doxygen already contain
            # linebreaks just after 70, that will
            # make the wrapping ugly. Removing
            # C++ linebreaks is probably not an option,
            # if we want to respect pre-formatting.
            out.extend(textwrap.wrap(line, 80, \
                                     subsequent_indent=subsequent_indent))

        return "\n".join(out)

    def _join_paragraphs(self, texts):
        # paragraphs (from "<para>") separated by a blank line

        return "\n\n".join( (text.strip() for text in texts) ).strip("\n")

    def _clean(self, node):
        N = self._nul

        texts = [N(node.text)]
        for child in node:
            check_subchildren = False

            if child.tag == "ref":
                check_subchildren = True
                texts[-1] += N(child.text) + N(child.tail)

            elif child.tag == "parameterlist":
                self._add_parameter_list(child, texts)

            elif child.tag == "itemizedlist":
                self._add_unordered_list(child, texts)

            elif child.tag == "orderedlist":
                self._add_ordered_list(child, texts)

            elif child.tag == "simplesect":
                kind = child.attrib["kind"]
                desc = self._paragraphs(child)
                # remove "@return: void"
                if kind != "return" or desc != "void":
                    self._add_tag(kind, desc, texts)

            elif child.tag == "ulink":
                check_subchildren = True
                # macro interpreted in tools/docs/epytext.py
                ref = child.attrib["url"]
                if ref == child.text:
                    texts[-1] += r"\link{{{}}}".format(ref)
                else:
                    texts[-1] += r"\link{{{},{}}}".format(ref, child.text)
                texts[-1] += N(child.tail)

            elif child.tag == "linebreak":
                check_subchildren = True
                texts.append(child.tail)

            elif child.tag in ("mdash", "ndash"):
                check_subchildren = True
                texts[-1] += "-" + N(child.tail)

            elif child.tag == "sp":
                check_subchildren = True
                texts[-1] += " " + N(child.tail)

            elif child.tag in ("preformatted", "verbatim"):
                # TODO? blockquote? may contain sub-elements like <para>)

                inner = [N(child.text)]
                for sub in child:
                    if sub.tag == "ref":
                        # ignore the link markup inside a <pre>
                        inner[-1] += N(sub.text) + N(sub.tail)
                    else:
                        # fail
                        check_subchildren = True
                        break
                if child.tail:
                    inner.append(N(child.tail))
                texts.append("".join(inner).strip("\n"))

            elif child.tag == "computeroutput":
                # like preformatted/verbatim above, but inline text
                texts[-1] += N(child.text)
                for sub in child:
                    if sub.tag == "ref":
                        # ignore the link markup
                        texts[-1] += N(sub.text) + N(sub.tail)
                    else:
                        # fail
                        check_subchildren = True
                        break
                texts[-1] += N(child.tail)

            elif child.tag == "programlisting":
                for sub in child:
                    if sub.tag == "codeline":
                        texts.append(self._clean(sub))
                    else:
                        # fail
                        check_subchildren = True
                        break
                if child.tail:
                    texts.append(N(child.tail))

            elif child.tag == "codeline":
                for sub in child:
                    texts[-1] += self._clean(sub)
                texts[-1] += N(child.tail)

            elif child.tag == "highlight":
                texts[-1] += self._clean(child)

            else:
                log_verb("Unrecognized tag \"%s\"" % child.tag)
                if child.text is not None:
                    texts.append(self._paragraphs(child))
                if child.tail is not None:
                    texts.append(child.tail)

            if check_subchildren:
                for sub in child:
                    raise process_exception_t(
                        "Unrecognized sub-tag \"%s\" under \"%s\"" \
                        % (sub.tag, child.tag))

        texts[-1] += N(node.tail)

        return "\n".join(text.strip() for text in texts)

    def _add_parameter_list(self, node, texts):
        tag   = node.attrib["kind"]
        plist = []
        for param in node.findall("parameteritem"):
            namelist    = param.find("parameternamelist")
            description = param.find("parameterdescription")
            names = []
            if namelist is not None:
                for name in namelist.findall("parametername"):
                    names.append(self._clean(name))
            if not names:
                names = ["unknown"]
            plist.append( (tag + " " + ",".join(names),
                           self._paragraphs(description).strip()) )

        # remove "@param none"
        if len(plist) == 1 and plist[0] == ("param none", ""):
            return

        for tag, desc in plist:
            self._add_tag(tag, desc, texts)

    def _add_unordered_list(self, node, texts):
        self._add_list(lambda n: "*", node, texts)

    def _add_ordered_list(self, node, texts):
        self._add_list(lambda n: "%d." % n, node, texts)

    def _add_list(self, marker, node, texts):
        num = 0
        for item in node.findall("listitem"):
            num += 1
            para = self._paragraphs(item).strip()
            texts.append(("%s " % marker(num)) + para)

    def _add_tag(self, tag, text, texts):
        result = "@%s" % tag
        if text:
            result += ": " + text
        texts.append(result)

    def _nul(self, text):
        return text if text else ""

    def _load_module(self, name):
        for suffix in ("_8hpp", "_8h"):
            xml_path = os.path.join(self.xml_dir, "%s%s.xml" % (name, suffix))
            if os.path.isfile(xml_path):
                with open(xml_path, "r") as f:
                    return ET.fromstring(f.read())
        return None

    def _enum_classes(self, xml):
        for node in xml.findall("compounddef/innerclass"):
            yield node.text

    def _load_class(self, xml, name):
        # apparently, an xpath to search for the TEXT of an element
        # is not available until Python 3.7
        for node in xml.findall("compounddef/innerclass"):
            if node.text == name:
                break
        else:
            node = None

        if node is None:
            return None
        xml_path = os.path.join(self.xml_dir, "%s.xml" % node.attrib["refid"])
        with open(xml_path, "r") as fin:
            return ET.fromstring(fin.read())

# --------------------------------------------------------------------------
# for wrappers/*.py files
# (output goes typically to bin/.../python/[23])

class pydoc_patcher_t(object):
    def __init__(self):
        self.traces = call_traces_t()
        self.traces.load(args.traces)

        self.cases = cases_t()
        self.cases.load(args.cases)

    def patch(self, infile, extra_sources, outfile):
        swig, cpp, doxy = extra_sources

        swig_repo = repo_t(swig, "SWiG")
        cpp_repo  = repo_t(cpp, "CPP parsing")
        doxy_repo = repo_t(doxy, "Doxygen parsing")

        self.classes   = {}
        self.functions = {}
        self.variables = {}

        with open(infile, "r") as f:
            text  = f.read()
            lines = text.split("\n")

        try:
            tree = ast.parse(text)
        except Exception as ex:
            # this text can be very long,
            # so we're not including all of it in the exception
            bad_line = "Line %d: %s" % (ex.lineno, lines[ex.lineno - 1]) \
                if ex.lineno > 0 and ex.lineno <= len(lines) \
                else "(line %s)" % str(ex.lineno)

            message = ex.__class__.__name__ + ": " + str(ex)
            raise pysyntax_exception_t(message, bad_line)

        log_info("Collecting from %s" % infile)
        with new_log_indent_t():
            visitor = pydoc_visitor_t(self.classes, self.functions, self.variables)
            visitor.collect_from(tree)

        cpp_patterns = cpp_patterns_t()

        NOT_SKIPPING = -1

        by_line   = self._sort_docstrings(visitor)
        skip_upto = NOT_SKIPPING

        with open(outfile, "w") as f:
            lineno = 0

            for lidx, line in enumerate(lines):
                if line.find("IDA Plugin SDK API wrapper") > -1:
                    skip_upto = lidx + 1
                    break

            if doxy.module is not None:
                f.write("\"\"\"\n")
                f.write(doxy.module)
                f.write("\"\"\"\n")

            for line in lines:
                lineno += 1

                if by_line and by_line[0][1].location.start_line == lineno:
                    kind, info   = by_line[0]
                    skip_upto    = info.location.end_line
                    indent       = info.location.start_col * " "
                    quote_open   = indent + "r\"\"\"\n"
                    quote_close  = indent + "\"\"\"\n"
                    long_name    = self._long_name(info)
                    special_case = self.cases.get(long_name)

                    global selective_debug
                    selective_debug = info.name == args.debug_name

                    log_debug("### Processing %s" % long_name)

                    # pywraps comments for functions typically contain
                    # a function prototype before the parameter documentation;
                    # for classes and variables, we add a dummy, empty prototype
                    # to allow matching in the replace() function below.

                    comment = structured_comment_t(kind != KIND_FUNCTION)
                    comment.parse(info.doc)

                    # "swig" and "doxy" have typically parameter documentation
                    # without a prototype, so an empty prototype is added
                    # (parameter True of structured_comment_t)
                    # in order to attempt to parse @param tags from these texts
                    # (as opposed to "free text before any prototype").

                    doxy_kind = special_case.doxy_kind(kind) \
                                if special_case else kind

                    swig_cmt  = structured_comment_t(True)
                    swig_info = swig_repo.match(kind, long_name)
                    if swig_info and swig_info.doc:
                        swig_cmt.parse(swig_info.doc)

                    doxy_cmt  = structured_comment_t(True)
                    doxy_info = doxy_repo.match(doxy_kind, long_name)
                    if doxy_info and doxy_info.doc:
                        # no prototypes from doxygen; also, avoid lines
                        # wrapped by textwrap to be interpreted as
                        # prototypes by accident
                        doxy_cmt.parse(doxy_info.doc, parse_prototypes=False)
                        # for functions, doxy_info.extra = C++ parameter types
                        doxy_cmt.add_cpp_params(doxy_info.extra)

                    cpp_info = cpp_repo.match(kind, long_name)

                    log_debug("==== From wrappers (.py)\n" + comment.total())
                    log_debug("==== From swig (.i)\n"      + swig_cmt.total())
                    log_debug("==== From Doxygen (.xml)\n" + doxy_cmt.total())

                    assembled = assembled_comment_t(special_case)
                    if comment.text_before.strip():
                        assembled.add_text_before(comment.text_before)
                    elif swig_cmt.text_before.strip():
                        assembled.add_text_before(swig_cmt.text_before)
                    else:
                        assembled.add_text_before(doxy_cmt.text_before)

                    if comment.prototypes:
                        for p in comment.prototypes:
                            assembled.add_prototype(p)
                    else:
                        assembled.add_prototype(prototype_t(""))

                    ret_type = cpp_patterns.from_pattern(cpp_info) \
                               if cpp_info else None
                    if ret_type:
                        log_debug("==== Return type from C++/Doxygen: \"%s\"" % ret_type)
                        for p in assembled.prototypes:
                            p.replace_return_type(ret_type)
                    else:
                        have_pyobject = any(p.get_return_type() == "PyObject *" \
                                            for p in assembled.prototypes)
                        if have_pyobject:
                            runtime_type = self.traces.suggest_return_type(long_name)
                            if runtime_type:
                                log_debug("==== Return type from runtime trace: \"%s\"" \
                                      % runtime_type)
                                for p in assembled.prototypes:
                                    if p.get_return_type() == "PyObject *":
                                        p.replace_return_type(runtime_type)

                    def replace(cmt):
                        for p in cmt.prototypes:
                            n = assembled.match_prototype(p)
                            if n < 0:
                                continue
                            log_debug("==== Matched prototype # %d, replaced" % n)
                            assembled.replace_after_prototype(n, p)

                    # SWIG has precedence
                    if swig_cmt.parsed:
                        log_debug("==== Taking from swig:")
                        replace(swig_cmt)
                    elif doxy_cmt.parsed:
                        log_debug("==== Taking from doxygen:")
                        replace(doxy_cmt)

                    if info.parent:
                        hook = doxy.get_hook_info(info.parent.name)
                        if hook:
                            assembled.ignore_parameters(
                                hook.ignore_parameters.get(info.name))

                    out_comment = assembled.total()
                    log_debug("==== Final comment:\n" + out_comment)
                    if out_comment:
                        f.write(quote_open)
                        f.write(self._indent(indent, out_comment))
                        f.write(quote_close)
                    else:
                        log_debug("==== (Empty, not written)")

                    if info.doc:
                        if skip_upto == lineno:
                            skip_upto = NOT_SKIPPING
                    else:
                        # no comment at source: the start line is actual code
                        f.write(line + "\n")
                        skip_upto = NOT_SKIPPING

                    by_line = by_line[1:]
                    continue

                if skip_upto == NOT_SKIPPING:
                    f.write(line + "\n")
                else:
                    if skip_upto == lineno:
                        skip_upto = NOT_SKIPPING
                    continue

        self._final_check(tree, outfile)

    class simplifier_t(ast.NodeVisitor):
        # Produce a simplified version of the AST
        # (flattened list, containing ony node names)
        # but without any string node
        # (it is not enough to leave a "Str" name without string content;
        #  some docstring may have been removed).
        # Expr nodes are also removed; docstrings are an Expr(Str()),
        # and Exprs containing something more complex will show the interior nodes.

        def simplify(self, subtree):
            self.output = []
            self.generic_visit(subtree)

            return self.output

        def visit(self, node):
            if not isinstance(node, (ast.Str, ast.Expr)):
                self.output.append(node.__class__.__name__)

            super(pydoc_patcher_t.simplifier_t, self).generic_visit(node)

    def _final_check(self, tree, outfile):
        # check that we produced valid Python code

        with open(outfile, "r") as f:
            try:
                # part 1: can it be parsed?
                final_tree = ast.parse(f.read())

                # part 2: basic AST comparison
                simpl = pydoc_patcher_t.simplifier_t()
                if simpl.simplify(tree) != simpl.simplify(final_tree):
                    raise process_exception_t("Final AST comparison failed!")

            except Exception as ex:
                message = ex.__class__.__name__ + ": " + str(ex)
                raise pysyntax_exception_t(message, outfile)

    def _indent(self, indent, text):
        lines = text.split("\n")
        lines = [(indent + line if line.strip() else "") \
                 for line in lines]

        return "\n".join(lines)

    def _long_name(self, info):
        if info.parent:
            return self._long_name(info.parent) + "." + info.name

        return info.name

    def _sort_docstrings(self, visitor):
        docs = []

        self._add_to_docs(visitor, docs)

        for info in visitor.classes.values():
            docs.append( (KIND_CLASS, info) )

            self._add_to_docs(info, docs)

        return sorted(docs, key=lambda pair: pair[1].location.start_line)

    def _add_to_docs(self, obj, docs):
        for info in obj.functions.values():
            docs.append( (KIND_FUNCTION, info) )

        for info in obj.variables.values():
            docs.append( (KIND_VARIABLE, info) )

# --------------------------------------------------------------------------
# Runtime info from calls to the IDAPython API,
# collected during special tests (t2 uitests ... --trace-idapython-calls)
# and gathered together in one file by tools/collect_traces.py.
# The name of this one file is passed to the program on the --traces option.

class call_traces_t(object):
    def load(self, path):
        if not path or not os.path.exists(path):
            self.traces = {}
            return

        with open(path, "r") as f:
            content = ast.literal_eval(f.read())

            self.traces = {}
            for key in content:
                data = content[key]
                if key == "#empty":
                    # entry with special format
                    for fun in data:
                        self.traces[fun] = set(self._str(x) for x in data[fun])
                else:
                    self.traces[key] = set(self._str(x) for x in data["return"])

    def _str(self, expr):
        if isinstance(expr, list):
            return "[" + ", ".join(self._str(x) for x in expr) + "]"
        if isinstance(expr, tuple):
            if len(expr) == 1:
                return "(" + self._str(expr[0]) + ",)"
            return "(" + ", ".join(self._str(x) for x in expr) + ")"

        return str(expr)

    def suggest_return_type(self, long_name):
        key = args.module + "." + long_name

        if key not in self.traces:
            return None

        # type [, type ...] [or None]

        return_set = self.traces[key]
        none_repr = "NoneType"
        if none_repr in return_set:
            suffix = " or None"
            return_set.remove(none_repr)
        else:
            suffix = ""

        types = ", ".join(sorted(return_set))
        if not types:
            return None

        return types + suffix

# --------------------------------------------------------------------------
# Exceptions to the general rule.

class cases_t(object):
    def load(self, path):
        if args.cases:
            with open(path, "r") as f:
                self.cases = ast.literal_eval(f.read())
        else:
            self.cases = {}

        for fun in self.cases:
            self.cases[fun] = case_t(fun, self.cases[fun])

    def get(self, long_name):
        key = args.module + "." + long_name

        return self.cases[key] if key in self.cases else None

# --------------------------------------------------------------------------
# Special case for one symbol.

class case_t(object):
    def __init__(self, symbol, items):
        self.symbol = symbol
        self.items  = items

        for item in items:
            if "param" in item:
                item["param"] = set(item["param"].split("|"))
            if "change" in item:
                item["change"] = self._to_function(item["change"])

    def _to_function(self, code_text):
        code_fun_name = "__INJECT_PYDOC__case"

        code     = ast.parse(code_text.strip())
        module   = ast.parse("def %s(_):\n pass" % code_fun_name)
        function = module.body[0]
        function.body = code.body

        scope  = {}
        exec(compile(module, "<case %s>" % self.symbol, "exec"), scope)

        return scope[code_fun_name]

    def ignore_parameter(self, name):
        # supercedes any special case
        for item in self.items:
            if "param" in item and name in item["param"]:
                if len(item["param"]) == 1:
                    # an action for just this parameter. Hijack it
                    item["ignore"] = True
                else:
                    # remove the parameter from this action, add a new one
                    item["param"].remove(name)
                    self._append_ignore_action(name)
                break
        else:
            # add exception
            self._append_ignore_action(name)

    def _append_ignore_action(self, name):
        self.items.append({
            "param" : set([name]),
            "ignore" : True
        })

    def is_parameter_ignored(self, name):
        item = self._get_param_action(name)

        return item and item.get("ignore", False)

    def change_param(self, name, desc):
        item = self._get_param_action(name)
        if item:
            change = item.get("change")
            if change:
                name, desc = change([name, desc])

        return name, desc

    def _get_param_action(self, name):
        for item in self.items:
            if "param" in item and name in item["param"]:
                return item
        return None

    def doxy_kind(self, kind):
        attr = "doxy-kind"
        for item in self.items:
            if attr in item:
                return item[attr]
        return kind

# --------------------------------------------------------------------------
# A function prototype, plus parameters and some text around.

class prototype_t(object):
    RE_PARAM = re.compile(r" *([A-Za-z0-9_]+)(?: *=.*?)? *([\),])")

    def __init__(self, *parts):
        self.proto   = list(parts)  # [0] name, [1] parameters, [2] return type
        self.after   = ""
        self.params  = []
        self.ctypes  = {}
        self.inter   = []  # text after each parameter
        self.retn    = ""
        self.ignored = False

        self._split_params_in_proto()

    def _split_params_in_proto(self):
        self.param_names = []

        if len(self.proto) < 2:
            return

        start = 1  # parameter list; skip "(" at 0
        while True:
            m = self.RE_PARAM.match(self.proto[1], start)
            if not m:
                break

            name, delimiter = m.groups()
            if name[0] == "_" and len(name) > 1:    # "self", not "_self"
                name = name[1:]
            self.param_names.append(name)

            if delimiter == ")":
                break
            start = m.end()

    def get_return_type(self):
        if len(self.proto) < 2:
            return None

        return self.proto[-1]

    def replace_return_type(self, ret_type):
        if len(self.proto) < 2:
            return  # no-op for dummy prototypes

        if len(self.proto) == 2:
            self.proto.append(ret_type)
        else:
            self.proto[-1] = ret_type

    def text_after_proto(self, line):
        self.after += line + "\n"

    def add_parameter(self, *parts):
        self.params.append(parts)
        self.inter .append("")

    def add_cpp_param(self, name, ctype):
        self.ctypes[name] = ctype

    def text_after_last_param(self, line):
        self.inter[-1] += line + "\n"

    def text_return(self, line):
        self.retn += line + "\n"

    def clone(self):
        copy = prototype_t(*self.proto)
        copy.ctypes = dict(self.ctypes)
        copy.after  = self.after
        copy.retn   = self.retn

        for p, t in zip(self.params, self.inter):
            copy.params.append(tuple(p))
            copy.inter .append(t)

        return copy

    def total(self, case=None):
        # ignored? (typically from assembled_comment_t._clear_repeats)
        if self.ignored:
            return ""

        part_1 = self.repr_proto() \
               + self._clean(self.after)

        part_2 = ""
        for p, t in zip(self.params, self.inter):
            # note: not cleaning texts after parameters ("t")
            #       to preserve some of the original formatting

            if self._is_parameter_ignored(p, case):
                repr_p = ""
                text_p = []
                for line in t.split("\n"):
                    # remove text associated to an ignored parameter,
                    # but stop removing on the next @tag
                    # (which may be other than @param)

                    if text_p:
                        text_p.append(line)
                    else:
                        line_text = line.lstrip()
                        if line_text and line_text[0] == "@":
                            text_p.append(line)
                t = "\n".join(text_p)
            else:
                repr_p = self._repr_param(p, case)

            part_2 += repr_p + t

        clean_retn = self._clean(self.retn)
        if clean_retn:
            part_2 += "@return: " + clean_retn

        return "\n".join(part for part in (part_1, part_2) if part)

    def _is_parameter_ignored(self, parts, case):
        if not case:
            return False

        _, name, _ = parts
        return case.is_parameter_ignored(name)

    def _repr_param(self, parts, case):
        indent, name, desc = parts

        if case:
            name, desc = case.change_param(name, desc)

        text = indent + "@param " + name
        if name.startswith("NONNULL_") and not name in self.ctypes:
            name = name[8:]
        if name in self.ctypes:
            if desc == self.ctypes[name]: # avoid some duplication
                desc = ""
            desc = ("(C++: %s)" % self.ctypes[name]) \
                 + (" " if desc else "") + desc
        if desc:
            text += ": " + desc

        return text + "\n"

    def _clean(self, text):
        cleaned = text.strip("\n")
        if cleaned:
            cleaned += "\n"
        return cleaned

    def repr_proto(self):
        if not self.proto[0]:
            return ""

        if len(self.proto) == 1:
            log_verb("Internal error, prototype with only 1 part: %s"
                 % repr(self.proto))
            return self.proto[0] + "\n"

        if len(self.proto) == 2:
            return "".join(self.proto) + "\n"

        return "".join(self.proto[:-1]) \
             + " -> " + self.proto[-1] + "\n"

# --------------------------------------------------------------------------
# Class to split a docstring into parts (prototype, parameter information, etc.)
#
# Docstrings are considered to be of the form:
#   (prototype, optionally parameters) repeated zero or more times,
#   with arbitrary text anywhere in-between.
#
# Prototypes are required to have NO space between function name and
# open parenthesis, otherwise many texts would look like a prototype.

class structured_comment_t(object):

    WORD       = r"[A-Za-z_][A-Za-z0-9_]*"
    PROTO_HEAD = r"(%s)(\(.*?\))" % WORD

    RE_WORD   = re.compile(WORD)
    RE_PARAM  = re.compile(r"(%s) *: *([< ]*%s.*)" % (WORD, WORD))
    RE_PROTO1 = re.compile(PROTO_HEAD + r"$")
    RE_PROTO2 = re.compile(PROTO_HEAD + r" *-> *(.*)")
    RE_TITLE  = re.compile(r"[Pp]arameters? *:?$")  # Parameters
    RE_DASHES = re.compile(r"-+$")                  # ----------
    RE_INDENT = re.compile(r" *")

    PAT_NONE   = 0
    PAT_PROTO  = 1
    PAT_PARAM  = 2
    PAT_TITLE  = 3
    PAT_RETURN = 4
    PAT_TEXT   = 5

    def __init__(self, always_a_prototype=False):
        self.always_a_prototype = always_a_prototype

        self.reset()
        self.parsed = False

    def reset(self):
        self.text_before = ""
        self.prototypes  = []
        self.ctypes      = {}  # collected for only one prototype in Doxygen

    def parse(self, text, parse_prototypes=True):
        self.reset()
        self.parsed = True

        lines = text.split("\n") if text else [""]
        prev  = self.PAT_NONE
        state = self.PAT_NONE # used to decide where to store text
                              # (after the prototype, or after a parameter)

        if self.always_a_prototype:
            self.prototypes.append(prototype_t(""))
            state = self.PAT_PROTO

        for line in lines:
            pat  = self._pattern(line, prev, parse_prototypes)
            prev = pat

            if pat == self.PAT_TITLE:
                continue

            if pat == self.PAT_PROTO:
                self.prototypes.append(prototype_t(*self.parts))

            elif pat == self.PAT_PARAM:
                if not self.prototypes:
                    self.prototypes.append(prototype_t(""))
                self.prototypes[-1].add_parameter(*self.parts)

            elif pat == self.PAT_RETURN:
                if not self.prototypes:
                   self.prototypes.append(prototype_t(""))
                self.prototypes[-1].text_return(self.parts[0])

            elif pat == self.PAT_TEXT:
                if self.prototypes:
                    if state == self.PAT_PROTO:
                        self.prototypes[-1].text_after_proto(line)
                    elif state == self.PAT_PARAM:
                        self.prototypes[-1].text_after_last_param(line)
                    elif state == self.PAT_RETURN:
                        self.prototypes[-1].text_return(line)
                    else:
                        self.text_before += line + "\n"
                else:
                    self.text_before += line + "\n"

            if pat in (self.PAT_PROTO, self.PAT_PARAM, self.PAT_RETURN):
                state = pat

    def _pattern(self, line, prev, parse_prototypes):
        # may also return extra information in self.parts

        indent = self.RE_INDENT.match(line).group(0)
        line   = line.strip()

        if line.startswith("@"):
            m = self.RE_WORD.search(line, 1)
            if m:
                tag = m.group(0)
                if tag == "param":
                    m = self.RE_WORD.search(line, m.end())
                    if m:
                        self.parts = indent, m.group(0), \
                                     self._rest_after_colon(line, m)
                        return self.PAT_PARAM
                    raise process_exception_t("No word after @param: " + line)
                if tag == "return":
                    self.parts = (self._rest_after_colon(line, m),)
                    return self.PAT_RETURN
                else:
                    return self.PAT_TEXT

            log_verb("Missing or invalid tag after \"@\": " + line)
            return self.PAT_TEXT

        if self.RE_TITLE.match(line) or self.RE_DASHES.match(line):
            return self.PAT_TITLE

        m = self.RE_PARAM.match(line)
        if m and prev != self.PAT_TEXT:
            self.parts = (indent,) + m.groups()
            return self.PAT_PARAM

        if not indent and parse_prototypes:
            for re in (self.RE_PROTO1, self.RE_PROTO2):
                m = re.match(line)
                if m:
                    self.parts = m.groups()
                    return self.PAT_PROTO

        return self.PAT_TEXT

    def _rest_after_colon(self, line, m):
        rest = line[m.end():].strip()
        if rest and rest[0] == ":":
            rest = rest[1:].lstrip()
        return rest

    def add_cpp_params(self, plist):
        if plist is None:
            return
        proto = self.prototypes[-1]
        for name, ctype in plist:
            proto.add_cpp_param(name, ctype)

    def total(self):
        # used only for debug output;
        # no notion of "special cases" passed to prototype_t.total()

        text = self.text_before
        if text:
            text = "\n" + text

        protos = "\n".join(p.total() for p in self.prototypes)
        if protos:
            protos = "\n" + protos

        return text + protos

# --------------------------------------------------------------------------
class assembled_comment_t(object):
    def __init__(self, case):
        self.case        = case
        self.text_before = ""
        self.prototypes  = []

    def add_text_before(self, text):
        self.text_before += text

    def add_prototype(self, prototype):
        self.prototypes.append(prototype.clone())

    def match_prototype(self, given):
        for i in range(len(self.prototypes)):
            if self._match(self.prototypes[i], given):
                return i
        return -1

    # add more detail if needed
    def _match(self, p1, p2):
        t1 = tuple(p1.proto)
        t2 = tuple(p2.proto)

        if t1 == ("",) or t2 == ("",):
            # wildcard - possibly coming from structured_comment_t(True)
            return True

        return t1 == t2

    def replace_after_prototype(self, i, given):
        proto = self.prototypes[i]
        if tuple(proto.proto) == ("",):
            proto.proto       = given.proto
            proto.param_names = given.param_names
        proto.ctypes = given.ctypes
        proto.after  = given.after
        proto.retn   = given.retn

        # replace only the parameters that match the prototype

        old_params = proto.params
        old_inter  = proto.inter
        proto.params = []
        proto.inter  = []

        names_in_proto = proto.param_names
        if len(names_in_proto) > 1 and names_in_proto[0] == "self":
            names_in_proto = names_in_proto[1:]

        given_params = self._params_fix(given.params, names_in_proto)

        NAME = 1
        index_old   = { old_params[i][NAME]   : (old_params[i], old_inter[i]) \
                                                for i in range(len(old_params)) }
        index_given = { given.params[i][NAME] : (given.params[i], given.inter[i]) \
                                                for i in range(len(given.params)) }

        selected = set()
        for i in range(len(names_in_proto)):
            param, inter = self._choose_param(i, names_in_proto,
                            given.params, given.inter, index_given,
                            old_params,   old_inter,   index_old)
            if param is not None:
                selected.add(param[NAME])
                proto.params.append(param)
                proto.inter .append(inter)

        # extra given parameters (not in the prototype)
        # are added but marked as ignored,
        # so that additional @tags in the inter-text can be displayed

        for i in range(len(names_in_proto), len(given.params)):
            name = given.params[i][NAME]
            if name not in selected:
                log_debug("Param %d: ignored \"%s\"" % (i, name))
                self.ignore_parameter(name)
                proto.params.append(given.params[i])
                proto.inter .append(given.inter [i])

    def _params_fix(self, given_params, names_in_proto):
        # make "py_XXX" match "XXX"

        NAME = 1
        for i in range(min(len(names_in_proto), len(given_params))):
            given_param = list(given_params[i])
            in_proto    = names_in_proto[i]

            if in_proto[:3] == "py_" and in_proto[3:] == given_param[NAME]:
                given_param[NAME] = in_proto
                given_params[i] = tuple(given_param)

    def _choose_param(self, i, names_in_proto,
                            given_params, given_inter, index_given,
                            old_params,   old_inter,   index_old):
        def safe_index(i, arr):
            return arr[i] if i < len(arr) else None

        in_proto = names_in_proto[i]

        # use a name if recognized, even if not in order
        if in_proto in index_given:
            given_param, given_inter = index_given[in_proto]
        else:
            given_param = safe_index(i, given_params)
            given_inter = safe_index(i, given_inter)

        if in_proto in index_old:
            old_param, old_inter = index_old[in_proto]
        else:
            old_param = safe_index(i, old_params)
            old_inter = safe_index(i, old_inter)

        NAME = 1
        DESC = 2

        log_debug("Param %d: in prototype \"%s\", original doc \"%s\", given doc \"%s\""
              % (i, in_proto, old_param[NAME] if old_param else "",
                              given_param[NAME] if given_param else ""))

        if given_param is None:
            if old_param:
                log_debug("- choosing old \"%s\" because none given" % old_param[NAME])
            return old_param, old_inter

        # make "py_XXX" match "XXX"
        given_param = list(given_param)
        if in_proto[:3] == "py_" and in_proto[3:] == given_param[NAME]:
            given_param[NAME] = in_proto
        given_param = tuple(given_param)

        if in_proto == "" or given_param[NAME] == in_proto:
            log_debug("- choosing given \"%s\"" % given_param[NAME])
            return given_param, given_inter

        if old_param is None:
            log_debug("- no match")
            return None, None

        # even if there is no match,
        # choose data if it appears to be more informative

        if len(old_param[NAME]) <= 2 and len(given_param[NAME]) > 2:
            log_debug("- choosing given \"%s\" because of short name \"%s\""
                  % (given_param[NAME], old_param[NAME]))
            return given_param, given_inter

        if len(given_param[NAME]) <= 2 and len(old_param[NAME]) > 2:
            log_debug("- choosing old \"%s\" because of short name \"%s\""
                  % (old_param[NAME], given_param[NAME]))
            return old_param, old_inter

        if len(given_param[DESC]) > 3 * len(old_param[DESC]):
            log_debug("- choosing given \"%s\" because it has more text"
                  % given_param[NAME])
            return given_param, given_inter

        if old_param:
            log_debug("- no good match, choosing old \"%s\""
                  % old_param[NAME])
        return old_param, old_inter

    def ignore_parameters(self, ignore_set):
        if ignore_set:
            for name in ignore_set:
                self.ignore_parameter(name)

    def ignore_parameter(self, name):
        if self.case is None:
            self.case = case_t("", [])
            # assembled_comment_t operates at the very end of the process;
            # there is likely no need to store this dummy case_t in the
            # dictionary of cases for all symbols (inside pydoc_patcher_t)

        self.case.ignore_parameter(name)

    def total(self):
        self._clear_repeats()
        return self.text_before + "".join(p.total(self.case) \
                                          for p in self.prototypes)

    def _clear_repeats(self):
        unique = set()
        for p in self.prototypes:
            tuple_p = tuple(p.proto)
            if tuple_p in unique:
                p.ignored = True
            else:
                unique.add(tuple_p)

# --------------------------------------------------------------------------
def main():
    if args.debug:
        log_level = LOG_LEVEL_DEBUG
    elif args.verbose:
        log_level = LOG_LEVEL_VERB

    log_info("Collecting from: %s" % args.interface)
    with new_log_indent_t():
        swig = swig_pydoc_collector_t()
        swig.collect(args.interface)

    log_info("Collecting from: %s" % args.cpp_wrapper)
    with new_log_indent_t():
        cpp = cpp_wrapper_parser_t()
        cpp.collect(args.cpp_wrapper)

    log_info("Collecting from: %s" % args.xml_doc_directory)
    with new_log_indent_t():
        doxy = doxygen_info_t(args.xml_doc_directory)
        doxy.load_hooks()
        doxy.load(args.module)

    extra_sources = swig, cpp, doxy

    log_info("Patching")
    with new_log_indent_t():
        patcher = pydoc_patcher_t()
        patcher.patch(args.input, extra_sources, args.output)

main()
