
import ast

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
ALL_KINDS = [
    KIND_CLASS,
    KIND_UNION,
    KIND_STRUCT,
    KIND_FUNCTION,
    KIND_VARIABLE,
    KIND_DEFINE,
    KIND_FILE,
]

# --------------------------------------------------------------------------
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

    def visit_AnnAssign(self, node):
        return self.visit_Assign(node)

    def visit_Assign(self, node):
        if self.in_func:
            return

        self.assign_line = location_t.last_line(node)
        # unless stated otherwise
        self.assign_warn = self.WARN_ON_VARIABLE

        # only syntax accepted: var = expr or self.member = expr
        # (as opposed to v1 = v2 = expr, or var += expr, or obj.member = expr)

        if isinstance(node, ast.Assign):
            if len(node.targets) != 1:
                return
            target = node.targets[0]
        else:
            target = node.target

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

        if isinstance(node.value, ast.Constant):
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

                docstring = self._clean_docstring(node.value.value)

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
