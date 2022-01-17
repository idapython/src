#!/usr/bin/python3

import glob
import os
import sys
import ast
import re

class args_t:
    def __init__(self, static):
        self.static = static

try:
    import idaapi
    # running as f.i.: idat -B -t -Scompare_traces.py -Loutput.log
    args = args_t(False)
except:
    # running stand-alone - static analysis
    args = args_t(True)

#-----------------------------------------------------------------------
# used by default, if no option -s

class runtime_analysis_t:
    def load(self):
        self._import_all_idapython()

        self.funcs = set()
        for module in self._idapython_modules():
            self.level = [module.__name__]
            self._examine(module)

    # a variation of tests/t2/phases/tests/trace_idapython_calls_idapythonrc.py,
    # idapython_wrapper_t._wrap()

    def _examine(self, obj):
        for name in dir(obj):
            # ignore "internals" for now
            if name.startswith("_"):
                continue
            if name not in obj.__dict__:
                continue

            child = obj.__dict__[name]  # different from getattr(...)

            if not hasattr(child, "__class__"): # f.i. SWIG's cvar, "C global variable"
                continue
            typename = child.__class__.__name__

            if typename == "type": # class
                self.level.append(name)
                self._examine(child)
                self.level.pop()
            elif typename in ("function", "staticmethod"):
                self.funcs.add(".".join(self.level + [name]))

    def _import_all_idapython(self):
        for name in os.listdir(os.path.dirname(idaapi.__file__)):
            name, ext = os.path.splitext(name)
            if name.startswith("ida_") and ext == ".py":
                __import__(name)

    def _idapython_modules(self):
        for name in sorted(sys.modules):
            if name.startswith("ida_"):
                yield sys.modules[name]

#-----------------------------------------------------------------------
# used only on option -s

class static_analysis_t(ast.NodeVisitor):
    def __init__(self):
        super().__init__()

    def load(self, basedir):
        self.funcs = set()
        for pathname in glob.glob(os.path.join(basedir, "ida_*.py")):
            self._examine(pathname)

    def _examine(self, pathname):
        module, _ = os.path.splitext(os.path.basename(pathname))

        with open(pathname, "r") as f:
            tree = ast.parse(f.read())

        self.level = [module]
        self.generic_visit(tree)

    def visit_ClassDef(self, node):
        self.level.append(node.name)
        super().generic_visit(node)
        self.level.pop()

    def visit_FunctionDef(self, node):
        if node.name.startswith("_") and not node.name.startswith("__"):
            return

        self.funcs.add(".".join(self.level + [node.name]))
        # skip entering the node's body

#-----------------------------------------------------------------------
class call_traces_t(object):
    def load(self, path):
        with open(path, "r") as f:
            content = ast.literal_eval(f.read())

            self.funcs = set()
            prefix = "ida_"
            for key in content:
                if key == "#empty":
                    for fun in content[key]:
                        self.funcs.add(prefix + fun)
                else:
                    self.funcs.add(prefix + key)

#-----------------------------------------------------------------------
def compare(analysis_funcs, runtime_funcs):
    check_diff = runtime_funcs - analysis_funcs
    if check_diff:
        print("? Strange, functions tested but not in the API:")
        for func in sorted(check_diff):
            print(" ", func)

    diff = analysis_funcs - runtime_funcs
    print("Coverage: {:.1f}%".format(
          100 * (1 - len(diff) / len(analysis_funcs))
    ))
    if diff:
        print("Untested functions:")
        for func in sorted(diff):
            print(" ", func)

#-----------------------------------------------------------------------
def get_dirs():
    # TODO
    py_ver   = 3
    this_dir = os.path.dirname(__file__)
    api_dir  = os.path.abspath(os.path.join(
                   this_dir, "..", "..", "..",
                   "bin", "x64_linux_gcc", "python", str(py_ver)
               ))

    return this_dir, api_dir

#-----------------------------------------------------------------------
def main():
    this_dir, api_dir = get_dirs()

    if args.static:
        print("Static analysis...")
        analysis = static_analysis_t()
        analysis.load(api_dir)
    else:
        print("Runtime analysis...")
        analysis = runtime_analysis_t()
        analysis.load()

    print("Reading traces...")
    call_traces = call_traces_t()
    call_traces.load(os.path.join(this_dir, "collected_traces.txt"))

    print("Comparing...")
    compare(analysis.funcs, call_traces.funcs)

    if "idaapi" in sys.modules:
        # running inside idat - get out
        idaapi.qexit(0)

main()
