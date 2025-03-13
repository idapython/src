
import ast

import pypasses

REPLS = {
    ast.Constant("sval_t") : ast.Name("int"),
    ast.Constant("uval_t") : ast.Name("int"),
    ast.Constant("int32") : ast.Name("int"),
    ast.Constant("uint32") : ast.Name("int"),
    ast.Constant("int") : ast.Name("int"),
    ast.Constant("bool") : ast.Name("bool"),
    ast.Constant("void") : ast.Name("None"),
    ast.Constant("ea_t") : ast.Name("ida_idaapi.ea_t"),

    ast.Constant("qstring") : ast.Name("str"),
    ast.Constant("qstring const &") : ast.Name("str"),
    ast.Constant("qstring &") : ast.Name("str"),
    ast.Constant("qstring const *") : ast.Name("str"),
    ast.Constant("qstring *") : ast.Name("str"),
    ast.Constant("const char *") : ast.Name("str"),
    ast.Constant("char const *") : ast.Name("str"),
}

def _node_eq(n0, n1):
    t0 = type(n0)
    if t0 == type(n1):
        if t0 == ast.Constant:
            if n0.value == n1.value:
                return True
        else:
            raise Exception(f"Unknown annotation type: {n0}")
    return False

def find_annotation_replacement(node):
    for key, value in REPLS.items():
        if _node_eq(key, node):
            return value


def process(tree, opts, logger):

    class source_transformer_t(pypasses.base_transformer_t):

        def visit_arg(self, node):
            if node.annotation is not None:
                repl = find_annotation_replacement(node.annotation)
                if repl is not None:
                    node = ast.arg(node.arg, repl, node.type_comment)
            return node

        def visit_FunctionDef(self, node):
            if node.returns:
                repl = find_annotation_replacement(node.returns)
                if repl is not None:
                    node.returns = repl
            self.generic_visit(node)
            return node

    transformer = source_transformer_t(opts.idapython_module_name)
    transformer.visit(tree)

    return tree
