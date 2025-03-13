
import ast

class _new_path_t(object):
    def __init__(self, visitor, path_el):
        self.visitor = visitor
        self.path_el = path_el

    def __enter__(self):
        self.visitor.current_path.append(self.path_el)

    def __exit__(self, exc_type, exc_value, traceback):
        self.visitor.current_path.pop()
        if exc_value:
            raise


class base_visitor_t(ast.NodeVisitor):

    def __init__(self, module_name):
        self.current_path = [module_name]

    def visit_ClassDef(self, node):
        with _new_path_t(self, node.name):
            self.generic_visit(node)

    def visit_FunctionDef(self, node):
        with _new_path_t(self, node.name):
            self.generic_visit(node)


class base_transformer_t(ast.NodeTransformer):

    def __init__(self, module_name):
        self.module_name = module_name
        self.current_path = []

    def visit_Module(self, node):
        assert not self.current_path
        with _new_path_t(self, self.module_name):
            self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        with _new_path_t(self, node.name):
            self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node):
        with _new_path_t(self, node.name):
            self.generic_visit(node)
        return node


def set_docstring(node, text):
    ds_node = ast.Expr(value=ast.Str(text))
    existing_ds = ast.get_docstring(node)
    if existing_ds:
        node.body[0] = ds_node
    else:
        node.body.insert(0, ds_node)
