
import ast
import os

import pypasses

def process(tree, opts, logger):

    if not os.path.isfile(opts.pydoc_overrides):
        return tree

    #
    # Collect docstrings from the overrides
    #
    class overrides_visitor_t(pypasses.base_visitor_t):

        def __init__(self, module_name):
            super(overrides_visitor_t, self).__init__(module_name)

            # we'll be storing documentation items as kvp's
            # where the key is the "path" to the item (e.g.,
            # `ida_typeinf.tinfo_t.get_udm`.
            self.doc_items = {}

        def _register_doc(self, node):
            ds = self._get_docstring(node)
            if ds:
                path = ".".join(self.current_path + [node.name])
                logger.debug(f"Registering \"{path}\"")
                self.doc_items[path] = ds

        def _get_docstring(self, node):
            return ast.get_docstring(node, clean=True)

        def visit_ClassDef(self, node):
            self._register_doc(node)
            return super(overrides_visitor_t, self).visit_ClassDef(node)

        def visit_FunctionDef(self, node):
            self._register_doc(node)
            return super(overrides_visitor_t, self).visit_FunctionDef(node)


    with open(opts.pydoc_overrides) as fin:
        overrides_tree = ast.parse(fin.read(), filename=opts.pydoc_overrides)
    overrides = overrides_visitor_t(opts.idapython_module_name)
    overrides.visit(overrides_tree)

    #
    # And apply it to the input
    #
    class source_transformer_t(pypasses.base_visitor_t):
        def __init__(self, module_name, overrides_kvps):
            super(source_transformer_t, self).__init__(module_name)
            self.overrides_kvps = overrides_kvps

        def _restore_doc(self, node):
            path = ".".join(self.current_path + [node.name])
            got = self.overrides_kvps.get(path, None)
            if got is not None:
                logger.debug(f"Found override for \"{path}\"")
                pypasses.set_docstring(node, got)
            return node

        def visit_ClassDef(self, node):
            node = self._restore_doc(node)
            super(source_transformer_t, self).visit_ClassDef(node)
            return node

        def visit_FunctionDef(self, node):
            node = self._restore_doc(node)
            super(source_transformer_t, self).visit_FunctionDef(node)
            return node

    transformer = source_transformer_t(opts.idapython_module_name, overrides.doc_items)
    transformer.visit(tree)

    return tree
