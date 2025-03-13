
import ast
import os

import pypasses

def process(tree, opts, logger):

    if not os.path.isfile(opts.pydoc_overrides):
        return tree

    #
    # Collect prototypes from the overrides
    #
    class overrides_visitor_t(pypasses.base_visitor_t):

        def __init__(self, module_name):
            super(overrides_visitor_t, self).__init__(module_name)
            self.prototypes = {}

        def _register_proto(self, node):
            path = ".".join(self.current_path + [node.name])
            logger.debug(f"Registering \"{path}\": {node}")
            self.prototypes[path] = node

        def visit_FunctionDef(self, node):
            self._register_proto(node)
            return super(overrides_visitor_t, self).visit_FunctionDef(node)


    with open(opts.pydoc_overrides) as fin:
        overrides_tree = ast.parse(fin.read(), filename=opts.pydoc_overrides)
    overrides = overrides_visitor_t(opts.idapython_module_name)
    overrides.visit(overrides_tree)

    #
    # And apply it to the input
    #
    class source_transformer_t(pypasses.base_transformer_t):
        def __init__(self, module_name, prototypes):
            super(source_transformer_t, self).__init__(module_name)
            self.prototypes = prototypes

        def visit_FunctionDef(self, node):
            path = ".".join(self.current_path + [node.name])
            found = self.prototypes.get(path, None)
            if found is not None:
                logger.debug(f"Found override for \"{path}\"")
                node.args = found.args
                node.returns = found.returns
            self.generic_visit(node)
            return node

    transformer = source_transformer_t(opts.idapython_module_name, overrides.prototypes)
    transformer.visit(tree)

    return tree
