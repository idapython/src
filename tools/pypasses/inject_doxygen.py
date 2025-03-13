
import ast
import os

import pypasses

def process(tree, opts, logger):

    class source_transformer_t(pypasses.base_transformer_t):

        class new_scope_t(object):
            def __init__(self, transformer, scope):
                self.transformer = transformer
                self.scope = scope

            def __enter__(self):
                self.transformer.dx_scope.append(self.scope)

            def __exit__(self, exc_type, exc_value, traceback):
                self.transformer.dx_scope.pop()
                if exc_value:
                    raise

        def __init__(self, module_name, dx_module):
            super(source_transformer_t, self).__init__(module_name)
            self.dx_scope = [dx_module]

        def _append_descriptions(self, dx_source, storage):
            if dx_source.brief_description:
                storage.append(dx_source.brief_description)
                storage.append("")
            if dx_source.detailed_description:
                storage.append(dx_source.detailed_description)

        def _handle_assign(self, node, target):
            ds_node = None
            if isinstance(target, ast.Name):
                dx_var = self.dx_scope[-1].find_variable(target.id)
                if dx_var:
                    logger.debug(f"Found documentation for assignment '{ast.dump(node)}': {dx_var}")
                    text = []
                    self._append_descriptions(dx_var, text)
                    if text:
                        ds_node = ast.Expr(value=ast.Str("\n".join(text)))
            return [node, ds_node] if ds_node else node

        def visit_AnnAssign(self, node: ast.AnnAssign):
            return self._handle_assign(node, node.target)

        def visit_Assign(self, node: ast.Assign):
            if len(node.targets) != 1:
                return node
            return self._handle_assign(node, node.targets[0])

        def visit_ClassDef(self, node):
            dx_class = self.dx_scope[-1].find_class(node.name)
            if dx_class:
                text = []
                self._append_descriptions(dx_class, text)
                if text:
                    pypasses.set_docstring(node, "\n".join(text))
                with self.new_scope_t(self, dx_class):
                    super(source_transformer_t, self).visit_ClassDef(node)
            else:
                super(source_transformer_t, self).visit_ClassDef(node)
            return node

        def visit_Module(self, node):
            dx_module = self.dx_scope[-1]
            if dx_module:
                text = []
                self._append_descriptions(dx_module, text)
                if text:
                    ds_node = ast.Expr(value=ast.Str("\n".join(text)))
                    node.body.insert(0, ds_node)
            self.generic_visit(node)
            return node

        def _map_argument_names_to_doxygen_info_and_derive_tags(
                self,
                dx_source,
                storage,
                arg_names):
            self._append_descriptions(dx_source, storage)
            args_and_return = []

            for arg_name in arg_names:
                if arg_name == "self":
                    continue
                dx_param = dx_source.find_parameter_by_name(arg_name)
                # if there's no description, no point in wasting space
                if dx_param and dx_param.description:
                    args_and_return.append(f"@param {arg_name}: {dx_param.description}")

            if dx_source.return_info and dx_source.return_info.description:
                args_and_return.append(f"@returns {dx_source.return_info.description}")

            for retval_value, retval_desc in dx_source.return_info.retvals:
                args_and_return.append(f"@retval {retval_value}: {retval_desc}")

            if args_and_return:
                storage.extend(args_and_return)

        def _is_likely_SWiG_dispatcher(self, node):
            """
            A SWiG polymorphism dispatcher will look like so:

              * def inf_huge_arg_align(*args) -> "bool"
              * def find_member(self, *args) -> "ssize_t"

            IOW:
              1. must not have regular args except for 'self'
              2. must have a vararg called 'args'
              3. must not have kwargs
            """

            # 1.
            for arg in node.args.args:
                if arg.arg != "self":
                    return False

            # 2.
            if not node.args.vararg or node.args.vararg.arg != "args":
                return False

            # 3.
            if node.args.kwarg:
                return False

            return True

        def _full_dx_scope_path(self, name):
            return ".".join(map(lambda s: s.name, self.dx_scope)) + "." + name

        def _process_type(self, type_text):
            from pypasses.proto_fix_known_types import find_annotation_replacement as far
            found = far(ast.Constant(type_text))
            if found:
                assert isinstance(found, ast.Name)
                type_text = found.id
            return type_text

        def visit_FunctionDef(self, node):
            logger.debug(f"Looking for: {self._full_dx_scope_path(node.name)}")
            dx_fun = self.dx_scope[-1].find_function(node.name)
            if dx_fun:
                logger.debug(f"Found doxygen function information")
                text = []
                arg_names = list(map(lambda a: a.arg, node.args.args))

                # If we have more than 1 flavor, it is either:
                #   - a polymorphic function
                #   - a function with default parameters
                # Let's check if SWiG was led to implement polymorphism (will use
                # `*args` in that case), or if it turns out we `%ignore`'d some and
                # thus have only one prototype in the Python bindings.
                if len(dx_fun.flavors) == 1 and self._is_likely_SWiG_dispatcher(node):
                    logger.debug(f"{self._full_dx_scope_path(node.name)} is a defarg-caused dispatcher")
                    # In this case, the prototype is pretty damn boring, and
                    # won't tell us much (i.e.,  `def thing(*args)`).
                    # We still want a list of tags though.
                    arg_names = list(map(lambda p: p.name, dx_fun.flavors[0].parameters))

                if len(dx_fun.flavors) > 1 and self._is_likely_SWiG_dispatcher(node):
                    logger.debug(f"{self._full_dx_scope_path(node.name)} is a dispatcher")
                    text.append("This function has the following signatures:")
                    text.append("")
                    for idx, flavor in enumerate(dx_fun.flavors):
                        text.append(f"    {idx}. {dx_fun.compose_prototype_string(flavor, self._process_type)}")
                    text.append("")
                    for idx, flavor in enumerate(dx_fun.flavors):
                        text.append(f"# {idx}: {dx_fun.compose_prototype_string(flavor, self._process_type)}")
                        text.append("")
                        self._map_argument_names_to_doxygen_info_and_derive_tags(flavor, text, arg_names)
                        if idx < len(dx_fun.flavors):
                            text.append("")
                else:
                    self._map_argument_names_to_doxygen_info_and_derive_tags(dx_fun.flavors[0], text, arg_names)
                if text:
                    pypasses.set_docstring(node, "\n".join(text))
            super(source_transformer_t, self).visit_FunctionDef(node)
            return node

    if opts.dx_module:
        transformer = source_transformer_t(
            opts.idapython_module_name,
            opts.dx_module)
        transformer.visit(tree)

    return tree
