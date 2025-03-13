
import os
import sys
import xml.etree.ElementTree as ET
import textwrap

COMPOUND_KIND_CLASS = "class"
COMPOUND_KIND_UNION = "union"
COMPOUND_KIND_STRUCT = "struct"

def newlineify(line):
    if not line.endswith("\n"):
        line = line + "\n"
    return line

class tree_visitor_t(object):

    SKIP_TREE = {}

    def __init__(
            self,
            passthrough_elements=[],
            skip_elements=[]):
        if not isinstance(passthrough_elements, list):
            passthrough_elements = [passthrough_elements]
        if not isinstance(skip_elements, list):
            skip_elements = [skip_elements]
        self.passthrough_elements = passthrough_elements
        self.skip_elements = skip_elements

    def _on_any(self, *args):
        pass

    def visit(self, tree):
        if tree.tag not in self.skip_elements:
            on = getattr(self, f"on_{tree.tag}") if tree.tag not in self.passthrough_elements else self._on_any
            if on(tree, True) is not self.SKIP_TREE:
                self.visit_children(tree)
                on(tree, False)

    def visit_children(self, tree):
        for child in tree:
            self.visit(child)


class base_text_collector_visitor_t(tree_visitor_t):

    def __init__(self, *args, **kwargs):
        super(base_text_collector_visitor_t, self).__init__(*args, **kwargs)
        self.text_bits = []

    def newline(self):
        self.text_bits.append("\n")

    def _sanitize_node_text(self, tree, text):
        return text

    def _collect_node_text(self, tree, is_start):
        text = tree.text if is_start else tree.tail
        text = self._sanitize_node_text(tree, text)
        self.text_bits.append(text)

    def clob(self, spacer="", strip=False, remove_empty=False):
        bits = filter(lambda b: b is not None, self.text_bits)
        if strip:
            chars = " " if strip is True else strip
            bits = map(lambda b: b.strip(chars), bits)
        if remove_empty:
            bits = filter(lambda b: b, bits)
        return spacer.join(bits)

    def oneliner_clob(self):
        return self.clob(spacer=" ", strip=" \n\t", remove_empty=True)


class description_text_collector_visitor_t(base_text_collector_visitor_t):

    def on_para(self, tree, is_start):
        class para_text_collector_visitor_t(description_text_collector_visitor_t):
            def on_para(self, tree, is_start):
                self._collect_node_text(tree, is_start)
        v = para_text_collector_visitor_t(
            passthrough_elements=self.passthrough_elements,
            skip_elements=self.skip_elements)
        v.visit(tree)
        # see if there's any content at all in there
        clob = v.oneliner_clob()
        if clob:
            # if yes, let's keep it as-is
            self.text_bits.append(v.clob())
            self.newline
        return self.SKIP_TREE

    def on_linebreak(self, tree, is_start):
        self._collect_node_text(tree, is_start)

    def on_ref(self, tree, is_start):
        self._collect_node_text(tree, is_start)

    def on_ndash(self, tree, is_start):
        if is_start:
            self.text_bits.append("-")
        self._collect_node_text(tree, is_start)

    def on_ulink(self, tree, is_start):
        if is_start:
            self.text_bits.append(f"[{tree.text}]({tree.attrib['url']})")
        else:
            self._collect_node_text(tree, is_start)

    def on_computeroutput(self, tree, is_start):
        if is_start:
            self.text_bits.append("`")
            self._collect_node_text(tree, is_start)
            self.text_bits.append("`")
        else:
            self._collect_node_text(tree, is_start)

    def on_verbatim(self, tree, is_start):
        return self.on_computeroutput(tree, is_start)

    def on_preformatted(self, tree, is_start):
        self._collect_node_text(tree, is_start)

    def on_programlisting(self, tree, is_start):

        class codeline_visitor_t(base_text_collector_visitor_t):
            def __init__(self, *args, **kwargs):
                kwargs["passthrough_elements"] = "highlight"
                super(codeline_visitor_t, self).__init__(*args, **kwargs)

            def on_ref(self, tree, is_start):
                self._collect_node_text(tree, is_start)

            def on_sp(self, tree, is_start):
                if is_start:
                    self.text_bits.append(" ")
                self._collect_node_text(tree, is_start)

        class programlisting_visitor_t(base_text_collector_visitor_t):
            def __init__(self, *args, **kwargs):
                super(programlisting_visitor_t, self).__init__(*args, **kwargs)
                self.lines = []

            def on_codeline(self, tree, is_start):
                sub = codeline_visitor_t()
                sub.visit_children(tree)
                line = newlineify(sub.clob())
                self.lines.append(" " * 4 + line)
                return self.SKIP_TREE

        v = programlisting_visitor_t()
        v.visit_children(tree)
        self.newline()
        self.text_bits.extend(v.lines)
        self.newline()
        return self.SKIP_TREE

    def _on_list(self, tree, is_start, prefixer):
        class list_visitor_t(description_text_collector_visitor_t):
            def __init__(self, *args, **kwargs):
                super(list_visitor_t, self).__init__(*args, **kwargs)
                self.lines = []

            # Note: Do _not_ add more `on_*` handlers here unless you are
            # absolutely sure you know what you're doing.
            # In particular, the fact that we don't support `on_parameterlist`
            # is _by design_, as it helps us realize when the doxygen-parsed
            # text is incorrect (because typically we have not left an empty
            # line after the last list item.)

            def on_listitem(self, tree, is_start):
                sub = description_text_collector_visitor_t()
                sub.visit_children(tree)
                line = newlineify(sub.clob())
                self.lines.append(prefixer(line, len(self.lines)))
                return self.SKIP_TREE

        v = list_visitor_t()
        v.visit_children(tree)
        self.newline()
        self.text_bits.extend(v.lines)
        self.newline()

        return self.SKIP_TREE

    def on_itemizedlist(self, tree, is_start):
        return self._on_list(tree, is_start, lambda l, _: f"* {l}")

    def on_orderedlist(self, tree, is_start):
        return self._on_list(tree, is_start, lambda l, idx: f"{idx}. {l}")


class type_text_collector_visitor_t(description_text_collector_visitor_t):
    def _sanitize_node_text(self, tree, text):
        if text:
            for undesirable in ["hexapi", "idaapi", "idaman", "ida_export"]:
                text = text.replace(undesirable, "")
        return text

    def on_type(self, tree, is_start):
        self._collect_node_text(tree, is_start)

    def type_clob(self):
        return self.oneliner_clob()


# --------------------------------------------------------

class documentable_t(object):
    def __init__(self, name):
        self.name = name
        self.classes = []
        self.functions = []
        self.variables = []

    def find_in_dataset(self, dataset, name):
        for one in dataset:
            if one.name == name:
                return one

    def find_class(self, name):
        return self.find_in_dataset(self.classes, name)

    def ensure_class(self, name):
        one = self.find_class(name)
        if one is None:
            one = class_t(name)
            self.classes.append(one)
        return one

    def find_function(self, name):
        return self.find_in_dataset(self.functions, name)

    def ensure_function(self, name):
        one = self.find_function(name)
        if one is None:
            one = function_t(name)
            self.functions.append(one)
        return one

    def find_variable(self, name):
        return self.find_in_dataset(self.variables, name)

    def ensure_variable(self, name):
        one = self.find_variable(name)
        if one is None:
            one = variable_t(name)
            self.variables.append(one)
        return one

    def find_with_kind(self, tree, element_name, kind):
        found = tree.find(element_name)
        if found:
            found_kind = found.attrib["kind"]
            if found_kind == kind:
                return found

    @staticmethod
    def load_description(tree, oneliner=False):

        class description_visitor_t(description_text_collector_visitor_t):
            def __init__(self, top_tag):
                super(description_visitor_t, self).__init__(
                    passthrough_elements=top_tag,
                    skip_elements=["parameterlist", "simplesect"])

        dv = description_visitor_t(tree.tag)
        dv.visit(tree)

        return dv.oneliner_clob() if oneliner else dv.clob()

    @staticmethod
    def load_descriptions(tree):
        # # wrapping at 80; if left at 70, texts from C++/Doxygen already contain
        # # linebreaks just after 70, that will make the wrapping ugly.
        # # Removing C++ linebreaks is probably not an option,
        # # if we want to respect pre-formatting.
        # wrap_text_at_column = 80
        brief = documentable_t.load_description(tree.find("briefdescription"), oneliner=True)
        detailed = documentable_t.load_description(tree.find("detaileddescription"))
        return brief, detailed

    def _get_direct_child_name(self, node):
        name_trees = node.findall("name")
        assert(len(name_trees) <= 1)
        if len(name_trees) == 1:
            return name_trees[0].text

    def load_section_functions(self, node):
        for member_tree in node.findall("./memberdef[@kind='function']"):
            function_name = self._get_direct_child_name(member_tree)
            if function_name:
                logger.debug(f"Found function: {self.name}.{function_name}")
                fun = self.ensure_function(function_name)
                fun_flavor = fun.new_flavor()
                fun_flavor.load_tree(member_tree, fun)

                logger.debug(f"{fun.name}: loaded function flavor with"
                             + f"\n\tbrief: {fun_flavor.brief_description}"
                             + f"\n\tdetailed: {fun_flavor.detailed_description}"
                             + f"\n\tprototype: {fun.compose_prototype_string(fun_flavor)}")

    def load_section_variables(self, node):
        section_kind = node.attrib["kind"]
        memberdef_kind = {
            "var" : "variable",
            "define" : "define",
            "user-defined" : "define",
            "public-attrib" : "variable",
            "public-static-attrib" : "variable",
        }[section_kind]
        for member_tree in node.findall(f"./memberdef[@kind='{memberdef_kind}']"):
            var_name = self._get_direct_child_name(member_tree)
            if var_name:
                logger.debug(f"Found variable: {self.name}.{var_name}")
                v = self.ensure_variable(var_name)
                v.load_tree(member_tree)

    def load_section_enums(self, node):
        for enum_tree in node.findall(f"./memberdef[@kind='enum']"):
            for enumvalue_tree in enum_tree.findall(f"./enumvalue"):
                enumvalue_name = self._get_direct_child_name(enumvalue_tree)
                if enumvalue_name:
                    logger.debug(f"Found (enum-based) variable: {self.name}.{enumvalue_name}")
                    v = self.ensure_variable(enumvalue_name)
                    v.load_tree(enumvalue_tree)


class module_t(documentable_t):
    def __init__(self, ida_module_name):
        super(module_t, self).__init__(ida_module_name)
        self.brief_description = None
        self.detailed_description = None

    def load_tree(self, tree):
        compounddef_node = tree.find("compounddef")
        if compounddef_node is not None:
            self.brief_description, self.detailed_description = documentable_t.load_descriptions(compounddef_node)

        for node in tree.findall("compounddef/innerclass"):
            logger.debug(f"Module has class {node.text} with refid {node.attrib['refid']}")
            klass_path = os.path.join(opts.doxygen_xml, f"{node.attrib['refid']}.xml")
            with open(klass_path, "r") as f:
                klass_tree = ET.fromstring(f.read())
            self.ensure_class(node.text).load_tree(klass_tree)

        for node in tree.findall("compounddef/sectiondef"):
            kind = node.attrib['kind']
            logger.debug(f"Module has section with kind {kind}")
            if kind in ["func"]:
                self.load_section_functions(node)
            elif kind in ["var", "define", "user-defined"]:
                self.load_section_variables(node)
            elif kind in ["enum"]:
                self.load_section_enums(node)


class variable_t(documentable_t):
    def __init__(self, name):
        self.name = name
        self.brief_description = None
        self.detailed_description = None

    def load_tree(self, tree):
        self.brief_description, self.detailed_description = documentable_t.load_descriptions(tree)


class function_t(documentable_t):

    class flavor_t(object):

        class prototype_element_t():
            def __init__(self, type, desc):
                self.type = type
                self.description = desc

        class param_t(prototype_element_t):
            def __init__(self, type, desc, name, defval):
                super(function_t.flavor_t.param_t, self).__init__(type, desc)
                self.name = name
                self.defval = defval

        class return_t(prototype_element_t):
            def __init__(self, type, desc):
                super(function_t.flavor_t.return_t, self).__init__(type, desc)
                self.retvals = []

            def append_retval(self, value, desc):
                self.retvals.append((value, desc))

        """
        While Python doesn't provide polymorphism, C++ does, and thus
        it's possible that the same function has multiple "flavors",
        each having their documentation & prototype.

        Since doxygen-produced contents represents information coming
        from the C++ side, it's only fitting that there can be multiple
        "flavors" of a function: it'll be up to the pypass to
        consolidate that into a single Python piece of pydoc.
        """
        def __init__(self):
            self.brief_description = None
            self.detailed_description = None
            self.return_info = None
            self.parameters = []

        def find_parameter_by_name(self, name):
            for p in self.parameters:
                if p.name == name:
                    return p

        def load_parameter_desc(self, tree, param_name):

            # Try to find the description in the <parameterlist>
            # <detaileddescription>
            #   <para>Retrive tinfo using type TID or struct/enum member MID
            #   <parameterlist kind="param">
            #     <parameteritem>
            #       <parameternamelist>
            #         <parametername>tid</parametername>
            #       </parameternamelist>
            #       <parameterdescription>
            #         <para>tid can denote a type tid or a member tid. </para>
            #       </parameterdescription>
            #     </parameteritem>
            for parameteritem_tree in tree.findall("./detaileddescription//parameterlist[@kind='param']/parameteritem"):
                for parameternamelist_tree in parameteritem_tree.findall("parameternamelist"):
                    for parametername_tree in parameternamelist_tree.findall("parametername"):
                        if parametername_tree.text == param_name:
                            parameterdescription_tree = parameteritem_tree.find("parameterdescription")
                            if parameterdescription_tree is not None:
                                v = description_text_collector_visitor_t()
                                v.visit_children(parameterdescription_tree)
                                return v.oneliner_clob()

        def load_parameter(self, param_tree, toplevel_tree):

            param_name, param_type, param_desc, param_defval = "unnamed", None, None, None
            declname_tree = param_tree.find("declname")
            if declname_tree is not None:
                param_name = declname_tree.text

            defval_tree = param_tree.find("defval")
            if defval_tree is not None:
                class defval_text_collector_visitor_t(description_text_collector_visitor_t):
                    def on_defval(self, tree, is_start):
                        self._collect_node_text(tree, is_start)
                v = defval_text_collector_visitor_t()
                v.visit(defval_tree)
                param_defval = v.oneliner_clob()

            type_tree = param_tree.find("type")
            if type_tree is not None:
                v = type_text_collector_visitor_t()
                v.visit(type_tree)
                param_type = v.type_clob()
                # logger.debug(f"RAW BITS: {v.text_bits}")
                # logger.debug(f"PARAM TYPE: '{param_type}'")

            param_desc = self.load_parameter_desc(toplevel_tree, param_name)

            self.parameters.append(self.param_t(param_type, param_desc, param_name, param_defval))

        def load_tree(self, tree, parent_function):
            """
            From the markup below, we can see that on one hand we have
            the prototype of the function that's directly under the `memberdef`
            tree, whereas the description of the parameters, is under another
            `parameterlist` tree.

            <memberdef kind="function" id="classtinfo__t_1a1eb5baf526ca23ad9ab9c6cb86b7a30a" prot="public" static="no" const="no" explicit="no" inline="yes" virt="non-virtual">
              <type><ref refid="pro_8h_1ab65ed42d67e6c517c746ff2a6a187016" kindref="member">ssize_t</ref></type>
              <definition>ssize_t tinfo_t::get_udm_by_tid</definition>
              <argsstring>(udm_t *udm, tid_t tid)</argsstring>
              <name>get_udm_by_tid</name>
              <qualifiedname>tinfo_t::get_udm_by_tid</qualifiedname>
              <param>
                <type><ref refid="structudm__t" kindref="compound">udm_t</ref> *</type>
                <declname>udm</declname>
              </param>
              <param>
                <type><ref refid="pro_8h_1ad8791d30d19843bc09b78bdf01a852ec" kindref="member">tid_t</ref></type>
                <declname>tid</declname>
              </param>
              <briefdescription>
              </briefdescription>
              <detaileddescription>
                <para>Retrive tinfo using type TID or struct/enum member MID
                <parameterlist kind="param">
                  <parameteritem>
                    <parameternamelist>
                      <parametername>tid</parametername>
                    </parameternamelist>
                    <parameterdescription>
                      <para>tid can denote a type tid or a member tid. </para>
                    </parameterdescription>
                  </parameteritem>
                  <parameteritem>
                    <parameternamelist>
                      <parametername>udm[out]</parametername>
                    </parameternamelist>
                    <parameterdescription>
                      <para>place to save the found member to, may be nullptr </para>
                    </parameterdescription>
                  </parameteritem>
                </parameterlist>
                <simplesect kind="return">
                  <para>if a member tid was specified, returns the member index, otherwise returns -1. if the function fails, THIS object becomes empty. </para>
                </simplesect>
                </para>
              </detaileddescription>
              <inbodydescription>
              </inbodydescription>
              <location file="obj/x64_linux_gcc_64/idasdk/typeinf.hpp" line="3655" column="11" bodyfile="obj/x64_linux_gcc_64/idasdk/typeinf.hpp" bodystart="3655" bodyend="3655"/>
            </memberdef>
            """

            self.brief_description, self.detailed_description = documentable_t.load_descriptions(tree)

            for param_tree in tree.findall("param"):
                self.load_parameter(param_tree, tree)

            return_type, return_description = None, None
            return_type_tree = tree.find("type")
            if return_type_tree is not None:
                v = type_text_collector_visitor_t()
                v.visit(return_type_tree)
                return_type = v.type_clob()

            # We'll guarantee that we have only 1 'return' item.
            # The various values that are returned, should be placed in 'retval's
            for return_tree in tree.findall("./detaileddescription//simplesect[@kind='return']"):
                assert return_description is None
                v = description_text_collector_visitor_t()
                v.visit_children(return_tree)
                return_description = v.oneliner_clob()

            self.return_info = self.return_t(return_type, return_description)

            # While at it, we'll also guarantee that we don't have 'returns' items
            for returns_tree in tree.findall("./detaileddescription//simplesect[@kind='returns']"):
                crash()

            # Add support for '\retval's
            for parameteritem_tree in tree.findall("./detaileddescription//parameterlist[@kind='retval']/parameteritem"):
                retval_desc = None
                parameterdescription_tree = parameteritem_tree.find("parameterdescription")
                if parameterdescription_tree is not None:
                        v = description_text_collector_visitor_t()
                        v.visit_children(parameterdescription_tree)
                        retval_desc = v.oneliner_clob()

                for parameternamelist_tree in parameteritem_tree.findall("parameternamelist"):
                    for parametername_tree in parameternamelist_tree.findall("parametername"):
                        retval_value = parametername_tree.text
                        self.return_info.append_retval(retval_value, retval_desc)

    def __init__(self, name):
        super(function_t, self).__init__(name)
        self.flavors = []

    def new_flavor(self):
        f = self.flavor_t()
        self.flavors.append(f)
        return f

    def compose_prototype_string(self, flavor, type_processor=lambda t: t):
        parts = [self.name]
        parts.append("(")
        params_parts = []
        for p in flavor.parameters:
            param_parts = []
            param_parts.append(f"{p.name}")
            if p.type:
                param_parts.append(f": {type_processor(p.type)}")
            if p.defval is not None:
                param_parts.append(f"={p.defval}")
            params_parts.append("".join(param_parts))
        parts.append(", ".join(params_parts))
        parts.append(")")
        if flavor.return_info.type:
            parts.append(f" -> {type_processor(flavor.return_info.type)}")
        return "".join(parts)


class class_t(documentable_t):
    def __init__(self, name):
        super(class_t, self).__init__(name)
        self.brief_description = None
        self.detailed_description = None

    def load_tree(self, tree):
        compounds = list(tree.findall("compounddef"))
        assert(len(compounds) == 1)
        compound = compounds[0]
        compound_kind = compound.attrib["kind"]
        assert(compound_kind in [COMPOUND_KIND_CLASS, COMPOUND_KIND_UNION, COMPOUND_KIND_STRUCT])

        wks = {
            "public-type" : None,
            "public-func" : None,
            "public-attrib" : None,

            "public-static-func" : None,
            "public-static-attrib" : None,
        }
        for section_tree in compound.findall("sectiondef"):
            section_kind = section_tree.attrib["kind"]
            if section_kind.startswith("private-"):
                continue
            if section_kind.startswith("protected-"):
                continue
            if section_kind.startswith("friend"):
                continue
            if section_kind.startswith("user-defined"):
                # bitrange.hpp, netnode.hpp; see the `\name` things.
                # Just skip them for now
                logger.debug(f"Skipping section {section_tree}")
                continue
            assert(wks[section_kind] is None)
            wks[section_kind] = section_tree

        for section in map(lambda sn: wks[sn], ["public-func", "public-static-func"]):
            if section is not None:
                self.load_section_functions(section)

        for kind in ["var", "define", "user-defined", "public-attrib", "public-static-attrib"]:
            for section_tree in compound.findall(f"sectiondef[@kind='{kind}']"):
                self.load_section_variables(section_tree)

        for kind in ["enum"]:
            for section_tree in compound.findall(f"sectiondef[@kind='{kind}']"):
                self.load_section_enums(section_tree)

        if wks["public-type"]:
            self.load_section_enums(wks["public-type"])

opts, logger = None, None

class hooks_builder_t(object):

    def __init__(self, hooks_info):
        self.hooks_info = hooks_info

    def load_hooks_function(self, klass, tree):

        method_name = tree.find("./name").text

        hi = self.hooks_info
        logger.debug(f"Investigating hook function '{hi.class_name}.{method_name}'")
        if self.hooks_info.discard_prefixes and method_name.startswith(hi.discard_prefixes):
            logger.debug(f"Ignoring due to discarded prefixes {hi.discard_prefixes}")
            return

        brief, detailed = documentable_t.load_descriptions(tree)
        if hi.discard_doc and (
                brief.startswith(hi.discard_doc) or \
                detailed.startswith(hi.discard_doc)):
            logger.debug(f"Ignoring due to discarded doc {hi.discard_doc}")
            return

        for prefix in (hi.strip_prefixes or []):
            if method_name.startswith(prefix):
                method_name = method_name[len(prefix):]
                break

        recipe_info = hi.recipe_module.recipe.get(method_name, {})
        if recipe_info.get("ignore", False):
            logger.debug(f"Ignoring due to recipe-mandated ignore")
            return

        assert klass.find_function(method_name) is None
        fun = klass.ensure_function(method_name)
        fun_flavor = fun.new_flavor()
        fun_flavor.load_tree(tree, fun)

        def clean(thing):
            if thing.startswith("cb:"):
                thing = thing[3:].lstrip()
            return thing
        fun_flavor.brief_description = clean(fun_flavor.brief_description)
        fun_flavor.detailed_description = clean(fun_flavor.detailed_description)

        # `flavor_t.load_tree` expects a proper list of <param> elements
        # to determine the prototyp.
        # Since we are not parsing proper function documentation here, but
        # rather piecing things together, we don't have that <param> list:
        # all we have is a <parameterlist> with less-than-ideally-structured
        # information, extracted purely from the doxygen docstring, and not
        # from parsing the C++ prototype.
        # We'll have to do our best to collect that information, and
        # let the matcher hopefully do a good job.
        for parameteritem_tree in tree.findall("./detaileddescription//parameterlist[@kind='param']/parameteritem"):
            param_type, param_name, param_desc, param_defval = None, None, None, None
            param_name = parameteritem_tree.find(".//parametername").text
            param_desc = fun_flavor.load_parameter_desc(tree, param_name)
            fun_flavor.parameters.append(fun_flavor.param_t(param_type, param_desc, param_name, param_defval))
            logger.debug(f"Found parameter '{param_name}' ({param_desc})")

        logger.debug(f"Created hook method {klass.name}.{method_name}")

    def load_hooks_class(self, module, tree):

        hi = self.hooks_info
        logger.debug(f"Loading tree for hooks '{hi.class_name}', from enumeration with name '{hi.enum_name}'")
        klass = module.ensure_class(self.hooks_info.class_name)

        for enumvalue_tree in tree.findall("enumvalue"):
            self.load_hooks_function(klass, enumvalue_tree)



def parse(_opts, _logger):
    global opts
    global logger
    opts, logger = _opts, _logger

    module = None

    # Start from the toplevel doxygen-parsed XML document
    for suffix in ["_8hpp", "_8h"]:
        module_name = opts.idapython_module_name.replace("ida_", "")
        path = os.path.join(opts.doxygen_xml, f"{module_name}{suffix}.xml")
        if os.path.isfile(path):
            logger.debug(f"Found module entrypoint: {path}")
            with open(path, "r") as f:
                tree = ET.fromstring(f.read())
            module = module_t(opts.idapython_module_name)
            module.load_tree(tree)

    # And then create fake "hooks" classes
    genhooks_dir = os.path.join(os.path.dirname(__file__), "..", "..", "genhooks")
    if genhooks_dir not in sys.path:
        sys.path.append(genhooks_dir)
    import recipe_index
    for hinfo in recipe_index.hooks.get(opts.idapython_module_name, []):
        hbuilder = hooks_builder_t(hinfo)

        path = os.path.join(opts.doxygen_xml, hinfo.toplevel_xml_fname)
        with open(path, "r") as f:
            tree = ET.fromstring(f.read())
        enum_tree = tree.find(f".//memberdef[@kind='enum'][name='{hbuilder.hooks_info.enum_name}']")
        assert enum_tree

        hbuilder.load_hooks_class(module, enum_tree)

    return module
