from __future__ import print_function

import os
import textwrap
import xml.etree.ElementTree as ET

def join_all_element_text(el, sep=""):
    bits = []
    for txt in el.itertext():
        bits.append(txt)
    return sep.join(bits)

def remove_empty_header_or_footer_lines(lines):
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    return lines

class text_context_t:
    def __init__(self):
        self.tokens = [] # pending to be textwrap'd
        self.lines = [] # already textwrap'd

    def add_token_nostrip(self, token):
        if token:
            self.tokens.append(token)

    def add_token(self, token):
        if token:
            return self.add_token_nostrip(token.strip())

    def add_line(self, line):
        self.lines.append(line)

    def wrap_flush(self):
        if self.tokens:
            lines = textwrap.wrap("".join(self.tokens))
            self.lines.extend(lines)
            self.tokens = []

def _get_text_with_refs1(ctx, node):
    process_children = True
    if node.tag == "simplesect" and node.attrib.get("kind") == "return":
        return
    if node.tag == "parameterlist":
        return
    if node.tag == "ref":
        ctx.add_token_nostrip(" '%s' " % node.text)
    elif node.tag == "lsquo":
        ctx.add_token_nostrip(" `")
    elif node.tag == "rsquo":
        ctx.add_token_nostrip("' ")
    elif node.tag == "sp":
        ctx.add_token_nostrip(" ")
    elif node.tag == "computeroutput":
        for child in node:
            tmp = text_context_t()
            _get_text_with_refs1(tmp, child)
            ctx.add_token_nostrip("".join(tmp.tokens))
        txt = (node.text or "").strip()
        if txt:
            ctx.add_token_nostrip(" '%s' " % txt)
    elif node.tag == "programlisting":
        ctx.wrap_flush()
        ctx.add_line("")
        for child in node:
            if child.tag == "codeline":
                tmp = text_context_t()
                _get_text_with_refs1(tmp, child)
                code_line = "".join(tmp.tokens)
                ctx.add_line(code_line)
        ctx.add_line("")
        process_children = False
    else:
        ctx.add_token(node.text)
    ctx.add_token(node.tail)
    if process_children:
        for child in node:
            _get_text_with_refs1(ctx, child)

def get_element_description(el, child_tag):
    out = []
    for child in el.findall("./%s" % child_tag):
        ctx = text_context_t()
        _get_text_with_refs1(ctx, child)
        ctx.wrap_flush()
        if ctx.lines:
            out.extend(ctx.lines)
    out = remove_empty_header_or_footer_lines(out)
    if out:
        out0 = out[0]
        if out0.startswith("ui:"):
            out0 = out0[3:]
        if out0.startswith("cb:"):
            out0 = out0[3:]
        out0 = out0.lstrip()
        out[0] = out0
    return out

def load_xml_for_module(xml_dir_path, module_name, or_dummy=True):
    xml_tree = ET.Element("dummy") if or_dummy else None
    for sfx in ["_8hpp", "_8h"]:
        xml_path = os.path.join(xml_dir_path, "%s%s.xml" % (module_name, sfx))
        if os.path.isfile(xml_path):
            with open(xml_path) as fin:
                xml_tree = ET.fromstring(fin.read())
    return xml_tree

def load_xml_for_udt(xml_dir_path, xml_tree, udt_name):
    for ic in xml_tree.findall("./compounddef/innerclass"):
        if ic.text == udt_name:
            refid = ic.attrib.get("refid")
            xml_path = os.path.join(xml_dir_path, "%s.xml" % refid)
            with open(xml_path) as fin:
                udt_xml_tree = ET.fromstring(fin.read())
            return refid, udt_xml_tree
    return None, None

def get_toplevel_functions(xml_tree, name=None):
    path = "./compounddef/sectiondef[@kind='%s']/memberdef[@kind='function']"
    if name:
        path = "%s/[name='%s']" % (path, name)
    all_nodes = []
    for section_kind in ["func", "user-defined"]:
        nodes = xml_tree.findall(path % section_kind)
        all_nodes.extend(map(lambda n: n, nodes))
    return all_nodes

def get_udt_methods(xml_tree, refid, name=None):
    path = "./compounddef[@id='%s']/sectiondef[@kind='public-func']/memberdef[@kind='function']" % (
        refid,)
    if name:
        path = "%s/[name='%s']" % (path, name)
    return xml_tree.findall(path)

def get_single_child_element_text_contents(el, child_element_tag):
    nodes = el.findall("./%s" % child_element_tag)
    nnodes = len(nodes)
    if nnodes == 0:
        return None
    text = nodes[0].text
    if nnodes > 1:
        print("Warning: more than 1 child element with tag '%s' found; picking first" % (child_element_tag,))
    return text

def for_each_param(memberdef_node, callback):
    # <parameterlist kind="param">
    #   <parameteritem>
    #     <parameternamelist>
    #       <parametername>idp_modname</parametername>
    #     </parameternamelist>
    #     <parameterdescription>
    #       <para>(const char *) processor module name </para>
    #     </parameterdescription>
    #   </parameteritem>
    # </parameterlist>
    assert(memberdef_node.tag == "memberdef" and memberdef_node.attrib.get("kind") == "function")
    plist = memberdef_node.find("./detaileddescription/para/parameterlist[@kind='param']")
    def get_direct_text(n, tag):
        c = n.find("./%s" % tag)
        if c is not None:
            return " ".join(c.itertext()).strip()
    for param in memberdef_node.findall("./param"):
        name, ptyp, desc = None, None, None
        name = get_direct_text(param, "declname")
        ptyp = get_direct_text(param, "type")
        if name and plist is not None:
            sdk_doc_param_name = name.replace("NONNULL_", "")
            for plist_item in plist.findall("parameteritem"):
                if plist_item.find("./parameternamelist/[parametername='%s']" % sdk_doc_param_name) is not None:
                    pdesc_node = plist_item.find("./parameterdescription")
                    if pdesc_node is not None:
                        desc = " ".join(pdesc_node.itertext()).strip()
        callback(name, ptyp, desc)

def for_each_retval(detaileddescription_node, callback):
    # <parameterlist kind="retval">
    #   <parameteritem>
    #     <parameternamelist>
    #       <parametername>&gt;0</parametername>
    #     </parameternamelist>
    #     <parameterdescription>
    #       <para>ok, generated the definition text </para>
    #     </parameterdescription>
    #   </parameteritem>
    # </parameterlist>
    plist = detaileddescription_node.find("./para/parameterlist[@kind='retval']")
    if plist is not None:
        for parameteritem_el in plist.findall("parameteritem"):
            parameternamelist_el = parameteritem_el.find("parameternamelist")
            if parameternamelist_el is not None:
                parametername_els = parameternamelist_el.findall("parametername")
                if parametername_els:
                    parametername_el = parametername_els[0]
                    retval_value = parametername_el.text
                    retval_desc_els = parameteritem_el.findall("parameterdescription")
                    if retval_desc_els:
                        retval_desc = " ".join(retval_desc_els[0].itertext()).strip()
                    else:
                        retval_desc = None
                    callback(retval_value, retval_desc)
