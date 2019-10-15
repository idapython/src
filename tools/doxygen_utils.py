from __future__ import print_function

import os
import xml.etree.ElementTree as ET

def load_xml_for_module(xml_dir_path, module_name, or_dummy=True):
    xml_tree = ET.Element("dummy") if or_dummy else None
    for sfx in ["_8hpp", "_8h"]:
        xml_path = os.path.join(xml_dir_path, "%s%s.xml" % (module_name, sfx))
        if os.path.isfile(xml_path):
            with open(xml_path) as fin:
                xml_tree = ET.fromstring(fin.read())
    return xml_tree

def get_toplevel_functions(xml_tree, name=None):
    path = "./compounddef/sectiondef[@kind='%s']/memberdef[@kind='function']"
    if name:
        path = "%s/[name='%s']" % (path, name)
    all_nodes = []
    for section_kind in ["func", "user-defined"]:
        nodes = xml_tree.findall(path % section_kind)
        all_nodes.extend(map(lambda n: n, nodes))
    return all_nodes

def get_single_child_element_text_contents(el, child_element_tag):
    nodes = el.findall("./%s" % child_element_tag)
    nnodes = len(nodes)
    if nnodes == 0:
        return None
    text = nodes[0].text
    if nnodes > 1:
        print("Warning: more than 1 child element with tag '%s' found; picking first" % (child_element_tag,))
    return text

def for_each_param(node, callback):
    assert(node.tag == "memberdef" and node.attrib.get("kind") == "function")
    plist = node.find("./detaileddescription/para/parameterlist[@kind='param']")
    def get_direct_text(n, tag):
        c = n.find("./%s" % tag)
        if c is not None:
            return " ".join(c.itertext()).strip()
    for param in node.findall("./param"):
        name, ptyp, desc = None, None, None
        name = get_direct_text(param, "declname")
        ptyp = get_direct_text(param, "type")
        if name and plist is not None:
            for plist_item in plist.findall("parameteritem"):
                if plist_item.find("./parameternamelist/[parametername='%s']" % name) is not None:
                    pdesc_node = plist_item.find("./parameterdescription")
                    if pdesc_node is not None:
                        desc = " ".join(pdesc_node.itertext()).strip()
        callback(name, ptyp, desc)
