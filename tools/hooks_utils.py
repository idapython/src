
import os
import sys
import xml.etree.ElementTree as ET

import doxygen_utils

mydir, _ = os.path.split(__file__)
genhooks_dir = os.path.join(mydir, "genhooks")
if genhooks_dir not in sys.path:
    sys.path.append(genhooks_dir)

import all_recipes

class enum_info_t:
    def __init__(
            self,
            fname,
            enum_name,
            discard_prefixes,
            discard_doc,
            strip_prefixes,
            recipe,
            default_rtype):
        self.fname = fname
        self.enum_name = enum_name
        self.discard_prefixes = discard_prefixes
        self.discard_doc = discard_doc
        self.strip_prefixes = strip_prefixes
        self.recipe = recipe
        self.default_rtype = default_rtype

_hooks_enum_info = {}
for klass in all_recipes.hooks:
    fname,            \
    enum_name,        \
    discard_prefixes, \
    discard_doc,      \
    strip_prefixes,   \
    recipe_module = all_recipes.hooks[klass]

    _hooks_enum_info[klass] = enum_info_t(
        fname,
        enum_name,
        discard_prefixes,
        discard_doc,
        strip_prefixes,
        recipe_module.recipe,
        recipe_module.default_rtype)


def get_hooks_enum_information(class_name):
    return _hooks_enum_info[class_name]

def _parse_param_type(desc):
    if desc.startswith("("):
        import re
        m = re.match(r"\(([^\)]*)\)\s*(.*)", desc)
        if m:
            ptype = m.group(1)
            return ptype.lstrip(":").replace(" ::", " "), m.group(2)
    return None, None

def _parse_return_type(desc):
    default = None
    import re
    m = re.match(r".*\(default=([^\)]*)\).*", desc)
    if m:
        default = m.group(1)
    if desc.startswith("void"):
        return "void", None, default
    else:
        ptype, notype_pdesc = _parse_param_type(desc)
        if ptype is None and notype_pdesc is None:
            notype_pdesc = desc
        return ptype, notype_pdesc, default

def _parse_enumerator(enumval_el, name, enum_name, hooks_info):

    # Return type
    ret_el = enumval_el.find(".//simplesect[@kind='return']")
    rtype = None
    rdefault = None
    rexpr = None
    recipe_data = hooks_info.recipe.get(name, {})

    if "ignore" in recipe_data and recipe_data["ignore"]:
        return

    brief = doxygen_utils.get_element_description(enumval_el, "briefdescription")
    detailed = doxygen_utils.get_element_description(enumval_el, "detaileddescription")

    notype_rdesc = None
    retvals = []
    return_data = recipe_data["return"] if (recipe_data and "return" in recipe_data) else {}
    if "type" in return_data:
        rtype = return_data["type"]
    elif ret_el is not None:
        rdesc = ret_el.find("para").text
        rtype, notype_rdesc, rdefault = _parse_return_type(rdesc)

    detaileddescription_el = enumval_el.find("detaileddescription")
    if detaileddescription_el is not None:
        def collect_retval(value, desc):
            retvals.append((value, desc))
        doxygen_utils.for_each_retval(detaileddescription_el, collect_retval)

    if rtype is None:
        rtype = hooks_info.default_rtype

    if rtype != "void" and rdefault is None:
        rdefault = 0

    if "default" in return_data:
        rdefault = return_data["default"]
    if "retexpr" in return_data:
        rexpr = return_data["retexpr"]

    params = [{
        "name" : "<return>",
        "type" : rtype,
        "default" : rdefault,
        "retexpr" : rexpr,
        "desc" : notype_rdesc or None,
        "values" : retvals or None,
    }]

    # arguments
    plist_el = enumval_el.find(".//parameterlist[@kind='param']")
    if plist_el is not None:
        for pitem_el in plist_el.findall("./parameteritem"):
            pname = pitem_el.find(".//parametername").text
            if pname != "none" and pname != "...":
                pdesc = doxygen_utils.join_all_element_text(pitem_el.find(".//parameterdescription/para"))
                ptype, notype_pdesc = _parse_param_type(pdesc)
                if ptype is None:
                    print("Couldn't parse parameter description: \"%s\". Dropping notification \"%s\" altogether" % (pdesc, name))
                    return
                params.append({
                    "name" : pname,
                    "type" : ptype,
                    "desc" : notype_pdesc,
                    })

    # added parameters
    if "add_params" in recipe_data:
        params.extend(recipe_data["add_params"])

    return {
        "brief" : brief,
        "detailed" : detailed,
        "name" : name,
        "params" : params,
        "enum_name" : enum_name,
    }


def get_hooks_enumerators(xml_dir, class_name):
    hooks_info = get_hooks_enum_information(class_name)
    tree = ET.parse(os.path.join(xml_dir, hooks_info.fname))
    enum_el = tree.find(".//memberdef[@kind='enum']/[name='%s']" % hooks_info.enum_name)

    enumerators = []
    for enumval_el in enum_el.findall("./enumvalue"):
        discarded = False
        orig_name = enumval_el.find("./name").text
        name = orig_name
        for pfx in hooks_info.discard_prefixes:
            if name.startswith(pfx):
                discarded = True
                break
        if not discarded and hooks_info.discard_doc:
            JT = doxygen_utils.join_all_element_text
            discarded = JT(enumval_el.find("./detaileddescription")).strip().startswith(hooks_info.discard_doc) or \
                        JT(enumval_el.find("./briefdescription")).strip().startswith(hooks_info.discard_doc)
        if not discarded:
            for pfx in hooks_info.strip_prefixes:
                if name.startswith(pfx):
                    name = name[len(pfx):]
                    break
            if not name.startswith("OBSOLETE"):
                e = _parse_enumerator(enumval_el, name, orig_name, hooks_info)
                if e:
                    enumerators.append(e)

    return enumerators

