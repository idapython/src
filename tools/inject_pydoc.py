from __future__ import print_function
#
# This (non-idiomatic) python script is in charge of
#   1) Parsing all .i files in the 'swig/' directory, and
#      collecting all function, classes & methods comments
#      that can be found between <pydoc>/</pydoc> tags.
#   2) Reading, line by line, the idaapi_<platform>.py.raw
#      file, and for each function, class & method found
#      there, associate a possily previously-harvested
#      pydoc documentation.
#   3) Generating the idaapi_<platform>.py file.
#

import sys
import os
import re
import textwrap
import xml.etree.ElementTree as ET
import six

try:
    from argparse import ArgumentParser
except:
    print("Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'")
    raise

mydir, _ = os.path.split(__file__)
if mydir not in sys.path:
    sys.path.append(mydir)

import wrapper_utils
import hooks_utils

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-s", "--interface", required=True)
parser.add_argument("-w", "--cpp-wrapper", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-x", "--xml-doc-directory", required=True)
parser.add_argument("-e", "--epydoc-injections", required=True)
parser.add_argument("-m", "--module", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
parser.add_argument("-d", "--debug", default=False, action="store_true")
parser.add_argument("-D", "--debug-function", type=str, default="")
args = parser.parse_args()

this_dir, _ = os.path.split(__file__)
sys.path.append(this_dir)
import doxygen_utils

DOCSTR_MARKER = '"""'
DOCSTR_MARKER_START_RAW  = 'r"""'

inc = 0
class indenter_t(object):
    def __enter__(self):
        global inc
        inc += 1
        return self

    def __exit__(self, type, value, tb):
        global inc
        inc -= 1
        if value:
            raise

def get_indent_str():
    return "    " * inc

def verb(msg):
    if args.verbose:
        print(get_indent_str() + msg)

selective_debug_status = None
def dbg(msg):
    if args.debug:
        if selective_debug_status in [None, True]:
            print("DEBUG: " + get_indent_str() + msg)

# --------------------------------------------------------------------------
def load_patches(args):
    patches = {}
    dirpath, _ = os.path.split(__file__)
    candidate = os.path.join(dirpath, "inject_pydoc", "%s.py" % args.module)
    if os.path.isfile(candidate):
        with open(candidate) as fin:
            raw = fin.read()
        patches = eval(raw)
    return patches

# --------------------------------------------------------------------------
def split_oneliner_comments_and_remove_property_docstrings(lines):
    out_lines = []
    pat = re.compile('(.*= property\(.*), doc=r""".*"""(\))')
    for line in lines:

        line = line.rstrip()

        m = pat.match(line)
        if m:
            line = m.group(1) + m.group(2)

        if line.startswith("#"):
            out_lines.append(line)
            continue

        if len(line) == 0:
            out_lines.append("")
            continue

        handled = False
        if line.endswith(DOCSTR_MARKER):
            emarker_idx = line.rfind(DOCSTR_MARKER)
            if line.lstrip().startswith(DOCSTR_MARKER_START_RAW):
                smarker = DOCSTR_MARKER_START_RAW
                smarker_idx = line.find(DOCSTR_MARKER_START_RAW)
            elif line.lstrip().startswith(DOCSTR_MARKER):
                smarker = DOCSTR_MARKER
                smarker_idx = line.find(DOCSTR_MARKER)
            else:
                smarker_idx = -1
            if smarker_idx > -1:
                pfx = line[0:smarker_idx]
                meat = line[smarker_idx+len(smarker):emarker_idx]
                if len(meat.strip()):
                    out_lines.append(pfx + smarker)
                    out_lines.append(pfx + meat)
                    out_lines.append(pfx + DOCSTR_MARKER)
                    handled = True
        if not handled:
            out_lines.append(line)

    return out_lines

# --------------------------------------------------------------------------
def dedent(lines):
    if len(lines) < 1:
        return lines
    line0  = lines[0]
    indent = len(line0) - len(line0.lstrip())
    if indent < 0:
        raise BaseException("Couldn't find \" in '" + line0 + "'")
    expect = " " * indent
    def proc(l):
        #print "DE-INDENTING '%s'" % l
        if len(l) == 0:
            return l # Keep empty lines
        prefix = l[0:indent]
        if prefix != expect:
            raise BaseException("Line: '" + l + "' has wrong indentation. Expected " + str(indent) + " spaces.")
        return l[indent:]
    return list(map(proc, lines))

# --------------------------------------------------------------------------
def apply_indent(lines, indent):
    return list(map(lambda l: indent + l, lines))

# --------------------------------------------------------------------------
def add_lines_block(storage, lines):
    if storage and storage[-1] != "" and storage[-1] != "\n":
        storage.append("\n")
    storage.extend(lines)

# --------------------------------------------------------------------------
def get_fun_name(line):
    return re.search("def ([^\(]*)\(", line).group(1)

# --------------------------------------------------------------------------
def get_class_name(line):
    return re.search("class ([^\(:]*)[\(:]?", line).group(1)

# --------------------------------------------------------------------------
def get_indent_string(line):
    indent = len(line) - len(line.lstrip())
    if not indent:
        raise Exception("No indent in line '%s'" % line)
    return " " * indent

# --------------------------------------------------------------------------
class collect_pywraps_pydoc_t(object):
    """
    Search in all files in the 'plugins/idapython/swig/' directory
    for possible additional <pydoc> we could use later.
    """
    S_UNKNOWN   = 0
    S_IN_PYDOC  = 1
    S_IN_DOCSTR = 2
    # S_STOP      = 5
    PYDOC_START = "#<pydoc>"
    PYDOC_END   = "#</pydoc>"
    state = S_UNKNOWN
    lines = None

    def __init__(self, input_path):
        self.idaapi_pydoc = {"funcs" : {}, "classes" : {}}
        self.input_path = input_path

    def next(self):
        line = self.lines[0]
        self.lines = self.lines[1:]
        return line

    def set_fun(self, name, collected):
        self.idaapi_pydoc["funcs"][name] = dedent(collected)

    def collect_fun(self, fun_name):
        collected = []
        while len(self.lines) > 0:
            line = self.next()
            if self.state is self.S_IN_PYDOC:
                if line.startswith(self.PYDOC_END):
                    self.state = self.S_UNKNOWN
                    return self.set_fun(fun_name, collected)
                elif line.find(DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_DOCSTR
                elif not line.startswith("    "):
                    return self.set_fun(fun_name, collected)
            elif self.state is self.S_IN_DOCSTR:
                if line.find(DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_PYDOC
                    return self.set_fun(fun_name, collected)
                else:
                    collected.append(line)
            else:
                raise BaseException("Unexpected state: " + str(self.state))

    def set_method(self, cls, method_name, collected):
        cls["methods"][method_name] = dedent(collected)

    def collect_method(self, cls, method_name):
        collected = []
        while len(self.lines) > 0:
            line = self.next()
            if self.state is self.S_IN_PYDOC:
                if line.startswith(self.PYDOC_END):
                    self.state = self.S_UNKNOWN
                    return self.set_method(cls, method_name, collected)
                elif line.find(DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_DOCSTR
            elif self.state is self.S_IN_DOCSTR:
                if line.find(DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_PYDOC
                    return self.set_method(cls, method_name, collected)
                else:
                    collected.append(line)

    def set_class(self, name, cls_data, collected):
        cls_data["doc"] = dedent(collected) if len(collected) > 0 else None
        self.idaapi_pydoc["classes"][name] = cls_data

    def collect_cls(self, cls_name):
        collected = []
        cls = {"methods":{},"doc":None}
        while len(self.lines) > 0:
            line = self.next()
            if self.state is self.S_IN_PYDOC:
                if line.startswith("    def "):
                    self.collect_method(cls, get_fun_name(line))
                    if self.state == self.S_UNKNOWN: # method marked end of <pydoc>
                        return self.set_class(cls_name, cls, collected)
                elif line.find(DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_DOCSTR
                elif line.startswith(self.PYDOC_END):
                    self.state = self.S_UNKNOWN
                    return self.set_class(cls_name, cls, collected)
                elif len(line) > 1 and not line.startswith("    "):
                    return self.set_class(cls_name, cls, collected)
            elif self.state is self.S_IN_DOCSTR:
                if line.find(DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_PYDOC
                else:
                    collected.append(line)

    def collect_file_pydoc(self, filename):
        self.state = self.S_UNKNOWN
        with open(filename) as f:
            self.lines = split_oneliner_comments_and_remove_property_docstrings(f.readlines())
        context = None
        doc = []
        while len(self.lines) > 0:
            line = self.next()
            if self.state is self.S_UNKNOWN:
                if line.startswith(self.PYDOC_START):
                    self.state = self.S_IN_PYDOC
            elif self.state is self.S_IN_PYDOC:
                if line.startswith("def "):
                    self.collect_fun(get_fun_name(line))
                elif line.startswith("class "):
                    self.collect_cls(get_class_name(line))
                elif line.startswith(self.PYDOC_END):
                    self.state = self.S_UNKNOWN

    def collect(self):
        verb("### Processing %s" % os.path.basename(self.input_path))
        self.collect_file_pydoc(self.input_path)
        return self.idaapi_pydoc


class generated_func_info_t:
    """
    Object model of what could be extracted from the SWiG-generated
    python documentation. Functions that use polymorphism will have
    multiple 'signature_t's.
    """

    class signature_t:
        PARAM_WITH_CPP_TYPE_INFO_RE = re.compile(r".*:\s*(.*\(C\+\+:.*\).*)")

        def __init__(self, prototype):
            self.prototype = prototype
            self.params = []
            self.returns = []
            self.retvals = []

        def replace_param(self, original_name, name, text, indent):
            found_idx = -1
            for idx, l in enumerate(self.params):
                if l.lstrip().startswith("%s:" % name):
                    found_idx = idx
                    break
            if found_idx < 0:
                for idx, l in enumerate(self.params):
                    if l.lstrip().startswith("%s:" % original_name):
                        found_idx = idx
                        break
            if found_idx >= 0:
                m = self.PARAM_WITH_CPP_TYPE_INFO_RE.match(self.params[found_idx])
                if m:
                    text = re.sub(r"(.*)\(C\+\+:.*\)(.*)", r"\1 - %s\2" % m.group(1), text)
                lines = textwrap.wrap(text, 70, subsequent_indent=" " * indent, break_on_hyphens=False)
                self.params = self.params[0:found_idx] + lines + self.params[found_idx+1:]
            else:
                verb("No param named '%s' for function with prototype '%s'" % (name, self.prototype))

        def append_return(self, text, indent):
            if self.returns is not None:
                verb("Overriding return information")
            self.returns = textwrap.wrap(text, 70, subsequent_indent=" " * indent, break_on_hyphens=False)

        def append_retval(self, text, indent):
            self.retvals.extend(textwrap.wrap(text, 70, subsequent_indent=" " * indent, break_on_hyphens=False))

        def get_lines(self):
            return [self.prototype] \
                + list(map(lambda l: "    %s" % l, self.params + self.returns + self.retvals))


    def __init__(self, lines):
        self.original_comment = False
        self.signatures = []

        STATE_NONE = None
        STATE_IN_SIG = "in signature"
        STATE_AFTER_SIG = "after signature"
        STATE_IN_PARAMS = "in params"
        state = STATE_NONE
        current_sig = None
        try:
            for line in lines:
                line = line.lstrip()
                assert(not line.startswith("@param"))
                assert(not line.startswith("@return"))

                # print(">>> '%s' (state=%s)" % (line, state))
                if line:
                    if state == STATE_NONE:
                        assert(current_sig is None)
                        current_sig = self.signature_t(line)
                        state = STATE_IN_SIG
                    elif state == STATE_IN_SIG:
                        assert(current_sig is not None)
                    elif state == STATE_AFTER_SIG:
                        assert(current_sig is not None)
                        if line.startswith("Parameters"):
                            state = STATE_IN_PARAMS
                        else:
                            # print("FLUSHING!")
                            self.signatures.append(current_sig)
                            current_sig = None
                    elif state == STATE_IN_PARAMS:
                        if not line.startswith("-------"):
                            current_sig.params.append(line)
                    else:
                        crash()
                else:
                    if state == STATE_NONE:
                        pass
                    elif state == STATE_IN_SIG:
                        state = STATE_AFTER_SIG
                    elif state == STATE_AFTER_SIG:
                        pass
                    elif state == STATE_IN_PARAMS:
                        # print("FLUSHING!!")
                        self.signatures.append(current_sig)
                        current_sig = None
                        state = STATE_NONE
                    else:
                        crash()
        except AssertionError:
            verb("Couldn't parse comment; it's likely it was not generated by SWiG. Assuming 'original_comment'.")
            self.original_comment = True


class ioarg_t:
    def __init__(self, original_name, name, ptyp, desc):
        self.original_name = original_name
        self.name = name
        self.ptyp = ptyp
        self.desc = desc

    def __str__(self):
        return "{original_name=\"%s\", name=\"%s\", ptyp=\"%s\", desc=\"%s\"}" % (
            self.original_name,
            self.name,
            self.ptyp,
            self.desc)


class SDK_base_info_t:

    def __init__(self):
        self.brief = None
        self.detailed = None

    def is_valid(self):
        return self.brief or self.detailed


class SDK_func_info_t(SDK_base_info_t):
    # FIXME: Ideally, each match_t should bring its own description,
    # but that will make the resulting documentation more busy and
    # it's unclear what we would gain...
    class match_t:
        def __init__(self): #, brief, detailed):
            # self.brief = brief
            # self.detailed = detailed
            self.params = []
            self.returns = None
            self.retvals = None

    def __init__(self):
        SDK_base_info_t.__init__(self)
        self.matches = []

    def maybe_set_brief_and_detailed(self, brief, detailed):
        # set the brief+detailed info, if none was set yet
        if not self.brief and not self.detailed:
            self.brief = brief
            self.detailed = detailed

    def maybe_add_param_to_match(
            self,
            swig_generated_param_names,
            match,
            name,
            ptyp,
            desc):
        dbg("maybe_add_param_to_match(name=%s, ptyp=%s, desc=%s, swig_generated_param_names=%s)" % (
            name,
            ptyp,
            desc,
            swig_generated_param_names))
        # SWiG will rename e.g., 'from' to '_from' automatically, and we want to match that
        swig_name = ("_%s" % name) if name in ["from", "with"] else name
        to_add = None
        if swig_name in swig_generated_param_names:
            to_add = ioarg_t(name, swig_name, ptyp, desc)
        elif name == "from":
            if "frm" in swig_generated_param_names:
                to_add = ioarg_t(name, "frm", ptyp, desc)
        if to_add:
            dbg("==> adding='%s'" % (to_add,))
            match.params.append(to_add)

    def traverse(self, node, swig_generated_param_names):
        self.maybe_set_brief_and_detailed(
            doxygen_utils.get_element_description(node, "briefdescription"),
            doxygen_utils.get_element_description(node, "detaileddescription"))

        match = self.match_t()

        # collect params
        doxygen_utils.for_each_param(
            node,
            lambda name, ptyp, desc: self.maybe_add_param_to_match(
                swig_generated_param_names,
                match,
                name,
                ptyp,
                desc))

        # return value
        return_node = node.find(".//simplesect[@kind='return']")
        if return_node is not None:
            return_desc = " ".join(return_node.itertext()).strip()
            if return_desc:
                match.returns = ioarg_t(None, None, None, return_desc)

        detaileddescription_el = node.find("detaileddescription")
        if detaileddescription_el:
            def collect_retval(value, desc):
                if match.retvals is None:
                    match.retvals = []
                match.retvals.append((value, desc))
            doxygen_utils.for_each_retval(detaileddescription_el, collect_retval)

        self.matches.append(match)


    def import_from_hooks_enumerator(self, enum, swig_generated_param_names):
        self.maybe_set_brief_and_detailed(
            enum.get("brief", None),
            enum.get("detailed", None))

        match = self.match_t()

        params = enum.get("params", [])[:]

        # return value
        if params and params[0]["name"] == "<return>":
            retdata = params[0]
            params = params[1:]
            if retdata["desc"]:
                match.returns = ioarg_t(None, None, retdata["type"], retdata["desc"])
            if retdata["values"]:
                match.retvals = retdata["values"]

        # collect params
        for param in params:
            self.maybe_add_param_to_match(
                swig_generated_param_names,
                match,
                param["name"],
                param["type"],
                param["desc"])

        self.matches.append(match)


class SDK_def_info_t(SDK_base_info_t):
    def traverse(self, node):
        self.brief = doxygen_utils.get_element_description(node, "briefdescription")
        self.detailed = doxygen_utils.get_element_description(node, "detaileddescription")

    def generate_lines(self):
        out = []
        if self.brief:
            out.extend(self.brief)
        out.append("")
        if self.detailed:
            out.extend(self.detailed)
        out = doxygen_utils.remove_empty_header_or_footer_lines(out)
        return doxygen_utils.remove_empty_header_or_footer_lines(
            [DOCSTR_MARKER] \
            + list(map(lambda s : s.replace('\\', '\\\\'), out)) \
            + [DOCSTR_MARKER])


# --------------------------------------------------------------------------
class idaapi_fixer_t(object):
    lines = None

    def __init__(self, collected_pywraps_pydoc, patches, cpp_wrapper_functions):
        self.collected_pywraps_pydoc = collected_pywraps_pydoc
        self.patches = patches
        self.cpp_wrapper_functions = cpp_wrapper_functions
        self.xml_dir = None
        # Since variables cannot have a docstring in Python,
        # but epydoc supports the syntax:
        # ---
        # MYVAR = 12
        # """
        # MYVAR is the best
        # """
        # ---
        # we want to remember whatever epydoc-compatible
        # documentation we inject, since it will be impossible to
        # retrieve it from the runtime.
        self.epydoc_injections = {}

    def has_more(self):
        return len(self.lines) > 0

    def next(self):
        line = self.lines[0]
        with indenter_t():
            dbg("next(): '%s'" % line)
        self.lines = self.lines[1:]
        return line

    def copy(self, out):
        line = self.next()
        out.append(line)
        return line

    def push_front(self, line):
        self.lines.insert(0, line)

    def get_class_info(self, class_name):
        return self.collected_pywraps_pydoc["classes"].get(class_name)

    def get_def_info(self, def_name):
        def_info = None
        dnodes = self.xml_tree.findall("./compounddef/sectiondef[@kind='define']/memberdef[@kind='define']/[name='%s']" % def_name)
        ndnodes = len(dnodes)
        if ndnodes > 0:
            if ndnodes > 1:
                print("Warning: more than 1 define doc found for '%s'; picking first" % def_name)
            dd = SDK_def_info_t()
            dd.traverse(dnodes[0])
            if dd.is_valid():
                def_info = dd.generate_lines()
        return def_info

    def extract_swig_generated_param_names(self, fun_name, lines):
        def sanitize_param_name(pn):
            idx = pn.find("=")
            if idx > -1:
                pn = pn[0:idx]
            pn = pn.strip()
            return pn
        for l in lines:
            if l.find(fun_name) > -1:
                idx_open_paren = l.find("(")
                idx_close_paren = l.find(") -> ")
                if idx_close_paren == -1 and l.endswith(")"):
                    idx_close_paren = len(l) - 1
                if idx_open_paren > -1 \
                   and idx_close_paren > -1 \
                   and idx_close_paren > idx_open_paren+1:
                    clob = l[idx_open_paren+1:idx_close_paren]
                    parts = clob.split(",")
                    return list(map(sanitize_param_name, parts))
        return []

    def maybe_fix_swig_generated_docstring_prototype(self, fun_name, line):
        forced_output_type = None
        fdef = None
        for _, one in six.iteritems(self.cpp_wrapper_functions):
            if one.api_function_name == fun_name:
                fdef = one
                break
        if fdef:
            for l in fdef.contents:
                for pattern, forced in [
                        ("resultobj = _maybe_sized_cstring_result(", "str"),
                        ("resultobj = _maybe_cstring_result(", "str"),
                        ("resultobj = _maybe_binary_result(", "str"),
                        ("resultobj = _maybe_cstring_result_on_charptr_using_allocated_buf(", "str"),
                        ("resultobj = _maybe_cstring_result_on_charptr_using_qbuf(", "str"),
                        ("resultobj = _maybe_byte_array_as_hex_or_none_result(", "str"),
                        ("resultobj = _maybe_byte_array_or_none_result(", "bytes"),
                        ("resultobj = _sized_cstring_result(", "str"),
                ]:
                    if l.find(pattern) > -1:
                        assert(forced_output_type is None);
                        forced_output_type = forced
        if forced_output_type:
            splitter = " -> "
            idx = line.find(splitter)
            if idx > -1:
                line = line[0:idx + len(splitter)] + forced_output_type
        return line

    def generate_function_pydoc(self, class_name=None):
        out = []
        line = self.copy(out)
        fun_name = get_fun_name(line)
        class_info = self.get_class_info(class_name) if class_name else None

        if args.debug_function:
            global selective_debug_status
            selective_debug_status = fun_name == args.debug_function

        #verb("generate_function_pydoc: fun_name: '%s'" % fun_name)
        line = self.copy(out)
        doc_start_line_idx = len(out)
        if line.find(DOCSTR_MARKER) > -1:
            # Opening docstring line; determine indentation level
            indent = get_indent_string(line)
            docstring_line_nr = 0
            while True:
                line = self.next()
                if docstring_line_nr == 0:
                    line = self.maybe_fix_swig_generated_docstring_prototype(fun_name, line)

                if line.find(DOCSTR_MARKER) > -1:

                    # Closing docstring line
                    pydoc_lines = out[doc_start_line_idx:]
                    swig_generated_param_names = self.extract_swig_generated_param_names(fun_name, pydoc_lines)

                    if class_name is None:
                        pywraps_fi = self.collected_pywraps_pydoc["funcs"].get(fun_name)
                    else:
                        pywraps_fi = class_info["methods"].get(fun_name) if class_info else []
                    if pywraps_fi:
                        # documentation coming from pywraps takes precedence.
                        dbg("'pywraps/'-originating comment takes precedence (%s)" % str(pywraps_fi))
                        found = pywraps_fi
                        if pydoc_lines:
                            l0 = pydoc_lines[0].lstrip()
                            if l0.startswith(fun_name):
                                found = [l0] + found
                    else:
                        found = []
                        # no documentation coming from pywraps.
                        # Merge SWiG-generated documentation, and the
                        # SDK-provided bits
                        generated_fi = generated_func_info_t(pydoc_lines)
                        if generated_fi.original_comment:
                            dbg("SWiG-generated comment found (%s)" % str(pydoc_lines))
                            found = pydoc_lines
                        else:
                            sdk_fi = SDK_func_info_t()
                            fnodes = []
                            if class_name is None:
                                fnodes = doxygen_utils.get_toplevel_functions(
                                    self.xml_tree,
                                    name=fun_name)
                            else:
                                if class_name.endswith("_Hooks"):
                                    enums = hooks_utils.get_hooks_enumerators(
                                        self.xml_dir,
                                        class_name)
                                    for enum in enums:
                                        if enum["name"] == fun_name:
                                            sdk_fi.import_from_hooks_enumerator(
                                                enum,
                                                swig_generated_param_names)
                                else:
                                    refid, udt_xml_tree = doxygen_utils.load_xml_for_udt(
                                        self.xml_dir,
                                        self.xml_tree,
                                        udt_name=class_name)
                                    if udt_xml_tree:
                                        fnodes = doxygen_utils.get_udt_methods(
                                            udt_xml_tree,
                                            refid,
                                            name=fun_name)

                            for fnode in fnodes:
                                sdk_fi.traverse(fnode, swig_generated_param_names)

                            if sdk_fi.brief:
                                found.extend(sdk_fi.brief)
                                found.append("")
                            if sdk_fi.detailed:
                                found.extend(sdk_fi.detailed)
                                found.append("")

                            # We'll look in all SDK signatures (i.e., we don't
                            # do proper signature matching) and patch all params
                            # in all generated signatures information. Hopefully
                            # this will be good enough.
                            for sdk_match in sdk_fi.matches:
                                for p in sdk_match.params:
                                    dbg("Handling param '%s'" % p)
                                    if p.name:
                                        pline = "@param %s" % p.name
                                        subsequent_indent = len(pline) + 2
                                        if p.desc:
                                            pline = "%s: %s" % (pline, p.desc)
                                        if p.ptyp:
                                            pline = "%s (C++: %s)" % (pline, p.ptyp)
                                        for sig in generated_fi.signatures:
                                            sig.replace_param(p.original_name, p.name, pline, subsequent_indent)
                                if sdk_match.returns:
                                    rline = "@return: %s" % sdk_match.returns.desc
                                    for sig in generated_fi.signatures:
                                        sig.append_return(rline, len("@return: "))
                                if sdk_match.retvals:
                                    for retval_value, retval_desc in sdk_match.retvals:
                                        rvline_pfx = "@retval: %s - " % retval_value
                                        rvline = "%s%s" % (rvline_pfx, retval_desc)
                                        for sig in generated_fi.signatures:
                                            sig.append_retval(rvline, len(rvline_pfx))

                            # Append the (modified) signatures
                            for sig in generated_fi.signatures:
                                add_lines_block(found, sig.get_lines())

                    found = doxygen_utils.remove_empty_header_or_footer_lines(found)
                    if found:
                        verb("fix_%s: found info for %s" % (
                            "method" if class_name else "fun", fun_name));
                        while len(out) > doc_start_line_idx:
                            out.pop()
                        add_lines_block(out, apply_indent(found, indent))


                    #
                    # apply possible additional patches
                    #
                    fun_patches = self.patches.get(fun_name, {})

                    example = fun_patches.get("+example", None)
                    if example:
                        ex_lines = list(map(lambda l: "Python> %s" % l, example.split("\n")))
                        out.extend(list(map(lambda l: indent + l, ["", "Example:"] + ex_lines)))

                    repl_text = fun_patches.get("repl_text", None)
                    if repl_text:
                        from_text, to_text = repl_text
                        for i in range(doc_start_line_idx, len(out)):
                            out[i] = out[i].replace(from_text, to_text)

                    out.append(line)
                    break
                else:
                    out.append(line)
                docstring_line_nr += 1
        return out

    def generate_method_pydoc(self, class_name):
        return self.generate_function_pydoc(class_name)

    def generate_class_pydoc(self):
        out = []
        line = self.copy(out)
        cls_name = get_class_name(line)
        class_info = self.get_class_info(cls_name)
        verb("generate_class_pydoc: found info for %s" % cls_name);
        while True:
            line = self.copy(out)
            if line.strip():
                indent = get_indent_string(line)
                break

        # If class has doc, maybe inject additional <pydoc>
        if class_info:
            if line.find(DOCSTR_MARKER) > -1:
                while self.has_more():
                    line = self.next()
                    if line.find(DOCSTR_MARKER) > -1:
                        doc = class_info["doc"]
                        if doc is not None:
                            out.append("\n")
                            for dl in doc:
                                out.append(indent + dl)
                        out.append(line)
                        break
                    else:
                        out.append(line)

        # Iterate on class methods, and possibly patch
        # their docstring
        method_start = indent + "def "
        while self.has_more():
            line = self.next()
            # print "Fixing methods.. Line is '%s'" % line
            if line.startswith(indent) or line.strip() == "":
                if line.startswith(method_start):
                    self.push_front(line)
                    out.extend(self.generate_method_pydoc(cls_name))
                else:
                    out.append(line)
            else:
                self.push_front(line)
                break

        return out

    def fix_assignment(self, out, match):
        # out.append("LOL: %s" % match.group(1))
        line = self.copy(out)
        line = self.next()
        if not line.startswith(DOCSTR_MARKER):
            # apparently no epydoc-compliant docstring follows. Let's
            # look for a possible match in the xml doc.
            def_name = match.group(1)
            found = self.get_def_info(def_name)
            if found:
                verb("fix_assignment: found info for %s" % (def_name,))
                out.extend(found)
                self.epydoc_injections[def_name] = found[:]
        self.push_front(line)

    IDENTIFIER_PAT = r"([a-zA-Z_]([a-zA-Z_0-9]*)?)"
    IDENTIFIER_RE = re.compile(IDENTIFIER_PAT)
    SIMPLE_ASSIGNMENT_RE = re.compile(r"^(%s)\s*=.*" % IDENTIFIER_PAT)

    def fix_file(self, args):
        input_path, self.xml_dir, out_path = args.input, args.xml_doc_directory, args.output
        with open(input_path) as f:
            self.lines = split_oneliner_comments_and_remove_property_docstrings(f.readlines())
        self.xml_tree = doxygen_utils.load_xml_for_module(self.xml_dir, args.module)
        out = []
        while len(self.lines) > 0:
            line = self.next()
            if line.startswith("def "):
                self.push_front(line)
                with indenter_t():
                    out.extend(self.generate_function_pydoc())
            elif line.startswith("class "):
                self.push_front(line)
                with indenter_t():
                    out.extend(self.generate_class_pydoc())
            else:
                m = self.SIMPLE_ASSIGNMENT_RE.match(line)
                if m:
                    self.push_front(line)
                    with indenter_t():
                        self.fix_assignment(out, m)
                else:
                    out.append(line)
        out = list(map(lambda l: l.replace("NONNULL_", ""), out))
        with open(out_path, "w") as o:
            o.write("\n".join(out))

# --------------------------------------------------------------------------
patches = load_patches(args)
collecter = collect_pywraps_pydoc_t(args.interface)
collected_pywraps_pydoc = collecter.collect()
parser = wrapper_utils.cpp_wrapper_file_parser_t(args)
cpp_wrapper_functions = parser.parse(args.cpp_wrapper)
fixer = idaapi_fixer_t(collected_pywraps_pydoc, patches, cpp_wrapper_functions)
fixer.fix_file(args)
with open(args.epydoc_injections, "w") as fout:
    for key in sorted(fixer.epydoc_injections.keys()):
        fout.write("\n\nida_%s.%s\n" % (args.module, key))
        fout.write("\n".join(fixer.epydoc_injections[key]))
