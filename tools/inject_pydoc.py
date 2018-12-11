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

try:
    from argparse import ArgumentParser
except:
    print("Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'")
    raise

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-w", "--wrapper", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-x", "--xml-doc-directory", required=True)
parser.add_argument("-e", "--epydoc-injections", required=True)
parser.add_argument("-m", "--module", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()

this_dir, _ = os.path.split(__file__)
sys.path.append(this_dir)
import doxygen_utils

DOCSTR_MARKER  = '"""'

def verb(msg):
    if args.verbose:
        print(msg)

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
def split_oneliner_comments(lines):
    out_lines = []
    for line in lines:

        line = line.rstrip()

        if line.startswith("#"):
            out_lines.append(line)
            continue

        if len(line) == 0:
            out_lines.append("")
            continue

        pfx = None
        while line.find(DOCSTR_MARKER) > -1:
            idx  = line.find(DOCSTR_MARKER)
            meat = line[0:idx]
            try:
                if len(meat.strip()) == 0:
                    pfx = meat
                    out_lines.append(pfx + DOCSTR_MARKER)
                else:
                    out_lines.append((pfx if pfx is not None else "") + meat)
                    out_lines.append((pfx if pfx is not None else "") + DOCSTR_MARKER)
            except:
                raise BaseException("Error at line: " + line)
            line = line[idx + len(DOCSTR_MARKER):]
        if len(line.strip()) > 0:
            out_lines.append((pfx if pfx is not None else "") + line)
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
    return map(proc, lines)

# --------------------------------------------------------------------------
def get_fun_name(line):
    return re.search("def ([^\(]*)\(", line).group(1)

# --------------------------------------------------------------------------
def get_class_name(line):
    return re.search("class ([^\(:]*)[\(:]?", line).group(1)

# --------------------------------------------------------------------------
def get_indent_string(line):
    indent = len(line) - len(line.lstrip())
    return " " * indent

# --------------------------------------------------------------------------
class collect_pydoc_t(object):
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
            line = next(self)
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
            line = next(self)
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
            line = next(self)
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
        with open(filename, "rt") as f:
            self.lines = split_oneliner_comments(f.readlines())
        context = None
        doc = []
        while len(self.lines) > 0:
            line = next(self)
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


class base_doc_t:
    def __init__(self):
        self.brief = None
        self.detailed = None

    def add_token_nostrip(self, out, token):
        if token:
            out.append(token)

    def add_token(self, out, token):
        if token:
            return self.add_token_nostrip(out, token.strip())

    def get_text_with_refs1(self, out, node):
        if node.tag == "simplesect" and node.attrib.get("kind") == "return":
            return
        if node.tag == "parameterlist":
            return
        if node.tag == "ref":
            self.add_token_nostrip(out, " '%s' " % node.text)
        else:
            self.add_token(out, node.text)
        self.add_token(out, node.tail)
        for child in node:
            self.get_text_with_refs1(out, child)

    def remove_empty_header_or_footer_lines(self, lines):
        while lines and not lines[0].strip():
            lines = lines[1:]
        while lines and not lines[-1].strip():
            lines = lines[:-1]
        return lines

    def get_description(self, node, child_tag):
        out = []
        for child in node.findall("./%s" % child_tag):
            one = []
            self.get_text_with_refs1(one, child)
            if one:
                clob = "".join(one)
                if clob:
                    out.extend(textwrap.wrap(clob))
        return self.remove_empty_header_or_footer_lines(out)

    def is_valid(self):
        return self.brief or self.detailed

    def append_lines(self, out):
        tmp = self.generate_lines()
        tmp = self.remove_empty_header_or_footer_lines(tmp)
        if tmp:
            out.extend(tmp)

    def generate_lines(self):
        unimp()


class ioarg_t:
    def __init__(self, name, ptyp, desc):
        self.name = name
        self.ptyp = ptyp
        self.desc = desc


class fun_doc_t(base_doc_t):
    def __init__(self):
        base_doc_t.__init__(self)
        self.params = []
        self.retval = None

    def traverse(self, node, swig_generated_param_names):
        self.brief = self.get_description(node, "briefdescription")
        self.detailed = self.get_description(node, "detaileddescription")

        # collect params
        def add_param(name, ptyp, desc):
            if name == "from":
                name = "_from" # SWiG will rename 'from' to '_from' automatically, and we want to match that
            if name in swig_generated_param_names:
                self.params.append(ioarg_t(name, ptyp, desc))
        doxygen_utils.for_each_param(node, add_param)

        # return value
        return_node = node.find(".//simplesect[@kind='return']")
        if return_node is not None:
            return_desc = " ".join(return_node.itertext()).strip()
            if return_desc:
                self.retval = ioarg_t(None, None, return_desc)

    def generate_lines(self):
        out = []
        if self.brief:
            out.extend(self.brief)
        out.append("")
        if self.detailed:
            out.extend(self.detailed)
        out.append("")
        for p in self.params:
            pline = ""
            subsequent_indent = 0
            if p.name:
                pline = "@param %s" % p.name
            if p.desc:
                if pline:
                    subsequent_indent = len(pline) + 2
                pline = "%s: %s" % (pline, p.desc)
            if p.ptyp:
                pline = "%s (C++: %s)" % (pline, p.ptyp)
            if pline:
                plines = textwrap.wrap(pline, 70, subsequent_indent=" " * subsequent_indent)
                out.extend(plines)
        if self.retval:
            rline = "@return: %s" % self.retval.desc
            rlines = textwrap.wrap(rline, 70, subsequent_indent=" " * len("@return: "))
            out.extend(rlines)
        return out


class def_doc_t(base_doc_t):
    def __init__(self):
        base_doc_t.__init__(self)

    def traverse(self, node):
        self.brief = self.get_description(node, "briefdescription")
        self.detailed = self.get_description(node, "detaileddescription")

    def generate_lines(self):
        out = []
        if self.brief:
            out.extend(self.brief)
        out.append("")
        if self.detailed:
            out.extend(self.detailed)
        out = self.remove_empty_header_or_footer_lines(out)
        return [DOCSTR_MARKER] + out + [DOCSTR_MARKER]


# --------------------------------------------------------------------------
def collect_structured_fun_doc(node, swig_generated_param_names):
    fd = fun_doc_t()
    fd.traverse(node, swig_generated_param_names)
    if fd.is_valid():
        return fd


# --------------------------------------------------------------------------
class idaapi_fixer_t(object):
    lines = None

    def __init__(self, collected_info, patches):
        self.collected_info = collected_info
        self.patches = patches
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

    def next(self):
        line = self.lines[0]
        self.lines = self.lines[1:]
        return line

    def copy(self, out):
        line = next(self)
        out.append(line)
        return line

    def push_front(self, line):
        self.lines.insert(0, line)

    def get_fun_info(self, fun_name, swig_generated_param_names):
        fun_info = self.collected_info["funcs"].get(fun_name)
        if not fun_info:
            # def get_all_functions(xml_tree, name=None):
            fnodes = doxygen_utils.get_toplevel_functions(self.xml_tree, name=fun_name)
            nfnodes = len(fnodes)
            if nfnodes > 0:
                if nfnodes > 1:
                    print("Warning: more than 1 function doc found for '%s'; picking first" % fun_name)

                fd = fun_doc_t()
                fd.traverse(fnodes[0], swig_generated_param_names)
                if fd.is_valid():
                    fun_info = []
                    fd.append_lines(fun_info)
        return fun_info

    def get_class_info(self, class_name):
        return self.collected_info["classes"].get(class_name)

    def get_method_info(self, class_info, method_name):
        return class_info["methods"].get(method_name)

    def get_def_info(self, def_name):
        def_info = None
        dnodes = self.xml_tree.findall("./compounddef/sectiondef[@kind='define']/memberdef[@kind='define']/[name='%s']" % def_name)
        ndnodes = len(dnodes)
        if ndnodes > 0:
            if ndnodes > 1:
                print("Warning: more than 1 define doc found for '%s'; picking first" % def_name)
            dd = def_doc_t()
            dd.traverse(dnodes[0])
            if dd.is_valid():
                def_info = []
                dd.append_lines(def_info)
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
                    return map(sanitize_param_name, parts)
        return []

    def fix_fun(self, out, class_info=None):
        line = self.copy(out)
        fun_name = get_fun_name(line)
        # verb("fix_fun: fun_name: '%s'" % fun_name)
        line = self.copy(out)
        doc_start_line_idx = len(out)
        if line.find(DOCSTR_MARKER) > -1:
            # Opening docstring line; determine indentation level
            indent = get_indent_string(line)
            while True:
                line = next(self)
                if line.find(DOCSTR_MARKER) > -1:
                    # Closing docstring line
                    swig_generated_param_names = self.extract_swig_generated_param_names(fun_name, out[doc_start_line_idx:])
                    if class_info is None:
                        found = self.get_fun_info(fun_name, swig_generated_param_names)
                    else:
                        found = self.get_method_info(class_info, fun_name)
                    if found:
                        verb("fix_%s: found info for %s" % (
                            "method" if class_info else "fun", fun_name));
                        out.append("\n")
                        out.extend(map(lambda l: indent + l, found))


                    #
                    # apply possible additional patches
                    #
                    fun_patches = self.patches.get(fun_name, {})

                    example = fun_patches.get("+example", None)
                    if example:
                        ex_lines = map(lambda l: "Python> %s" % l, example.split("\n"))
                        out.extend(map(lambda l: indent + l, ["", "Example:"] + ex_lines))

                    repl_text = fun_patches.get("repl_text", None)
                    if repl_text:
                        from_text, to_text = repl_text
                        for i in xrange(doc_start_line_idx, len(out)):
                            out[i] = out[i].replace(from_text, to_text)

                    out.append(line)
                    break
                else:
                    out.append(line)

    def fix_method(self, class_info, out):
        return self.fix_fun(out, class_info)

    def fix_class(self, out):
        line = self.copy(out)
        cls_name = get_class_name(line)
        found = self.get_class_info(cls_name)
        if found is None:
            return

        verb("fix_class: found info for %s" % cls_name);
        line = self.copy(out)
        indent = get_indent_string(line)

        # If class has doc, maybe inject additional <pydoc>
        if line.find(DOCSTR_MARKER) > -1:
            while True:
                line = next(self)
                if line.find(DOCSTR_MARKER) > -1:
                    doc = found["doc"]
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
        while True:
            line = next(self)
            # print "Fixing methods.. Line is '%s'" % line
            if line.startswith(indent) or line.strip() == "":
                if line.startswith(method_start):
                    self.push_front(line)
                    self.fix_method(found, out)
                else:
                    out.append(line)
            else:
                self.push_front(line)
                break

    def fix_assignment(self, out, match):
        # out.append("LOL: %s" % match.group(1))
        line = self.copy(out)
        line = next(self)
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
        input_path, xml_dir_path, out_path = args.input, args.xml_doc_directory, args.output
        with open(input_path, "rt") as f:
            self.lines = split_oneliner_comments(f.readlines())
        self.xml_tree = doxygen_utils.load_xml_for_module(xml_dir_path, args.module)
        out = []
        while len(self.lines) > 0:
            line = next(self)
            if line.startswith("def "):
                self.push_front(line)
                self.fix_fun(out)
            elif line.startswith("class "):
                self.push_front(line)
                self.fix_class(out)
            else:
                m = self.SIMPLE_ASSIGNMENT_RE.match(line)
                if m:
                    self.push_front(line)
                    self.fix_assignment(out, m)
                else:
                    out.append(line)
        with open(out_path, "wt") as o:
            o.write("\n".join(out))

# --------------------------------------------------------------------------
patches = load_patches(args)
collecter = collect_pydoc_t(args.wrapper)
collected = collecter.collect()
fixer = idaapi_fixer_t(collected, patches)
fixer.fix_file(args)
with open(args.epydoc_injections, "wb") as fout:
    for key in sorted(fixer.epydoc_injections.keys()):
        fout.write("\n\nida_%s.%s\n" % (args.module, key))
        fout.write("\n".join(fixer.epydoc_injections[key]))
