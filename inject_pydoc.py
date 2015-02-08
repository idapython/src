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

import re
import os
import os.path

DOCSTR_MARKER  = "\"\"\""

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
class collect_idaapi_pydoc_t(object):
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
    DOCSTR_MARKER  = DOCSTR_MARKER #"\"\"\""
    state = S_UNKNOWN
    lines = None

    def __init__(self):
        self.idaapi_pydoc = {"funcs" : {}, "classes" : {}}

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
                elif line.find(self.DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_DOCSTR
                elif not line.startswith("    "):
                    return self.set_fun(fun_name, collected)
            elif self.state is self.S_IN_DOCSTR:
                if line.find(self.DOCSTR_MARKER) > -1:
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
                elif line.find(self.DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_DOCSTR
            elif self.state is self.S_IN_DOCSTR:
                if line.find(self.DOCSTR_MARKER) > -1:
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
                elif line.find(self.DOCSTR_MARKER) > -1:
                    self.state = self.S_IN_DOCSTR
                elif line.startswith(self.PYDOC_END):
                    self.state = self.S_UNKNOWN
                    return self.set_class(cls_name, cls, collected)
                elif len(line) > 1 and not line.startswith("    "):
                    return self.set_class(cls_name, cls, collected)
            elif self.state is self.S_IN_DOCSTR:
                if line.find(self.DOCSTR_MARKER) > -1:
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

    def collect(self, dirpath):
        for root, dirs, files in os.walk(dirpath):
            for f in files:
                self.collect_file_pydoc(os.path.join(root, f))
        return self.idaapi_pydoc


# --------------------------------------------------------------------------
class idaapi_fixer_t(object):
    lines = None

    def __init__(self, collected_info):
        self.collected_info = collected_info

    def next(self):
        line = self.lines[0]
        self.lines = self.lines[1:]
        return line

    def copy(self, out):
        line = self.next()
        out.append(line)
        return line

    def push_front(self, line):
        self.lines.insert(0, line)

    def get_fun_info(self, fun_name):
        if fun_name in self.collected_info["funcs"]:
            return self.collected_info["funcs"][fun_name]
        else:
            return None

    def get_class_info(self, class_name):
        if class_name in self.collected_info["classes"]:
            return self.collected_info["classes"][class_name]
        else:
            return None

    def get_method_info(self, class_info, method_name):
        if method_name in class_info["methods"]:
            return class_info["methods"][method_name]
        else:
            return None

    def fix_fun(self, out, class_info=None):
        line = self.copy(out)
        fun_name = get_fun_name(line)
        line = self.copy(out)
        if line.find(DOCSTR_MARKER) > -1:
            # Determine indentation level
            indent = get_indent_string(line)
            while True:
                line = self.next()
                if line.find(DOCSTR_MARKER) > -1:
                    if class_info is None:
                        found = self.get_fun_info(fun_name)
                    else:
                        found = self.get_method_info(class_info, fun_name)
                    if found is not None:
                        out.append("\n")
                        for fl in found:
                            out.append(indent + fl)
                    out.append(line)
                    break
                else:
                    out.append(line)

    def fix_method(self, class_info, out):
        return self.fix_fun(out, class_info)

    def fix_cls(self, out):
        line = self.copy(out)
        cls_name = get_class_name(line)
        class_info = self.get_class_info(cls_name)
        if class_info is None:
            return

        line = self.copy(out)
        indent = get_indent_string(line)

        # If class has doc, maybe inject additional <pydoc>
        if line.find(DOCSTR_MARKER) > -1:
            while True:
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
        while True:
            line = self.next()
            # print "Fixing methods.. Line is '%s'" % line
            if line.startswith(indent) or line.strip() == "":
                if line.startswith(method_start):
                    self.push_front(line)
                    self.fix_method(class_info, out)
                else:
                    out.append(line)
            else:
                self.push_front(line)
                break

    def fix_file(self, idaapi_filename, out_filename):
        with open(idaapi_filename, "rt") as f:
            self.lines = split_oneliner_comments(f.readlines())
        out = []
        while len(self.lines) > 0:
            line = self.next()
            # print "LINE: %s" % line
            if line.startswith("def "):
                self.push_front(line)
                self.fix_fun(out)
            elif line.startswith("class "):
                self.push_front(line)
                self.fix_cls(out)
            else:
                out.append(line)
        with open(out_filename, "wt") as o:
            for ol in out:
                o.write(ol)
                o.write("\n")

# --------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    collecter = collect_idaapi_pydoc_t()
    collected = collecter.collect(sys.argv[1])
    # import pprint
    # pprint.pprint(collected, indent=2)
    fixer = idaapi_fixer_t(collected)
    target_file = sys.argv[2]
    result_file = sys.argv[3]
    fixer.fix_file(target_file, result_file)
