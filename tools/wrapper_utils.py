
from __future__ import with_statement
from __future__ import print_function

import re

class TextStream:
    def __init__(self, text):
        self.text = text
        self.point = 0
        self.maxpoint = len(self.text)
        self.line_nr = 0
        self.char_nr = 0

    def line(self):
        pt = self.point
        self.advance_to_newline()
        return self.text[pt : self.point]

    def char(self):
        c, self.point = self.text[self.point], self.point + 1
        if c == '\n':
            self.line_nr += 1
            self.char_nr = 0
        return c

    def advance_to_newline(self):
        p = self.point
        while self.text[p] != '\n':
            p += 1
        p += 1
        self.line_nr += 1
        self.char_nr = 0
        self.point = p

    def empty(self):
        return self.point >= self.maxpoint


class function_def_t:
    def __init__(self, api_function_name, line_nr, contents):
        self.api_function_name = api_function_name
        self.line_nr = line_nr
        self.contents = contents


class cpp_wrapper_file_parser_t:

    API_FNAME_REGEX = re.compile(".*PyObject \\*_wrap_([^\\(]*)\\(.*\\).*")

    def __init__(self, args):
        self.args = args
        self.text = None

    def _is_fundecl(self, line):
        if len(line) <= 2:
            return None
        if line[0:1].isspace():
            return None
        if line[len(line)-1:] != "{":
            return None
        open_paren_idx = line.find("(")
        if open_paren_idx == -1 or line.find(")") == -1:
            return None
        part = line[0:open_paren_idx]
        for idx in range(len(part) - 1, 0, -1):
            c = part[idx]
            if not c.isalnum() and c not in ["_"]:
                return part[idx+1:]

    def _collect_funbody_lines(self, ts):
        pt = ts.point
        braces_cnt = 1
        while True:
            c = ts.char()
            if c == "{":
                braces_cnt = braces_cnt + 1
            elif c == "}":
                braces_cnt = braces_cnt - 1
                if braces_cnt == 0:
                    break;
            # TODO: Skip strings!
        return ts.text[pt : ts.point].split("\n")

    def verb(self, msg):
        if self.args.verbose:
            print("DEBUG: %s" % msg)

    def parse(self, path):
        with open(path) as f:
            self.text = f.read()

        ts = TextStream(self.text)
        functions = {}

        # Process lines
        while not ts.empty():
            line = ts.line().rstrip()
            # self.verb("Line: '%s'" % line)

            fname = self._is_fundecl(line)
            if fname:

                # self.verb("Entering function (from line %d: '%s')" % (ts.line_nr, line))
                line_nr = ts.line_nr
                match = self.API_FNAME_REGEX.match(line)
                api_fname = match.group(1) if match else None
                body = self._collect_funbody_lines(ts)
                functions[fname] = function_def_t(api_fname, line_nr, [line] + body)

        return functions
