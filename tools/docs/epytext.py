
import re

class HR_Epytext:
    def __init__(self, text):
        self.html_translation = {
            "&" : "&amp;",
            "<" : "&lt;",
            ">" : "&gt;",
            "\"": "&quot;",
            "'" : "&apos;"
        }

        identifier = r"[a-zA-Z_][a-zA-Z_0-9]*"
        parameter  = r"{}(?:=[^,)]*)?".format(identifier)
        macro_tail = r"(?:[^,}]+,)*(?:[^,}]+})?"

        self.re_non_blank  = re.compile(r"[^ ]")
        self.re_identifier = re.compile(r" *({})" \
                                        .format(identifier))
        self.re_signature  = re.compile(r"^ *{} *\( *({} *(, *{} *)*)?\) *(->.*)?$" \
                                        .format(identifier, parameter, parameter))
        self.re_ident_list = re.compile(r" *({}(?: *, *{})*)" \
                                        .format(identifier, identifier))
        self.re_macro      = re.compile(r"\\ *({}) *{{({})" \
                                        .format(identifier, macro_tail))
        self.re_macro_more = re.compile(macro_tail)

        self.blocks = self._blocks(text)

    def html(self):
        text = ""
        for block in self.blocks:
            text += block.format()
        return text

    def _blocks(self, text):
        state    = state_t()
        blocks   = []
        fields   = False
        flen     = 0
        stack    = []
        in_macro = False

        def end():
            # close the current paragraph (if it has text at all)
            if state.text:
                while stack and state.indent <= stack[-1][0]: # nest blocks
                    stack.pop()

                parent = stack[-1][1] if stack else None
                block  = parblock_t(parent, fields, flen,
                                    state.indent, state.text, state.bullet)

                stack.append( (state.indent, block) )

                blocks.append(block)
                state.reset()

        lines = text.split("\n")
        for line in lines:
            m     = self.re_non_blank.search(line)
            start = m.start() if m else 0
            line  = line[start:]

            if in_macro:
                m = self.re_macro_more.match(line)
                if m:
                    macro_tail = self._more_macro_tail(macro_tail, m.group(0))
                    if not self._is_macro_end(macro_tail):
                        continue
                else:
                    # broken macro end; finish it here
                    self._verb("broken macro \"{}\" {{ \"{}\", end: \"{}\"".format(
                               macro_name, macro_tail, line))
                in_macro = False
                state.text += self._expand_macro(macro_name, macro_tail)
                line = line[m.end():]
            else:
                m = self.re_macro.search(line)
                if m:
                    self._process_line(start, line[:m.start()], state, end)
                    macro_name = m.group(1)
                    macro_tail = m.group(2)
                    in_macro = not self._is_macro_end(macro_tail)
                    if in_macro:
                        continue
                    state.text += self._expand_macro(macro_name, macro_tail)
                    line = line[m.end():]

            self._process_line(start, line, state, end)

        end()
        blocks = self._collect_bullet_lists(blocks)

        # set up nested blocks
        top_blocks = []
        for block in blocks:
            if block.parent is None:
                top_blocks.append(block)
            else:
                block.parent.add_child(block)

        return top_blocks

    def _process_line(self, start, line, state, end):
        m = self.re_signature.match(line)
        if m:
            end()
            state.text = "<strong class=\"epy_sig\">{}</strong>".format(
                         self._escape(line))
            end()
            return

        if not line:
            end()
            return

        if line[0] == "@":
            end()
            # as per the EpyText spec, all lines from now on are fields
            fields = True
            flen   = 1

            m = self.re_identifier.match(line, 1)
            if m:
                mb   = self.re_non_blank.search(line, m.end())
                flen = mb.start() if mb else m.end()

                if m.group(1) == "param":
                    cls = "epy_parameter"
                    mp = self.re_ident_list.match(line, m.end())
                    if mp:
                        m = mp
                else:
                    cls = "epy_tag"
                line = "<strong class=\"{}\">{}</strong>" \
                       .format(cls, m.group(1)) \
                       + self._escape(line[m.end():])

        # Require at least one blank after the "-";
        # f.i. "-1 (C++: int)" is not a bullet item.
        # Allow also "* " as bullet marker.
        elif line[:2] in ("- ", "* "):
            end()
            m = self.re_non_blank.search(line, 1)
            line = self._escape(line[m.start():]) if m else ""
            state.bullet = True
        else:
            line = self._escape(line)

        if start != state.indent:
            end()
            state.indent = start

        if state.text:
            state.text += "\n"
        state.text += line

    def _more_macro_tail(self, tail, more_tail):
        # hack around textwrap
        if tail[-1:] == "-":
            return tail + more_tail
        return tail + " " + more_tail

    def _is_macro_end(self, tail):
        return tail[-1:] == "}"

    def _expand_macro(self, name, tail):
        params = self._parse_macro_tail(tail)

        if name == "sq":
            self._adjust_macro_params(params, 4, 4)
            params = [p.strip() for p in params]
            table = """
<table border="1">
  <tr><td>{}</td><td>{}</td></tr>
  <tr><td>{}</td><td>{}</td></tr>
</table>
"""
            return table.format(*params)

        if name == "link":
            self._adjust_macro_params(params, 1, 2)
            if len(params) == 1:
                params += params
            return "<a href=\"{}\">{}</a>".format(*params)

        self._verb("Unimplemented macro {}, params {}".format(repr(name), repr(params)))
        return "\\{}{{{}}}".format(name, ",".join(params))

    def _parse_macro_tail(self, tail):
        params = tail.split(",")

        if params[-1][-1:] == "}":
            params[-1] = params[-1][:-1]
        elif params[-1] == "":
            params.pop()

        return params

    def _adjust_macro_params(self, params, n_min, n_max):
        if len(params) < n_min:
            params.extend( (4 - len(params)) * [''] )
        while len(params) > n_max:
            params.pop()

    def _collect_bullet_lists(self, blocks):
        out   = []
        lists = []

        for block in blocks:
            if block.bullet:
                while lists and lists[-1].start > block.start:
                    lists.pop()
                if not lists or lists[-1].start != block.start:
                    lists.append(listblock_t(block.parent))
                    out.append(lists[-1])
                lists[-1].add_child(block)
            else:
                if lists:
                    lists = []
                out.append(block)

        return out

    def _escape(self, text):
        # avoid the multiple versions of html.escape
        trans = ""
        for c in text:
            if c in self.html_translation:
                trans += self.html_translation[c]
            else:
                trans += c
        return trans

    def _verb(self, message):
        print("VERBOSE:", message)

class state_t:
    def __init__(self, indent=None, text=None, bullet=None):
        if indent is None:
            self.reset()
        else:
            self.indent = indent
            self.text   = text
            self.bullet = bullet

    def reset(self):
        self.indent = -1
        self.text   = ""
        self.bullet = False

class block_t:
    def __init__(self, parent):
        self.parent   = parent
        self.children = []

    def add_child(self, block):
        self.children.append(block)

class parblock_t(block_t):
    def __init__(self, parent, field, flen, start, text, bullet):
        super().__init__(parent)
        self.field  = field
        self.flen   = flen
        self.start  = start
        self.text   = text
        self.bullet = bullet

    def format(self):
        start = self.start
        if self.field:
            start = max(0, start - self.flen)
        if self.parent:
            cls = "epy_nested"
            start = max(0, start - self.parent.start)
        elif self.field:
            cls = "epy_field"
        else:
            cls ="epy_par"

        tag  = "span" if self.bullet else "div"
        text = ""
        if self.text:
            text += "<{} class=\"{}\">\n".format(tag, cls)
            text += self.text
        for child in self.children:
            text += child.format()
        if self.text:
            text += "</{}>\n".format(tag)

        return text

class listblock_t(block_t):
    def __init__(self, parent):
        super().__init__(parent)

    @property
    def start(self):
        return self.children[0].start

    def format(self):
        text = "<ul class=\"epy_ul\">\n"
        for child in self.children:
            text += "<li class=\"epy_li\">" + child.format() + "</li>\n"
        text += "</ul>\n"

        return text
