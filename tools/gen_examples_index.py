"""
Generate the index.html for the examples subdirectory,
based on structured docstrings on each Python example
"""

from __future__ import print_function
import ast
import re
import os
import sys

from argparse import ArgumentParser
parser = ArgumentParser()
parser.add_argument("-e", "--examples-dir", required=True)
parser.add_argument("-t", "--template", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()

def verb(msg):
    if args.verbose:
        print(msg)

class ProcessException(Exception):
    pass

#-------------------------------------------------------------------------------

class Examples(object):
    def __init__(self):
        self.re_indent = re.compile(r'^ *')
        self.re_tag    = re.compile(r'^ *([a-zA-Z_][a-zA-Z_0-9]*):')

        self.tags = Tags()
        self.html = None

    def template(self, path):
        with open(path, 'r') as f:
            self.html = HTML(f.read(), self.tags)

    def process(self):
        if not self.html:
            raise ProcessException('No template!')

        self.examples = []

        for relpath, path in self._files_with_extension('.py', args.examples_dir):
            verb("Processing \"%s\"" % path)
            with open(path, 'r') as f:
                self._load_ast(relpath, path, ast.parse(f.read(), path))

        self.examples = {'sub': sorted(self.examples, \
                                       key=lambda x: x[self.tags.order()])}

        self.html.produce(self.examples)

    def _load_ast(self, relpath, path, tree):
        self.tags.reset()
        self.tags.add(Tags.PATH, relpath)
        self.tags.add(Tags.NAME, os.path.splitext(os.path.basename(path))[0])
        self.tags.add(Tags.USES, self._uses_names(tree))
        self.tags.add(Tags.CATEGORY, relpath.split(os.sep)[0])
        self._parse_structured_comment(ast.get_docstring(tree, False))
        self.examples.append(self.tags.get())

    def _parse_structured_comment(self, docstring):
        if not docstring:
            return

        first_line  = True
        group_tag   = None
        group_lines = []

        def end_group():
            if group_tag:
                self._remove_common_indentation(group_lines)

                if group_tag == Tags.DESCRIPTION:
                    item = '\n'.join(group_lines).lstrip('\n')
                elif group_tag in (Tags.KEYWORDS, Tags.SEE_ALSO):
                    item = [{group_tag: x.strip()} \
                            for x in ','.join(group_lines).split(',')]
                else:
                    item = ' '.join(group_lines)

                self.tags.add(group_tag, item)

        # Blocks of lines are separated by an empty line.
        # An attempt is made to preserve the original indentation
        # of each block of lines.
        #
        # If a block of lines wishes to contain a blank line,
        # it must represent it with a line containing only a dot ('.')
        # (indentation is irrelevant for these 'dot' lines).
        # Example:
        #    description:
        #        This is one
        #        big paragraph
        #    .
        #        This is another
        #        big paragraph
        #    .
        #        This is the final
        #        big paragraph

        warned = False

        for line in docstring.split('\n'):
            indent, line = self._indented_line(line.rstrip(), 0)

            if line == '':
                end_group()
                first_line  = True
                group_tag   = None
                group_lines = []
                continue

            if first_line:
                first_line = False

                m = self.re_tag.match(line)
                if not m:
                    if not warned:
                        warned = True
                        path = self.tags.get()[Tags.PATH]
                        verb('{}:\n  No tag in docstring'.format(path))
                    continue

                group_tag = m.group(1)
                if not self.tags.is_valid(group_tag) or \
                   not self.tags.can_occur_in_docstring(group_tag):
                    path = self.tags.get()[Tags.PATH]
                    msg  = self.tags.error_message(group_tag)
                    verb('{}:\n  {}'.format(path, msg))
                    group_tag = None

                indent, line = self._indented_line(line, m.end())

            if group_tag:
                group_lines.append( (indent, line) )

        end_group()

    def _indented_line(self, line, fromPos):
        line = line[fromPos:]

        m = self.re_indent.match(line)

        indent = fromPos + len(m.group())
        line   = line[m.end():]

        if line == '.':
            return None, None

        return indent, line

    def _remove_common_indentation(self, lines):
        if not lines:
            return

        min_indent = min(t[0] for t in lines if t[1])

        for i in range(len(lines)):
            if lines[i][1]:
                lines[i] = ((lines[i][0] - min_indent) * ' ') + lines[i][1]
            else:
                lines[i] = ''

    def _uses_names(self, tree):
        names = set()
        def callback(name):
            names.add(name)

        visitor = TreeVisitor(callback, ['idc', 'idautils'])
        visitor.generic_visit(tree)
        return [{Tags.USES: name} for name in sorted(names)]

    def _files_with_extension(self, ext, rootdir):
        for path, _, files in os.walk(rootdir):
            for filename in files:
                if os.path.splitext(filename)[1] == ext:
                    relpath = os.path.relpath(path, rootdir)
                    yield os.path.join(relpath, filename), \
                          os.path.join(path, filename)

#-------------------------------------------------------------------------------

class Tags(object):
    NAME        = "name"
    PATH        = "path"
    SUMMARY     = "summary"
    DESCRIPTION = "description"
    CATEGORY    = "category"
    KEYWORDS    = "keywords"
    USES        = "uses"
    SEE_ALSO    = "see_also"
    JSDATA      = "jsdata"

    # tags that can be used in the template (as a <!--gen:xxx--> comment)
    ALL_TAGS = set([NAME, PATH, SUMMARY, DESCRIPTION, CATEGORY, \
                    KEYWORDS, USES, SEE_ALSO, JSDATA])

    # tags that can be used in the examples' docstrings
    IN_DOCSTRING = set([SUMMARY, DESCRIPTION, CATEGORY, \
                        KEYWORDS, USES, SEE_ALSO])

    def __init__(self):
        self.tags = {}
        self.reset()

    def order(self):
        return self.NAME

    def error_message(self, name):
        return 'Unrecognized tag: "{}"'.format(name)

    def check(self, name):
        if name not in self.ALL_TAGS:
            raise ProcessException(self.error_message(name))

    def is_valid(self, name):
        return name in self.ALL_TAGS

    def can_occur_in_docstring(self, tag):
        return tag in self.IN_DOCSTRING

    def reset(self):
        self.items = {}
        for tag in self.ALL_TAGS:
            if tag in (self.KEYWORDS, self.USES, self.SEE_ALSO):
                self.items[tag] = []
            elif tag != self.JSDATA:
                self.items[tag] = ''

    def add(self, tag, item):
        self.items[tag] = item

    def get(self):
        return self.items

#-------------------------------------------------------------------------------

class TreeVisitor(ast.NodeVisitor):
    def __init__(self, callback, interesting_names, *args):
        super(TreeVisitor, self).__init__(*args)
        self.my_callback = callback
        self.interesting_names = set(interesting_names)

    def visit_ImportFrom(self, node):
        if self._is_interesting(node.module):
            self._add_interesting_names(node.names)

    def _add_interesting_names(self, aliases):
        for alias in aliases:
            if isinstance(alias, ast.alias):
                name = alias.asname if alias.asname else alias.name
                self.interesting_names.add(name)

    def _is_interesting(self, name):
        return name.startswith('ida_') or name in self.interesting_names

    def visit_Name(self, node):
        self._callback_if_interesting(node)

    def visit_Attribute(self, node):
        self._callback_if_interesting(node)

    def _callback_if_interesting(self, node):
        names = self._dotted_name(node)
        if not names:
            return
        if self._is_interesting(names[0]) \
           and names[-1] != '__init__':     # removed calls to base constructors
            self.my_callback('.'.join(names))

    def _dotted_name(self, node):
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            names = self._dotted_name(node.value)
            if names:
                return names + [node.attr]
        return None

#-------------------------------------------------------------------------------

class HTML(object):
    def __init__(self, template, tags):
        self.replacer = TemplateReplacer(tags)

        self.replacer.template(template)

    def produce(self, examples):
        with open(args.output, 'w') as f:
            self.replacer.expand(examples, f)

#-------------------------------------------------------------------------------

class SpecialBlock(object):
    GROUP = 0
    FIRST = 1
    LAST  = 2

    def __init__(self, kind, payload=None):
        self.kind    = kind
        self.payload = payload

#-------------------------------------------------------------------------------

class TemplateReplacer(object):
    def __init__(self, tags):
        self.tags = tags

        self.re_variable = re.compile(r'(?i)<!--gen:([a-z_]+)-->')

        self.comment_block = '<!--gen:block-->'
        self.comment_end   = '<!--gen:end-->'

        self.comment_group = re.compile(r'<!--gen:group:([a-z_]+)-->$')

        self.comment_first = '<!--gen:first-->'
        self.comment_last  = '<!--gen:last-->'

    def template(self, content):
        lines = content.strip().split('\n')

        # convert the file content, with block-end repetition blocks,
        # into a list of (1) strings and (2) nested lists for blocks

        stack = [[]]

        for line in lines:
            clean = line.strip().lower()
            if clean == self.comment_block:
                stack.append([])
            elif clean == self.comment_end:
                if len(stack) == 0:
                    raise ProcessException('mismatched gen:end')
                d = stack.pop()
                stack[-1].append(d)
            elif clean == self.comment_first:
                # open block
                stack.append([SpecialBlock(SpecialBlock.FIRST)])
            elif clean == self.comment_last:
                # open block
                stack.append([SpecialBlock(SpecialBlock.LAST)])
            else:
                m = self.comment_group.match(clean)
                if m:
                      v = m.group(1)
                      self.tags.check(v)
                      # open block
                      stack.append([SpecialBlock(SpecialBlock.GROUP, v)])
                else:
                    stack[-1].append(line)

        self.template = stack.pop()

        if len(stack) != 0:
            raise ProcessException('gen:block/group without gen:end')

    def expand(self, data, f):
        self._expand(self.template, data, None, f)

    def _expand(self, block, data, conditions, f):
        self._verify_block(block, data)

        if not isinstance(block, list):
            raise ProcessException('Expected block')

        for line in block:
            if isinstance(line, list):
                first = False # meaning, restrict/show only the first
                last  = False
                if line and isinstance(line[0], SpecialBlock):
                    special = line[0]
                    line    = line[1:]
                    if special.kind == SpecialBlock.GROUP:
                        gvar   = special.payload
                        subkey = 'sub'
                    elif special.kind == SpecialBlock.FIRST:
                        first  = True
                        subkey = None
                    elif special.kind == SpecialBlock.LAST:
                        last   = True
                        subkey = None
                    else:
                        raise ProcessException('Unknown SpecialBlock: {} {}' \
                                               .format(special.kind,
                                                       repr(special.payload)))
                else:
                    # regular block
                    gvar   = None
                    subkey = self._obtain_subkey(line)

                if subkey is None:
                    # (i.e. first,last): multiple lines but no data repetition
                    if conditions:
                        if first and not conditions[0]:
                            continue
                        if last  and not conditions[1]:
                            continue
                    self._expand(line, data, None, f)
                    continue

                subdata = data[subkey]

                if not isinstance(subdata, list):
                    raise ProcessException('Expected multiple data for {}' \
                                           .format('group' if gvar else 'block'))

                # repeat for each item

                if gvar:
                    subdata = self._group_by(subdata, gvar)

                n_items = len(subdata)
                for i in range(n_items):
                    conditions = i == 0, i == n_items - 1
                    self._expand(line, subdata[i], conditions, f)
                continue

            f.write(self._substitute_variables(line, data))
            f.write('\n')

    def _obtain_subkey(self, block):
        # presently (we don't need more at the moment)
        # a block contains either:
        #   - a single variable inside, under the key = variable
        #   - multiple variables, under a constant key = 'sub'
        #     (so just one per block)

        variables = set()

        for line in block:
            if isinstance(line, list):
                continue  # only this level

            for key, _, _ in self._variables_in_line(line):
                variables.add(key)

        for key in variables:
            break # get first

        return key if len(variables) == 1 else 'sub'

    def _group_by(self, data, gvar):
        # data assumed already sorted
        grouped = {}
        for item in data:
            value = item[gvar]
            if isinstance(value, list):
                for obj in value:
                    subvalue = obj[gvar]
                    if subvalue not in grouped:
                        grouped[subvalue] = []
                    grouped[subvalue].append(item)
            else:
                if value not in grouped:
                    grouped[value] = []
                grouped[value].append(item)

        return [{gvar: key, 'sub': grouped[key]} for key in sorted(grouped)]

    def _substitute_variables(self, line, data):
            out  = ''
            last = 0
            for key, start, end in self._variables_in_line(line):
                sub  = self._substitution_string(key, data)
                out += line[last:start] + sub
                last = end
            out += line[last:]

            return out

    def _substitution_string(self, key, data):
        if key != Tags.JSDATA:
            value = data[key]
            if key == Tags.PATH:
                value = "/".join(value.split(os.sep))
            return str(value)

        if 'sub' not in data:
            ProcessException('Please use <!--gen:{}--> at the top level only' \
                             .format(Tags.JSDATA))
        data = data['sub']

        # JavaScript representation of the data
        js    = '// collected data\nexamples = ['
        first = True
        for item in data:
            if first:
                first = False
            else:
                js += ','
            js += '\n' + self._js_example(item)
        js += '\n];'

        return js

    def _js_example(self, data):
        first = True
        js    = '{'
        for tag in Tags.ALL_TAGS:
            if tag in data and data[tag]:
                if first:
                    first = False
                else:
                    js += ','
                js += "'" + tag + "': " + self._js_subdata(tag, data[tag])
        js += '}'
        return js

    def _js_subdata(self, tag, subdata):
        if isinstance(subdata, list):
            # no need to recurse, these are object enclosing a single item
            subdata = [x[tag] for x in subdata]

        return repr(subdata)

    def _verify_block(self, block, data):
        # check that all variables at the first 'flat' level of this block
        # are present in the data and are not sublists
        # (which would require an inner block)

        for line in block:
            if isinstance(line, list):
                continue  # check only the flat level

            for key, _, _ in self._variables_in_line(line):
                if key == Tags.JSDATA:
                    continue
                if key not in data:
                    raise ProcessException('No keyword "{}" in data' \
                                           .format(key))
                if isinstance(data[key], list):
                    raise ProcessException('Missing block for multiple "{}" data' \
                                           .format(key))

    def _variables_in_line(self, line):
        pos = 0
        while True:
            m = self.re_variable.search(line, pos)
            if m is None:
                break

            tag = m.group(1).lower()
            self.tags.check(tag)

            yield tag, m.start(), m.end()
            pos = m.end()

try:
    e = Examples()
    e.template(args.template)
    e.process()
except ProcessException as ex:
    print('? {}\n  {}'.format(sys.argv[0], ex))
    sys.exit(1)
# other exceptions - let them fail
