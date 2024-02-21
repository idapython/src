"""
Generate the index.html/.md for the examples subdirectory,
based on structured docstrings on each Python example
"""

from __future__ import print_function
import ast
import re
import os
import sys

prog_name, _ = os.path.splitext(os.path.basename(sys.argv[0]))
prog_dir     = os.path.dirname(sys.argv[0])

from argparse import ArgumentParser
parser = ArgumentParser()
subparsers = parser.add_subparsers(dest="command")
subparsers.required = True
w_subparser = subparsers.add_parser("write")
s_subparser = subparsers.add_parser("show")

parser.add_argument("-v", "--verbose", default=False, action="store_true")
w_subparser.add_argument("-e", "--examples-dir", required=True)
w_subparser.add_argument("-t", "--template", required=True)
w_subparser.add_argument("-o", "--output", required=True)
s_subparser.add_argument("-k", "--keywords", default=False, action="store_true")
s_subparser.add_argument("-s", "--search", type=str)
s_subparser.add_argument("-e", "--examples-dir", required=True)

args = parser.parse_args()

# --------------------------------------------------------------------------
def verb(msg):
    if args.verbose:
        print(msg)

# --------------------------------------------------------------------------
class ProcessException(Exception):
    pass

# --------------------------------------------------------------------------
def read_config():
    global config

    config_path = os.path.join(prog_dir, prog_name + ".cfg")
    with open(config_path, "r", encoding="UTF-8", errors="surrogateescape") as f:
        config = ast.literal_eval(f.read())

    config["exclude"] = set(config["exclude"])

    for _, key_res in config["auto-keywords"]:
        for i in range(len(key_res)):
            key_res[i] = re.compile(key_res[i] + "$") # anchored for match()

#-------------------------------------------------------------------------------
class Examples(object):
    def __init__(self):
        self.re_indent   = re.compile(r"^ *")
        self.re_tag      = re.compile(r"^ *([a-zA-Z_][a-zA-Z_0-9]*):")
        self.re_wspace   = re.compile(r"[ \t\r\n]*")
        self.re_userlink = re.compile(r"@{(.*?)}")

        self.index = None
        self.shortcut_finder = ShortcutFinder()

    def process(self):
        if args.command == "write":
            # parses the templates, and bails out on template error
            # before going into analyzing the examples
            self.index = ExamplesIndex()

        self.examples = []

        for relpath, path in self._files_with_extension(".py", args.examples_dir):
            verb("Processing \"%s\"" % path)
            with open(path, "r", encoding="UTF-8", errors="surrogateescape") as f:
                self._load_ast(relpath, ast.parse(f.read(), path))

        self._post_read_processing()

        if args.command == "show":
            self._show()
        elif args.command == "write":
            self.index.produce(self.examples, self._collect_all_keywords())

    def _post_read_processing(self):
        self._collect_example_names()  # requisite for other post-read actions

        self._collect_imported_uses()

        # trim down the final collection

        self.examples = [e for e in self.examples \
                         if e.name not in config["exclude"]]
        self.examples = sorted(self.examples, key=lambda x: x.name)

        self._collect_example_names()  # now invalid, redo

        self._parse_description_links()
        self._check_see_also_links()

    def _show(self):
        if args.keywords:
            print("\nKeywords used:")
            for keyword in self._collect_all_keywords():
                print(" ", keyword)

        if args.search:
            print("\nExamples using \"%s\":" % args.search)
            for example in self.examples:
                if args.search in example.keywords:
                    print(" ", example.path)

    def _collect_all_keywords(self):
        all_keywords = set()
        for example in self.examples:
            all_keywords.update(example.keywords)

        return sorted(all_keywords, key=lambda x: x.lower())

    def _load_ast(self, relpath, tree):
        name     = os.path.splitext(os.path.basename(relpath))[0]
        category = relpath.split(os.sep)[0]

        # fix for Windows: paths may contain "\" instead of "/";
        # these ultimately come from os.walk() and the command line
        # (_files_with_extension(), plus args.examples_dir -> rootdir)
        relpath = relpath.replace("\\", "/")

        uses, imports = self._uses_and_imports(tree)
        docstring     = ast.get_docstring(tree, False)

        tags = Tags()
        tags.add(Tags.PATH, relpath)
        tags.add(Tags.NAME, name)
        tags.add(Tags.CATEGORY, category)

        shortcuts = sorted(self.shortcut_finder.find(tree), \
                           key=lambda x: x.lower())
        tags.add(Tags.SHORTCUTS, shortcuts)

        # the next two are kept as sets;
        # they will be sorted lists after _collect_imported_uses()
        tags.add(Tags.USES, uses)
        tags.add(Tags.IMPORTS, imports)

        self._parse_structured_comment(docstring, tags)
        self._add_autokeywords(tags)

        self.examples.append(Example(tags.get()))

    def _add_autokeywords(self, tags):
        def add_keyword(m, key_out):
            groups_dict = {str(n): m.group(n) for n in range(1, m.re.groups+1)}
            new_keyword = key_out % groups_dict

            keywords = tags.tag_so_far(Tags.KEYWORDS)
            keywords.append(new_keyword)

        global config
        autokeys = config["auto-keywords"]

        for use in tags.tag_so_far(Tags.USES):
            for key_out, key_res in autokeys:
                # check for ALL auto-keywords generated by this "use"
                for key_re in key_res:
                    # check for ANY pattern that matches this auto-keyword
                    m = key_re.match(use)
                    if m:
                        add_keyword(m, key_out)
                        break

        keywords = tags.tag_so_far(Tags.KEYWORDS)
        tags.add(Tags.KEYWORDS, sorted(keywords, key=lambda x: x.lower()))

    def _parse_structured_comment(self, docstring, tags):
        if not docstring:
            return

        first_line  = True
        group_tag   = None
        group_lines = []

        def end_group():
            if group_tag:
                self._remove_common_indentation(group_lines)

                if group_tag == Tags.DESCRIPTION:
                    item = "\n".join(group_lines).strip("\n")
                elif group_tag in (Tags.KEYWORDS, Tags.SEE_ALSO):
                    item = []
                    for x in ",".join(group_lines).split(","):
                        x = x.strip()
                        if x:
                            item.append(x)
                else:
                    item = " ".join(group_lines).strip()

                if group_tag in (Tags.SUMMARY, Tags.DESCRIPTION):
                    # capitalize first
                    m = self.re_wspace.match(item)
                    if m and m.end() < len(item):
                        item = item[:m.end()] + item[m.end()].upper() \
                                              + item[m.end()+1:]

                verb("  Read from docstring: tag \"%s\"" % group_tag)
                tags.add(group_tag, item)

        # Blocks of lines are separated by indentation:
        # a block MUST begin with a tag (followed by ":") at indent 0.
        #
        # An attempt is made to preserve the original indentation
        # of each block of lines.

        for line in docstring.split("\n"):
            indent, line = self._indented_line(line.rstrip(), 0)

            if indent == 0 and line:
                end_group()
                first_line  = True
                group_tag   = None
                group_lines = []

            if first_line:
                if not line:
                    # ignore blank lines before the first tag
                    continue
                first_line = False

                m = self.re_tag.match(line)
                if not m:
                    tags.error("No tag in docstring: \"\"\"\n%s\n\"\"\"" % docstring)

                group_tag = m.group(1)
                tags.valid(group_tag)
                tags.can_occur_in_docstring(group_tag)

                indent, line = self._indented_line(line, m.end())

            if group_tag:
                group_lines.append( (indent, line) )

        end_group()

    def _indented_line(self, line, fromPos):
        line = line[fromPos:]

        m = self.re_indent.match(line)

        indent = fromPos + len(m.group())
        line   = line[m.end():]

        return indent, line

    def _remove_common_indentation(self, lines):
        if not lines:
            return

        min_indent = min(t[0] for t in lines if t[1])

        for i in range(len(lines)):
            if lines[i][1]:
                lines[i] = ((lines[i][0] - min_indent) * " ") + lines[i][1]
            else:
                lines[i] = ""

    def _uses_and_imports(self, tree):
        names = set()
        def callback_uses(name):
            verb("  Uses \"%s\"" % name)
            names.add(name)

        imports = set()
        def callback_imports(name):
            verb("  Imports \"%s\"" % name)
            imports.add(name)

        visitor = TreeVisitor(callback_uses,
                              callback_imports,
                              ["idc", "idautils"])
        visitor.generic_visit(tree)

        return names, imports

    def _parse_description_links(self):
        # (all examples have been read already)
        for example in self.examples:
            text = example.description

            out = ""
            while True:
                m = self.re_userlink.search(text)
                if not m:
                    break

                target_name = m.group(1)
                if target_name not in self.examples_set:
                    raise ProcessException(
                        "Link in \"%s\": \"%s\" is not an example name" \
                        % (example.path, target_name))

                try:
                    subs = config["link-format"] % {'1': target_name}
                except Exception as ex:
                    raise ProcessException(
                        "Link format, %s: %s" % (type(ex).__name__, ex))

                out  = text[:m.start()] + subs
                text = text[m.end():]

            example.description = out + text

    def _check_see_also_links(self):
        # do their targets exist?
        # (all examples have been read already)
        for example in self.examples:
            for see_also in example.see_also:
                if see_also not in self.examples_set:
                    raise ProcessException(
                        "%s\n  See-also link to unexistent \"%s\""
                        % (example.path, see_also))

    def _collect_imported_uses(self):
        # if an example imports another,
        # make the parent "use" the API calls that the child "uses"
        # (this has to be done after all examples have been read)

        examples_dict = { e.name: e for e in self.examples }

        # 1. restrict the imports to examples only

        imported_set = set()
        for example in self.examples:
            example.imports &= self.examples_set
            imported_set    |= example.imports

        # 2. topological sort of the imported examples

        graph = {}
        for example in self.examples:
            for imported in example.imports:
                # this example imports other examples
                if example.name in graph:
                    graph[example.name].append(imported)
                else:
                    graph[example.name] = [imported]

        roots = set(graph) - imported_set

        # 3. add children uses to parents

        for name in roots:
            self._add_imported_uses(name, examples_dict, graph, set())

        # 4. now we can make them sorted lists instead of sets
        #    (we leave "uses" of uppercase before lowercase;
        #     the use of constants looks better this way)

        for example in self.examples:
            example.uses    = sorted(example.uses)
            example.imports = sorted(example.imports, key=lambda x: x.lower())

    def _add_imported_uses(self, name, examples_dict, graph, cycle_detect):
        # cycles shouldn't happen if we're reading code that actually works,
        # but we better protect ourselves against bad input
        cycle_detect.add(name)

        example = examples_dict[name]

        for child in graph[name]:
            if child in graph:
                if child in cycle_detect:
                    raise ProcessException("Cycle in import: %s -> %s" % (name, child))

                self._add_imported_uses(child, examples_dict, graph, cycle_detect)

            example.uses |= examples_dict[child].uses

        cycle_detect.remove(name)

    def _collect_example_names(self):
        # (after all examples have been read)
        self.examples_set = set(e.name for e in self.examples)

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
    SHORTCUTS   = "shortcuts"
    USES        = "uses"
    IMPORTS     = "imports"
    SEE_ALSO    = "see_also"
    AUTHOR      = "author"

    # tags that can be used in the template (with the {{example.XXX}} syntax)
    ALL_TAGS = set([NAME, PATH, SUMMARY, DESCRIPTION, CATEGORY, \
                    KEYWORDS, USES, IMPORTS, SEE_ALSO, AUTHOR])

    # tags that can be used in the examples' docstrings
    IN_DOCSTRING = set([SUMMARY, DESCRIPTION, CATEGORY, \
                        KEYWORDS, USES, SEE_ALSO, AUTHOR])

    def __init__(self):
        self.items = {}
        for tag in self.ALL_TAGS:
            if tag in (self.KEYWORDS, self.SEE_ALSO):
                self.items[tag] = []
            elif tag in (self.USES, self.IMPORTS):
                self.items[tag] = set()
            else:
                self.items[tag] = ""

    def error(self, message):
        raise ProcessException("%s:\n  %s" \
                               % (self.items[self.PATH], message))

    def valid(self, tag):
        if tag not in self.ALL_TAGS:
            self.error("Unrecognized tag: \"%s\"" % tag)

    def can_occur_in_docstring(self, tag):
        if tag not in self.IN_DOCSTRING:
            self.error("Not allowed in docstring: \"%s\"" % tag)

    def add(self, tag, item):
        self.items[tag] = item

    def tag_so_far(self, tag):
        return self.items[tag]

    def get(self):
        return self.items

#-------------------------------------------------------------------------------
class Example(object):
    def __init__(self, content):
        self.content = content

    def __getattr__(self, key):
        if key in self.content:
            return self.content[key]
        raise AttributeError("Example: \"%s\"" % key)

#-------------------------------------------------------------------------------
class TreeVisitor(ast.NodeVisitor):
    def __init__(self, callback_uses,
                       callback_imports,
                       interesting_names,
                       *args):
        super(TreeVisitor, self).__init__(*args)
        self.callback_uses     = callback_uses
        self.callback_imports  = callback_imports
        self.interesting_names = set(interesting_names)

    def visit_Import(self, node):
        for alias in node.names:
            self.callback_imports(alias.name)

    def visit_ImportFrom(self, node):
        self.callback_imports(node.module)

        if self._is_interesting(node.module):
            self._add_interesting_names(node.names)

    def _add_interesting_names(self, aliases):
        for alias in aliases:
            if isinstance(alias, ast.alias):
                name = alias.asname if alias.asname else alias.name
                self.interesting_names.add(name)

    def _is_interesting(self, name):
        return name.startswith("ida_") or name in self.interesting_names

    def visit_Name(self, node):
        self._callback_if_interesting(node)

    def visit_Attribute(self, node):
        self._callback_if_interesting(node)

    def _callback_if_interesting(self, node):
        names = self._dotted_name(node)
        if not names:
            return
        if self._is_interesting(names[0]) \
           and names[-1] != "__init__":     # removed calls to base constructors
            self.callback_uses(".".join(names))

    def _dotted_name(self, node):
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            names = self._dotted_name(node.value)
            if names:
                return names + [node.attr]
        return None

#-------------------------------------------------------------------------------
class ShortcutFinder(ast.NodeVisitor):
    def find(self, tree):
        self._reset()
        self.generic_visit(tree)

        return self.results

    def _reset(self):
        self.results = []
        self.stack   = []

    def generic_visit(self, node):
        # look for "action_desc_t" instances, 4th constructor parameter
        if isinstance(node, ast.Call):
            name = self._name(node.func)

            if name == "ida_kernwin.action_desc_t":
                if len(node.args) >= 4:
                    # search the scopes for value(s) of this parameter
                    values = self._find_values(node.args[3])
                    for value in values:
                        self.results.append(value)

        # assigment - fill in (string) values into the current scope
        elif isinstance(node, ast.Assign):
            names  = [self._name(t) for t in node.targets]
            scope  = self.stack[-1][1]

            value = None
            # save strings
            if isinstance(node.value, ast.Str):
                value = node.value.s
            # save also lists of names, in case they are class names
            elif isinstance(node.value, ast.List):
                if all(isinstance(elt, ast.Name) for elt in node.value.elts):
                    value = [elt.id for elt in node.value.elts]

            for name in names:
                self._assign(scope, name, value)

            # if our immediate ancestor is a class definition,
            # add this symbol also to the class scope
            if len(self.stack) > 1 and self.stack[-2][0]:
                class_scope = self.stack[-2][0]
                if self.class_name in class_scope:
                    for name in names:
                        self._assign(class_scope[self.class_name], name, value)

        # remember class names
        elif isinstance(node, ast.ClassDef):
            class_scope     = self.stack[-1][0]
            self.class_name = node.name

            class_scope[self.class_name] = {}

        # "for" - treat it as a list assignment
        elif isinstance(node, ast.For):
            # only syntax recognized: "for name in name"
            if isinstance(node.target, ast.Name) and \
               isinstance(node.iter,   ast.Name):
                name   = node.target.id
                scope  = self.stack[-1][1]
                values = self._find_list(node.iter.id)
                # save the variable as having multiple values
                self._assign(scope, name, values)
                scope[name] = values

        # keep a stack of scopes [classes, variables]
        self.stack.append([{}, {}])
        super(ShortcutFinder, self).generic_visit(node)
        self.stack.pop()

    def _assign(self, scope, name, value):
        if value:
            scope[name] = value
        else:
            # symbol overwritten with something I don't understand, forget
            if name in scope:
                del scope[name]

    def _find_values(self, arg):
        if isinstance(arg, ast.Str):
            return [arg.s]

        # single variable
        if isinstance(arg, ast.Name):
            value = self._variable_in_scope(arg.id)
            if value:
                return [value]

        # variable dot variable - TODO: nested classes
        if isinstance(arg, ast.Attribute) and \
           isinstance(arg.value, ast.Name):
            left_name  = arg.value.id
            right_name = arg.attr

            values = self._find_list(left_name)
            if values:
                # return the values for each class scope
                returned = []
                for c_name in values:
                    class_scope = self._find_class_scope(c_name)
                    if right_name in class_scope:
                        returned.append(class_scope[right_name])
                return returned

        return []

    def _variable_in_scope(self, name):
        for i in range(len(self.stack) - 1, -1, -1):
            scope = self.stack[i][1]
            if name in scope:
                return scope[name]
        return None

    def _find_list(self, name):
        values = self._variable_in_scope(name)
        if isinstance(values, list):
            return values
        return None

    def _find_class_scope(self, name):
        for i in range(len(self.stack) - 1, -1, -1):
            class_scope = self.stack[i][0]
            if name in class_scope:
                return class_scope[name]
        return {}

    def _name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._name(node.value) + "." + node.attr

        # too complex for me
        return "@" + node.__class__.__name__

#-------------------------------------------------------------------------------
class ExamplesIndex(object):
    def __init__(self):
        self.replacer = TemplateReplacer()

        with open(args.template, "r", encoding="UTF-8", errors="surrogateescape") as f:
            self.replacer.template(f.read())

    def produce(self, examples, all_keywords):
        with open(args.output, "w", encoding="UTF-8") as f:
            self.replacer.expand(examples, all_keywords, f)

#-------------------------------------------------------------------------------
class TemplateReplacer(object):
    def __init__(self):
        self.re_percent_line = re.compile(r" *% *")
        self.re_end_keyword  = re.compile(r"end([a-z]+|})$")
        self.re_variable     = re.compile(r"{{(.*?)}}")

        self.keywords = { # has_body, keyword
            ast.If:          (True,  "if"),
            ast.For:         (True,  "for"),
            ast.FunctionDef: (True,  "def"),
            ast.Break:       (False, "break"),
            ast.Continue:    (False, "continue"),
            ast.Return:      (False, "return")
        }
        # "else" treated separately

    def template(self, content):
        lines = content.rstrip("\n").split("\n")

        # convert the template lines into a Python module

        body = [self._sandwich(lines)]
        self.module = ast.Module(body=body, type_ignores=[])
        self.module = ast.fix_missing_locations(self.module)

        # "import" the module
        self.module_scope = {}
        exec(compile(self.module, "Template", "exec"), self.module_scope)

    def expand(self, examples, all_keywords, f):
        # group by category
        grouped = {}
        for example in examples:
            if example.category not in grouped:
                grouped[example.category] = []
            grouped[example.category].append(example)

        # call the template's entry point
        self.module_scope["__mm__entry"](grouped, all_keywords, f)

    def _sandwich(self, lines, lineno=0, open_keyword=None):
        in_else = False

        body = []
        text = ""
        while lineno < len(lines):
            line = lines[lineno]
            lineno += 1

            # process "% statement"s in the template
            m = self.re_percent_line.match(line)
            if m:
                line = self._clean_line(line, m.end())

                # text so far
                if text:
                    body.extend(self._substitute_variables(text))
                    text = ""

                # "else" is not an ast.<Node>; parsed separately
                ret = self._is_else(line, lineno, open_keyword)
                if ret:
                    in_else   = True
                    prev_body = body
                    body = []
                    continue

                # code block start "%{"
                if self._is_start_of_code_block(line, lineno):
                    inner_body, _, lineno = self._code_block(lines, lineno)
                    body.extend(inner_body)
                    continue

                if self._is_end_keyword(line, lineno, open_keyword):
                    if not in_else:
                        prev_body, body = body, []
                    return prev_body, body, lineno

                has_body, keyword, statement = self._check_percent_line(line, lineno)
                if has_body:
                    inner_body, \
                    inner_else, lineno = self._sandwich(lines, lineno, keyword)

                    statement.body = inner_body
                    if inner_else:
                        statement.orelse = inner_else

                body.append(statement)
                continue

            text += line + "\n"

        if open_keyword:
            raise ProcessException(
                "Template: unterminated \"%s\"" % open_keyword)

        if text:
            body.extend(self._substitute_variables(text))

        # wrap the final code in a function, so that data can be passed
        return self._function_def("__mm__entry",
                                  ["examples", "all_keywords", "_mm_f"],
                                  body)

    def _code_block(self, lines, lineno):
        start_lineno = lineno

        code = ""
        while lineno < len(lines):
            line = lines[lineno]
            lineno += 1

            # process "% statement"s in the template
            m = self.re_percent_line.match(line)
            if m:
                line = self._clean_line(line, m.end())

                if self._is_end_of_code_block(line, lineno):
                    try:
                        body = ast.parse(code, "Template").body
                        return body, [], lineno
                    except:
                        line_range = "%s" % lineno if lineno == start_lineno \
                                     else "%d-%d" % (start_lineno, lineno)
                        raise ProcessException("Template[%s]: syntax error" % \
                                   line_range)
                break # no other % allowed but %}

            code += line + "\n"

        raise ProcessException("Template: unterminated \"{\"")

    def _is_else(self, line, lineno, open_keyword):
        if line != "else:":
            return False

        # use only in statements that accept "else"
        if open_keyword not in ("if", "for"):
            raise ProcessException(
                "Template[%d]: invalid \"else\"%s" % \
                    (lineno, " in \"%s\"" % open_keyword \
                             if open_keyword else ""))

        return True

    def _is_start_of_code_block(self, line, lineno):
        return line == "{"

    def _is_end_of_code_block(self, line, lineno):
        return line == "}"

    def _is_end_keyword(self, line, lineno, open_keyword):
        m = self.re_end_keyword.match(line)
        if not m:
            return False

        if m.group(1) != open_keyword:
            raise ProcessException(
                "   Template[%d]: expected \"end%s\"" % \
                (lineno, open_keyword))

        return True

    def _check_percent_line(self, line, lineno):
        # return the code for a "% statement" in the template
        if line[-1] == ":":
            line += "\n pass"
        try:
            tree = ast.parse(line, "Template")
        except:
            raise ProcessException("Template[%d]: syntax error" % lineno)

        if type(tree) is ast.Module and \
           len(tree.body) == 1:
            head = type(tree.body[0])
            if head in self.keywords:
                return self.keywords[head] + (tree.body[0],)

        raise ProcessException("Template[%d]: unrecognized keyword" % lineno)

    def _clean_line(self, line, code_pos):
        comment_pos = line.find("#")
        if comment_pos >= 0:
            line = line[:comment_pos]

        return line[code_pos:].rstrip()

    def _substitute_variables(self, input_text):
        # generate code to substitute {{variables}} when the template is run
        code = []
        text = ""
        while input_text:
            m = self.re_variable.search(input_text)
            if not m:
                break

            # text in-between
            text += input_text[:m.start()]
            if text:
                code.append(self._output_text(text))
                text = ""
            input_text = input_text[m.end():]

            code.append(self._output_eval(m.group(1)))

        text += input_text
        if text:
            code.append(self._output_text(text))

        return code

    def _output_text(self, text):
        return ast.Expr(value=self._call(self._dot("_mm_f", "write"),
                                         [ast.Str(text)]))

    def _output_eval(self, expr):
        # eval(expr)
        value = self._call(ast.Name("eval", ast.Load()), [ast.Str(expr)])
        # str(eval(expr))
        valueStr = self._call(ast.Name("str", ast.Load()), [value])
        # _mm_f.write(str(eval(expr)))
        call = self._call(self._dot("_mm_f", "write"), [valueStr])

        return ast.Expr(call)

    def _dot(self, name1, name2):
        return ast.Attribute(value=ast.Name(name1, ast.Load()),
                             attr=name2,
                             ctx=ast.Load())

    def _call(self, func, args):
        return ast.Call(
            func=func,
            args=args,
            keywords=[]
        )

    def _function_def(self, fun_name, fun_args, fun_body):
        fun_args = ast.arguments(args=[ast.arg(a, None) \
                                       for a in fun_args],
                                 posonlyargs=[],
                                 kwonlyargs=[],
                                 kw_defaults=[],
                                 defaults=[])
        return ast.FunctionDef(name=fun_name,
                               args=fun_args,
                               body=fun_body,
                               decorator_list=[])

#-------------------------------------------------------------------------------
try:
    read_config()
    e = Examples()
    e.process()
except ProcessException as ex:
    print(ex)
    sys.exit(1)
# other exceptions - let them fail
