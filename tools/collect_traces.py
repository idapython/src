#!/usr/bin/python3

# A tool to merge all the /tmp files produced by
# t2/phases/tests/trace_idapython_calls_idapythonrc.py,
# into a persisted file (in P4, not in /tmp)
# that can be read to improve the IDAPython documentation.

import sys
import os
import tempfile
import ast

tools_dir   = os.path.dirname(__file__)
output_file = os.path.join(tools_dir, "collected_traces.txt")
input_files = "trace_idapython_calls_output.txt"  # on each test directory

stats_tests_added = 0
stats_funcs_added = 0
stats_lines_added = 0

#------------------------------------------------------------------------
def load_existing(pathname):
    if not os.path.exists(pathname):
        return {}

    with open(pathname, "r") as f:
        collected = ast.literal_eval(f.read())

        # turn lists into sets for easier merging

        for key in collected:
            if key == "#empty":
                empty_data = collected[key]
                for fun in empty_data:
                    empty_data[fun] = matcher_t(empty_data[fun])
            else:
                fun_data = collected[key]
                fun_data["return"] = matcher_t(fun_data["return"])
                fun_data["tests"]  = set(fun_data["tests"])

    return collected

#------------------------------------------------------------------------
def load_from_test(collected_data, test_name, pathname):
    global stats_tests_added, stats_funcs_added, stats_lines_added

    with open(pathname, "r") as f:
        content = ast.literal_eval(f.read())

        if "#empty" in collected_data:
            common = collected_data["#empty"]
        else:
            stats_tests_added += 1
            collected_data["#empty"] = common = {}

        for key in content:
            # ida_* modules only
            prefix = "ida_"
            if not key.startswith(prefix):
                continue
            fun = key[len(prefix):]

            # presently we remove all dictionary content except for return values;
            # we'll see in the future if we use the rest of info, 
            # or if we don't use a dictionary at all in the idapythonrc
            # note: return values in /tmp traces were collected as repr()
            content_rets = [ast.literal_eval(x["return"]) for x in content[key]]

            if test_name == "empty":
                # entry with a special format
                if fun not in common:
                    common[fun] = matcher_t(content_rets)
                    stats_funcs_added += 1
                    stats_lines_added += common[fun].count()
                continue

            for line in content_rets:
                if fun in common:
                    if common[fun].add(line):
                        stats_lines_added += 1
                    continue

                if fun in collected_data:
                    fun_data = collected_data[fun]
                    rets  = fun_data["return"]
                    tests = fun_data["tests"]
                else:
                    stats_funcs_added += 1
                    rets  = matcher_t()
                    tests = set()
                    fun_data = { "return":rets, "tests":tests }
                    collected_data[fun] = fun_data

                if test_name not in tests:
                    stats_tests_added += 1
                    tests.add(test_name)

                if rets.add(line):
                    stats_lines_added += 1

#------------------------------------------------------------------------
# Stores different return values of functions collected at runtime,
# and simplifies repetitions like [str, str, str] into a pattern [str, ...]

class matcher_t:
    def __init__(self, initial_content=[]):
        self.patterns = []

        for value in initial_content:
            self.add(value)

    def add(self, value):
        if any(pat.match(value) for pat in self.patterns):
            return False  # another instance of what we already have

        # something new
        self.patterns.append(pattern_t(value))
        return True

    def count(self):
        return len(self.patterns)

    def sorted(self):
        return sorted(repr(pat) for pat in self.patterns)

#------------------------------------------------------------------------
class pattern_t:
    def __init__(self, value):
        self.expr = self._build(value)

    def _build(self, value):
        if isinstance(value, list) and len(value) > 0:
            # recognize a special form of lists as a repetition_t object
            # that we stored (via repetition_t.__repr__) in a previous run
            # (saved into, and now reloaded from, the "tools/collected_traces.txt" file)
            if len(value) == 2 and value[1] == "...":
                return repetition_t(value[0])

            first = value[0]
            if all(x == first for x in value[1:]):
                return repetition_t(first)

            # heterogeneous list - treated as separate values
            return value

        if isinstance(value, tuple):
            build = []
            for x in value:
                build.append(self._build(x))
            return tuple(build)

        return value

    def match(self, value):
        # "match" may update the pattern when receiving new values:
        # replace the pattern if it was converted into a repetition

        m = self._match(self.expr, value)
        if isinstance(m, bool):
            return m

        self.expr = m
        return True

    def _match(self, pat, val):
        if isinstance(pat, tuple) and isinstance(val, tuple):
            if len(pat) != len(val):
                return False

            return self._maybe_replace_parts(pat, val)

        if pat == [] and isinstance(val, list) and len(val) > 0:
            # convert [] into a repetition (we didn't before,
            # because with an empty list we couldn't know WHAT was repeated)
            return repetition_t(val[0])
            
        if isinstance(pat, repetition_t):
            return pat.match(val)

        return pat == val

    def _maybe_replace_parts(self, pat_tuple, val_tuple):
        ret = []

        all_bool = True
        for p, v in zip(pat_tuple, val_tuple):
            m = self._match(p, v)

            if isinstance(m, bool):
                if not m:
                    return False
                # keep the previous part
                ret.append(p)
            else:
                # new part
                ret.append(m)
                all_bool = False
        if all_bool:
            return True # good match but no replacements

        return tuple(ret)

    def __repr__(self):
        return repr(self.expr)

#------------------------------------------------------------------------
class repetition_t:
    def __init__(self, core):
        self.core = pattern_t(core)

    def match(self, value):
        if not isinstance(value, list):
            return False

        return all(self.core.match(item) for item in value)

    def __repr__(self):
        return "[" + repr(self.core) + ", '...']"

#------------------------------------------------------------------------
def dump_data(collected_data):
    content = "{\n"

    for fun_name in sorted(collected_data):
        content += "  \"{}\": {{\n".format(fun_name)

        fun_data = collected_data[fun_name]
        if fun_name == "#empty":
            # "empty test" entry, different format that the rest

            for fun_in_empty in fun_data:
                content += "    \"{}\": [\n".format(fun_in_empty)

                for line in fun_data[fun_in_empty].sorted():
                    content += "      {},\n".format(line) # return values
                content += "    ],\n"
        else:
            # data per function

            rets  = fun_data["return"]
            tests = fun_data["tests"]

            content += "    \"return\": [\n"
            for line in rets.sorted():
                content += "      {},\n".format(line)
            content += "    ],\n"

            content += "    \"tests\": [\n"
            for test_name in sorted(tests):
                content += "      \"{}\",\n".format(test_name)
            content += "    ]\n"

        content += "  },\n"
    content += "}\n"

    return content

#------------------------------------------------------------------------
def test_dir():
    username = os.path.basename(os.path.expanduser("~"))
    # or more reliably:
    #   import getpass
    #   username = getpass.getuser()
    # but the above works nearly always, with one less dependency

    return "/tmp/{}/uitests".format(username)

#------------------------------------------------------------------------
def all_test_trace_files():
    testdir  = test_dir()
    emptydir = os.path.join(testdir, "empty")

    if os.path.isdir(emptydir):
        test_output = os.path.join(emptydir, input_files)
        if os.path.exists(test_output):
            yield "empty", test_output  # process the "empty" test first

    for entry in os.scandir(testdir):
        if entry.name == "empty":
            continue    # already read

        if entry.is_dir():
            test_output = os.path.join(entry.path, input_files)

            if os.path.exists(test_output):
                yield entry.name, test_output

#------------------------------------------------------------------------
def main():
    # check for p4 edit
    # (otherwise os.replace below would replace the output file silently)
    if os.path.exists(output_file) and not os.access(output_file, os.W_OK):
        print("{}: not writable".format(output_file))
        sys.exit(1)

    collected_data = load_existing(output_file)

    first = True
    for test_name, pathname in all_test_trace_files():
        if first:
            first = False
            if test_name != "empty" and not collected_data:
                print("Please run the \"empty\" test"
                      " when collecting for the first time.")
                sys.exit(1)

        load_from_test(collected_data, test_name, pathname)

    fout, fileout = tempfile.mkstemp()

    success = False
    try:
        os.write(fout, dump_data(collected_data).encode("ascii"))
        os.close(fout)
        os.replace(fileout, output_file)

        print ("Tests added: {}, functions added: {}, lines added: {}".format(
               stats_tests_added, stats_funcs_added, stats_lines_added))
        success = True
    finally:
        if not success:
            os.remove(fileout)

#------------------------------------------------------------------------
main()
