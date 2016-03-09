"""
Deploy code snips into swig interface files

(c) Hex-Rays
"""

import sys
import re
import os

major, minor, micro, _, _ = sys.version_info
if major < 2 or minor < 7:
    raise Exception("Expected Python version 2.7.x, but got %s.%s.%s (from %s)" % (major, minor, micro, sys.executable))

from argparse import ArgumentParser
parser = ArgumentParser()
parser.add_argument("-t", "--template", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--module", required=True)
parser.add_argument("-w", "--pywraps", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()

# creates a regular expression
def make_re(tag, module, prefix):
    module = "py_%s" % module
    s = '%(p)s<%(tag)s\(%(m)s\)>(.+?)%(p)s</%(tag)s\(%(m)s\)>' % {'m': module, 'tag': tag, 'p': prefix}
    return (s, re.compile(s, re.DOTALL))

def convert_path(path_in):
    parts = path_in.split('/')
    return os.sep.join(parts)

def deploy(module, template, output, pywraps, verbose):
    template = convert_path(template)
    output = convert_path(output)
    # create regular expressions
    tags = (
        ('pycode', make_re('pycode', module, '#')),
        ('code',   make_re('code', module, '//')),
        ('inline', make_re('inline', module, '//'))
    )

    # read dest file
    template_str = "".join(file(template, "r").readlines())

    # read input file(s)
    input_parts = []
    for fname in ["py_%s.%s" % (module, ext) for ext in ["hpp", "py"]]:
        path = os.path.join(pywraps, fname)
        if os.path.isfile(path):
            input_parts.append("".join(file(path, "r").readlines()))
    input_str = "".join(input_parts)

    pcount = 0
    for desc, (expr_str, expr) in tags:
        # find source pattern
        matches = expr.findall(input_str)
        if not matches:
            if verbose:
                print("Failed to match <%s> source expression against '%s', skipping...!" % (desc, expr_str))
            continue

        # find pattern in destination
        dest = expr.search(template_str)
        if not dest:
            raise Exception("Found <%s> for module '%s' in input, but failed to match in destination" % (desc, module))

        # accumulate all the strings to be replaced
        replaces = []
        for src in matches:
            replaces.append(src)

        template_str = template_str[:dest.start(1)] + "\n".join(replaces) + template_str[dest.end(1):]
        pcount += 1

    with open(output, 'w') as f:
        f.write(template_str)

deploy(args.module, args.template, args.output, args.pywraps, args.verbose)
