"""
Deploy code snips into swig interface files

(c) Hex-Rays
"""

import sys
import re
import os

# creates a regular expression
def make_re(tag, mod_name, prefix):
    s = '%(p)s<%(tag)s\(%(m)s\)>(.+?)%(p)s</%(tag)s\(%(m)s\)>' % {'m': mod_name, 'tag': tag, 'p': prefix}
    return (s, re.compile(s, re.DOTALL))

def deploy(mod_name, src_files, dest_file, silent = True):
    # create regular expressions
    templates = (
        ('pycode', make_re('pycode', mod_name, '#')),
        ('code',   make_re('code', mod_name, '//')),
        ('inline', make_re('inline', mod_name, '//'))
    )

    if not os.path.exists(dest_file):
        print "File", dest_file, "does not exist and will be skipped"
        return

    if not os.access(dest_file, os.W_OK):
        print "File", dest_file, "is not writable and will be skipped"
        return

    # read dest file
    dest_lines = "".join(file(dest_file, "r").readlines())

    # read all source files into one buffer
    src_lines = "".join(["".join(file(x, "r").readlines()) for x in src_files])

    pcount = 0
    for desc, (expr_str, expr) in templates:
        # find source pattern
        matches = expr.findall(src_lines)
        if not matches:
            if not silent:
                print "Failed to match <%s> source expression against '%s', skipping...!" % (desc, expr_str)
            continue

        # find pattern in destination
        dest = expr.search(dest_lines)
        if not dest:
            if not silent:
                print "Failed to match <%s> destination expression against '%s', skipping..." % (desc, expr_str)
                print dest_lines
                sys.exit(0)
            continue

        # accumulate all the strings to be replaced
        replaces = []
        for src in matches:
            replaces.append(src)

        dest_lines = dest_lines[:dest.start(1)] + "\n".join(replaces) + dest_lines[dest.end(1):]
        pcount += 1


    f = file(dest_file, 'w')
    if not f:
        print "Failed to open destination file:", dest_file
        return
    f.write(dest_lines)
    f.close()

    if pcount:
        print "Deployed successfully: %s (%d)" % (dest_file, pcount)
    else:
        print "Nothing was deployed in: %s" % dest_file


def main(argv = None):
    if not argv:
      argv = sys.argv
    if len(argv) != 4:
        print "Usage deploy.py modname src_file1,src_file2,... dest_file"
        return

    mod_name  = argv[1]
    src_files = argv[2].split(',')
    dest_file = argv[3]
    deploy(mod_name, src_files, dest_file)

#main(['', 'py_graph', 'py_graph.hpp,py_graph.py', 'graph.i'])
main()