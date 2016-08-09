"""
Deploy code snips into swig interface files

(c) Hex-Rays
"""

import sys, re, os, glob

major, minor, micro, _, _ = sys.version_info

try:
  from argparse import ArgumentParser
except:
  print "Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'"
  raise

parser = ArgumentParser()
parser.add_argument("-t", "--template", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--module", required=True)
parser.add_argument("-w", "--pywraps", required=True)
parser.add_argument("-d", "--interface-dependencies", type=str, required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()

# creates a regular expression
def make_re(tag, module, prefix):
    s = '%(p)s<%(tag)s\(%(m)s\)>(.+?)%(p)s</%(tag)s\(%(m)s\)>' % {'m': module, 'tag': tag, 'p': prefix}
    return (s, re.compile(s, re.DOTALL))


def convert_path(path_in):
    parts = path_in.split('/')
    return os.sep.join(parts)


def apply_tags(template_str, input_str, tags, verbose):
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
            raise Exception("Found <%s> for module '%s' in input, but failed to match in destination" % (
                    desc, expr))

        # accumulate all the strings to be replaced
        replaces = []
        for src in matches:
            replaces.append(src)

        template_str = template_str[:dest.start(1)] + "\n".join(replaces) + template_str[dest.end(1):]
    return template_str


def deploy(module, template, output, pywraps, iface_deps, verbose):
    template = convert_path(template)
    output = convert_path(output)

    # read template file
    template_str = "".join(file(template, "r").readlines())

    # read input file(s)
    all_files = glob.glob(os.path.join(pywraps, "py_%s.*" % module)) + \
        glob.glob(os.path.join(pywraps, "py_%s_*.*" % module))
    for path in all_files:
        fname = os.path.basename(path)
        tagname, _ = os.path.splitext(fname)
        if verbose:
            print("Considering file: '%s' (tagname: '%s')" % (path, tagname))

        # create regular expressions
        tags = (
            ('pycode', make_re('pycode', tagname, '#')),
            ('code',   make_re('code', tagname, '//')),
            ('inline', make_re('inline', tagname, '//')),
            ('decls',  make_re('decls', tagname, '//')),
            ('init',   make_re('init', tagname, '//')),
            )

        input_str = "".join(file(path, "r").readlines())
        template_str = apply_tags(template_str, input_str, tags, verbose)

    # write output file
    with open(output, 'w') as f:
        # f.write("""%module(docstring="IDA Plugin SDK API wrapper: {0}",directors="1",threads="1") {1}\n""".format(
        #     module,
        #     module if module == "idaapi" else "_ida_%s" % module))
        f.write("""%module(docstring="IDA Plugin SDK API wrapper: {0}",directors="1",threads="1") {1}\n""".format(
            module, "ida_%s" % module))
        f.write("#ifndef IDA_MODULE_DEFINED\n")
        f.write("""  #define IDA_MODULE_%s\n""" % module.upper())
        f.write("#define IDA_MODULE_DEFINED\n")
        f.write("#endif // IDA_MODULE_DEFINED\n")
        for dep in [module] + iface_deps.split(","):
          if len(dep):
            f.write("#ifndef HAS_DEP_ON_INTERFACE_%s\n" % dep.upper())
            f.write("  #define HAS_DEP_ON_INTERFACE_%s\n" % dep.upper())
            f.write("#endif\n")
        f.write("%include \"header.i\"\n")
        f.write(template_str)

deploy(args.module, args.template, args.output, args.pywraps, args.interface_dependencies, args.verbose)
