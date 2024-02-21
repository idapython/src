"""
Deploy code snips into swig interface files

(c) Hex-Rays
"""
from __future__ import print_function

import sys, re, os, glob

major, minor, micro, _, _ = sys.version_info

from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-t", "--template", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--module", required=True)
parser.add_argument("-w", "--pywraps", required=True)
parser.add_argument("-d", "--interface-dependencies", type=str, required=True)
parser.add_argument("-l", "--lifecycle-aware", default=False, action="store_true")
parser.add_argument("-v", "--verbose", default=False, action="store_true")
parser.add_argument("-x", "--xml-doc-directory", required=True)
args = parser.parse_args()

this_dir, _ = os.path.split(__file__)
sys.path.append(this_dir)
import doxygen_utils

typemaps = []

# generate typemaps that will have to be injected for additional checks
xml_tree = doxygen_utils.load_xml_for_module(args.xml_doc_directory, args.module, or_dummy=False)
if xml_tree is not None:
    all_functions = doxygen_utils.get_toplevel_functions(xml_tree)
    for fun_node in all_functions:
        fun_name = doxygen_utils.get_single_child_element_text_contents(fun_node, "name")
        params = []
        def reg_param(*args):
            params.append(args)
        doxygen_utils.for_each_param(fun_node, reg_param)
        def relevant_and_non_null(ptyp, desc):
            if ptyp.strip().startswith("qstring"):
                return False
            return (desc or "").lower().find("not be null") > -1

        for name, ptyp, desc in params:
            if relevant_and_non_null(ptyp, desc):
                # generate 'check' typemap
                signature = []
                body = []
                for idx, tpl in enumerate(params):
                    name, ptyp, desc = tpl
                    signature.append("%s %s" % (ptyp, name or ""))
                    if relevant_and_non_null(ptyp, desc):
                        body.append("if ( $%d == nullptr )" % (idx+1))
                        body.append("""  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$%d_type'");""" % (idx+1))
                    pass
                typemaps.append("%%typemap(check) (%s)" % ", ".join(signature))
                typemaps.append("{")
                typemaps.extend(body)
                typemaps.append("}")
                break
else:
    if args.module not in ["idaapi", "idc"]:
        raise Exception("Missing XML file for module '%s'" % args.module)


# creates a regular expression
def make_re(tag, module, prefix):
    s = r'%(p)s<%(tag)s\(%(m)s\)>(.+?)%(p)s</%(tag)s\(%(m)s\)>' % {'m': module, 'tag': tag, 'p': prefix}
    return (s, re.compile(s, re.DOTALL))


def convert_path(path_in):
    parts = path_in.split('/')
    return os.sep.join(parts)


def apply_tags(template_str, input_str, tags, verbose, path):
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
            raise Exception("Found <%s> for module '%s' in input (%s), but failed to match in destination" % (
                    desc, expr_str, path))

        # accumulate all the strings to be replaced
        replaces = []
        for src in matches:
            replaces.append(src)

        template_str = template_str[:dest.start(1)] + "\n".join(replaces) + template_str[dest.end(1):]
    return template_str


def deploy(module, template, output, pywraps, iface_deps, lifecycle_aware, verbose):
    template = convert_path(template)
    output = convert_path(output)

    # read template file
    with open(template) as fin:
        template_str = fin.read()

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
            ('pycode',   make_re('pycode', tagname, '#')),
            ('code',     make_re('code', tagname, '//')),
            ('inline',   make_re('inline', tagname, '//')),
            ('decls',    make_re('decls', tagname, '//')),
            ('init',     make_re('init', tagname, '//')),
        )

        with open(path) as fin:
            input_str = fin.read()
        template_str = apply_tags(template_str, input_str, tags, verbose, path)

    # synthetic tags
    if typemaps:
        typemaps_str = "\n".join([
            "//<typemaps(%s)>" % module,
            "\n".join(typemaps),
            "//</typemaps(%s)>" % module,
        ])
        synth_tags = (
            ('typemaps', make_re('typemaps', module, '//')),
        )
        template_str = apply_tags(template_str, typemaps_str, synth_tags, verbose, "[generated]")


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

        if lifecycle_aware:
            f.write("""
%%init %%{
{
  module_callbacks_t module_lfc;
  module_lfc.init = ida_%s_init;
  module_lfc.term = ida_%s_term;
  module_lfc.closebase = ida_%s_closebase;
  register_module_lifecycle_callbacks(module_lfc);
}
%%}
""" % (module, module, module))

deploy(
    args.module,
    args.template,
    args.output,
    args.pywraps,
    args.interface_dependencies,
    args.lifecycle_aware,
    args.verbose)

