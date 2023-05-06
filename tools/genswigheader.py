from __future__ import print_function

import sys
import os
import glob

from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--modules", required=True)
parser.add_argument("-s", "--sdk", required=True)
args = parser.parse_args()

with open(args.input) as fin:
    with open(args.output, "w") as fout:
        parts = []

        def add_imports_from_dep(depname):
            DEPNAME = depname.upper()
            for dep in glob.glob(os.path.join(args.sdk, "%s.*" % depname)):
                parts.append("  #ifdef HAS_DEP_ON_INTERFACE_%s" % DEPNAME)
                parts.append("  %import \"{0}.i\"".format(depname))
                parts.append("  #else")
                parts.append("  %import \"{0}\"".format(os.path.basename(dep)))
                parts.append("  #endif")
                parts.append("")

        parts.append("#if defined(IDA_MODULE_PRO)")
        parts.append("// nothing; has to be handled in pro.i")
        parts.append("#else")
        required_headers = ["pro", "ida", "xref", "typeinf", "enum", "netnode", "range", "lines", "kernwin", "bytes", "auto", "nalt", "idd", "idp", "gdl"]
        # required_headers = ["pro", "ida", "xref", "typeinf", "enum", "netnode", "range", "lines", "kernwin", "bytes", "auto", "nalt", "idd", "idp", "dirtree"]
        for rh in required_headers:
            add_imports_from_dep(rh)
        parts.append("#endif")

        # Collect NONNULL typemaps
        nonnul_typemaps_parts = []
        for md_path in glob.glob(os.path.join(args.sdk, "*.metadata")):
            with open(md_path, "rb") as md_fin:
                raw = md_fin.read().decode("UTF-8")
            md = eval(raw)
            for ptype, pname in md:
                nonnul_typemaps_parts.append(
                    """
%%typemap(check) (%s %s)
{
  if ( $1 == nullptr )
    SWIG_exception_fail(SWIG_ValueError, "invalid null pointer " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}
                    """ % (ptype, pname))

        # Can't use string.Template here, because it's a nightmare
        # to use with a file that has many '$' is it.
        template = fin.read()
        result = template\
                 .replace("${ALL_IMPORTS}", "\n".join(parts))\
                 .replace("${NONNULL_TYPEMAPS}", "\n".join(nonnul_typemaps_parts))

        fout.write(result)
