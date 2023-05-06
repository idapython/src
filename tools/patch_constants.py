"""
 This script replaces the long sequence of calls like:
 SWIG_Python_SetConstant(d, "s39_xg",SWIG_From_int(static_cast< int >(s39_xg)));
 SWIG_Python_SetConstant(d, "s39_xgr",SWIG_From_int(static_cast< int >(s39_xgr)));

 by a table of names+values and a loop calling the function.

 This is necessitated by the huge slowdown in GCC when trying to optimize a huge list of such calls
 in allins.cpp SWIG wrapper (~20 min).

"""
from __future__ import print_function

import re
from argparse import ArgumentParser

parser = ArgumentParser(description='Patch calling conventions for some functions, so it builds on windows')
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()

outlines = []
STAT_SEEKING = 1
STAT_ALMOST_THERE = 2
STAT_COLLECTING = 3

almost_there_re = re.compile(r"^\s+\*\s+Partial Init method.*")
start_collecting_re = re.compile(r"^#ifdef __cplusplus.*")
end_collecting_re = re.compile(r"^\s*/\* Initialize threading \*/")

# SWIG_Python_SetConstant(d, "BADADDR",SWIG_From_unsigned_SS_int(static_cast< unsigned int >(ea_t(-1))));
set_constant_re = re.compile(r"^\s*SWIG_Python_SetConstant\(\s*d\s*,([^,]*),(.*)\);$")

# Supported types we can simply expression for
#  SWIG_From_int(static_cast< int >(0x00C0))
pyobj_expr_int = re.compile(r"SWIG_From_int\(static_cast<\s*int\s*>\((.*)\)\)")
#  SWIG_From_unsigned_SS_int(static_cast< unsigned int >((1u << 16)))
pyobj_expr_uint = re.compile(r"SWIG_From_unsigned_SS_int\(static_cast<\s*unsigned\s+int\s*>\((.*)\)\)")
#  SWIG_From_long(static_cast< long >(0x00002000L))
pyobj_expr_long = re.compile(r"SWIG_From_long\(static_cast<\s*long\s*>\((.*)\)\)")
#  SWIG_From_unsigned_SS_long(static_cast< unsigned long >(0xF0000000LU))
pyobj_expr_ulong = re.compile(r"SWIG_From_unsigned_SS_long\(static_cast<\s*unsigned\s+long\s*>\((.*)\)\)")
#  SWIG_FromCharPtr("\22")
pyobj_expr_str = re.compile(r"SWIG_FromCharPtr\((.*)\)")


status = STAT_SEEKING
class Foldable(object):
    def __init__(self, re, enum, initializer, cast, replacement):
        self.re = re
        self.enum = enum
        self.initializer = initializer
        self.cast = cast
        self.replacement = replacement
        self.found_any = False

subexprs = {
    "i" : Foldable(
        pyobj_expr_int,
        "cit_int",
        "i",
        "int",
        "SWIG_From_int(static_cast< int >(ci.val))"),
}

def generate_constants(constants):
    # now, generate the array & loop
    outlines.append("""
/* 'SetConstant' replacement */
static const ida_local struct ci_t
{
    const char *name;
    int  val;
} cis[%d] = {
""" % len(constants))

    for c in constants:
        name = c[0]
        expr = c[1]

        # Analyze expression. If it is one of the
        # supported types, let's simplify the code.
        for kind in ["i"]:
            subexpr = subexprs[kind]
            sematch = subexpr.re.search(expr)
            if sematch:
                citype = subexpr.enum
                expr = sematch.group(1)
                init = subexpr.initializer
                cast = subexpr.cast
                subexpr.found_any = True
                break
        outlines.append("\t{%s, static_cast< int >(%s)},\n" % (name, expr))

    outlines.append("""
};

for ( size_t _cidx = 0; _cidx < qnumber(cis); ++_cidx )
{
  const ci_t &ci = cis[_cidx];
  PyObject *o = """)

    subexpr = subexprs["i"]
    outlines.append("""%s;""" % (subexpr.replacement))

    outlines.append("""
  SWIG_Python_SetConstant(d, ci.name, o);
}
""")

with open(args.input) as f:
    constants = []

    for line in f:
        if status == STAT_SEEKING:
            if almost_there_re.match(line):
                status = STAT_ALMOST_THERE
                if args.verbose:
                    print("Almost there at line: '%s'" % line)
            outlines.append(line)
        elif status == STAT_ALMOST_THERE:
            if start_collecting_re.match(line):
                status = STAT_COLLECTING
                if args.verbose:
                    print("Starting to collect at line: '%s'" % line)
                outlines.append("#ifdef __NT__\n")
                outlines.append("#pragma warning(disable: 4883)\n")
                outlines.append("#endif // __NT__\n")
            outlines.append(line)
        elif status == STAT_COLLECTING:
            if end_collecting_re.match(line):
                outlines.append(line)

                if len(constants):
                    generate_constants(constants)

                status = STAT_SEEKING
                if args.verbose:
                    print("Done collecting at line: '%s'" % line)
            else:
                match = set_constant_re.search(line)
                if match and pyobj_expr_int.search(match.group(2)):
                    tpl = (match.group(1), match.group(2))
                    constants.append(tpl)
                    if args.verbose:
                        print("Found 'SetConstant' expression: %s => %s" % tpl)
                else:
                    outlines.append(line)

import tempfile
temp = tempfile.NamedTemporaryFile(mode="w", delete=False)
temp.write("".join(outlines))
temp.close()

import shutil
shutil.move(temp.name, args.output)
