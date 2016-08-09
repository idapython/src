
import re

try:
  from argparse import ArgumentParser
except:
  print "Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'"
  raise

parser = ArgumentParser(description='Patch calling conventions for some functions, so it builds on windows')
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()

outlines = []
STAT_SEEKING = 1
STAT_COLLECTING = 2

start_collecting_re = re.compile(r"^SWIG_init\(void\)")
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
    def __init__(self, re, enum, initializer, replacement):
        self.re = re
        self.enum = enum
        self.initializer = initializer
        self.replacement = replacement
        self.found_any = False

subexprs = {
    "i" : Foldable(
        pyobj_expr_int,
        "cit_int",
        "i",
        "SWIG_From_int(static_cast< int >(ci.val.i))"),
    "u" : Foldable(
        pyobj_expr_uint,
        "cit_uint",
        "u",
        "SWIG_From_unsigned_SS_int(static_cast< unsigned int >(ci.val.u))"),
    "l" : Foldable(
        pyobj_expr_long,
        "cit_long",
        "l",
        "SWIG_From_long(static_cast< long >(ci.val.l))"),
    "ul" : Foldable(
        pyobj_expr_ulong,
        "cit_ulong",
        "ul",
        "SWIG_From_unsigned_SS_long(static_cast< unsigned long >(ci.val.ul))"),
    "s" : Foldable(
        pyobj_expr_str,
        "cit_charptr",
        "s",
        "SWIG_FromCharPtr(ci.val.s)"),
}

def generate_constants(constants):
    # now, generate the array & loop
    outlines.append("""
/* 'SetConstant' replacement */
union ida_local cival_t
{
    PyObject *o;
    int i;
    unsigned int u;
    long l;
    unsigned long ul;
    const char *s;
};

enum cit_t
{
    cit_int = 1,
    cit_uint,
    cit_long,
    cit_ulong,
    cit_charptr,
    cit_obj,
};

static const ida_local struct ci_t
{
    const char *name;
    cival_t val;
    cit_t type;
} cis[%d] = {
""" % len(constants))

    for c in constants:
        name = c[0]
        expr = c[1]
        init = "o"
        citype = "cit_obj"

        # Analyze expression. If it is one of the
        # supported types, let's simplify the code.
        for kind in subexprs.keys():
            subexpr = subexprs[kind]
            sematch = subexpr.re.search(expr)
            if sematch:
                citype = subexpr.enum
                expr = sematch.group(1)
                init = subexpr.initializer
                subexpr.found_any = True
                break
        outlines.append("\t{%s, {%s: (%s)}, %s},\n" % (name, init, expr, citype))

    outlines.append("""
};

for ( size_t _cidx = 0; _cidx < qnumber(cis); ++_cidx )
{
  const ci_t &ci = cis[_cidx];
  PyObject *o = NULL;
  switch ( ci.type )
  {
""")

    for kind in subexprs.keys():
        subexpr = subexprs[kind]
        if subexpr.found_any:
            outlines.append("""
    case %s:
      o = %s;
      break;
                    """ % (subexpr.enum, subexpr.replacement))

    outlines.append("""
    case cit_obj:
      o = ci.val.o;
      break;
    default: INTERR(0);
  }
  SWIG_Python_SetConstant(d, ci.name, o);
}
""")

with open(args.file, "rb") as f:
    constants = []

    for line in f:
        if status == STAT_SEEKING:
            outlines.append(line)
            if start_collecting_re.match(line):
                status = STAT_COLLECTING
                if args.verbose:
                    print "Starting to collect at line: '%s'" % line
        elif status == STAT_COLLECTING:
            if end_collecting_re.match(line):
                outlines.append(line)

                if len(constants):
                    generate_constants(constants)

                status = STAT_SEEKING
                if args.verbose:
                    print "Done collecting at line: '%s'" % line
            else:
                match = set_constant_re.search(line)
                if match:
                    tpl = (match.group(1), match.group(2))
                    constants.append(tpl)
                    if args.verbose:
                        print "Found 'SetConstant' expression: %s => %s" % tpl
                else:
                    outlines.append(line)

import tempfile
temp = tempfile.NamedTemporaryFile(delete=False)
temp.write("".join(outlines))
temp.close()

import shutil
shutil.move(temp.name, args.file)
