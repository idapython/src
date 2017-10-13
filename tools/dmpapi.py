
# helper script, used to dump the contents of the IDA
# APIs (used for 7.00 -> 6.95 compat support)

import os

import idc
import idaapi
import inspect
outfile = idc.ARGV[1]

def formatargspec(argspec):
    # only format the default args + values
    parts = []
    dflts = argspec.defaults or []
    for i in xrange(len(argspec.args) - len(dflts)):
        parts.append("_")
    for i in xrange(len(dflts)):
        parts.append("=%s" % str(dflts[i]))
    if argspec.varargs:
        parts.append("*%s" % argspec.varargs)
    if argspec.keywords:
        parts.append("**%s" % argspec.keywords)
    return ", ".join(parts)


def dump_module(module, out):
    mname = module.__name__
    outmod = []
    out[mname] = outmod
    for symbol in sorted(dir(module)):
        if symbol.endswith("_swigregister"):
            continue
        if symbol == "_%s" % mname: # _ida_area
            continue
        if symbol == "cvar":
            continue
        srcmod = inspect.getmodule(getattr(module, symbol))
        if srcmod and (srcmod.__name__.find("ctypes") > -1):
            continue
        thing = getattr(module, symbol)
        if inspect.isfunction(thing) or inspect.ismethod(thing):
            argspec = inspect.getargspec(thing)
            symbol = "%s(%s)" % (symbol, formatargspec(argspec))
            if thing.func_dict.get("bc695redef", False):
                symbol = "%s!bc695redef" % symbol
        outmod.append(symbol)

out = {}
for modname in sorted(sys.modules):
    module = sys.modules[modname]
    if modname.startswith("ida_") or modname in ["idc"]:
        # if modname not in ignorable_modules:
        dump_module(module, out)

with open(outfile, "w") as fout:
    import pprint
    fout.write("%s" % pprint.pformat(out))

idc.Exit(0)
