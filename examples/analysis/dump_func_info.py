"""
summary: dump (some) information about the current function.

description:
  Dump some of the most interesting bits of information about
  the function we are currently looking at.
"""

import binascii

import ida_kernwin
import ida_funcs


def dump_flags(fn):
    "dump some flags of the func_t object"
    print("Function flags: %08X" % fn.flags)
    if fn.is_far():
        print("  Far function")
    if not fn.does_return():
        print("  Function does not return")
    if fn.flags & ida_funcs.FUNC_FRAME:
        print("  Function uses frame pointer")
    if fn.flags & ida_funcs.FUNC_THUNK:
        print("  Thunk function")
    if fn.flags & ida_funcs.FUNC_LUMINA:
        print("  Function info is provided by Lumina")
    if fn.flags & ida_funcs.FUNC_OUTLINE:
        print("  Outlined code, not a real function")


def dump_regvars(pfn):
    "dump renamed registers information"
    assert ida_funcs.is_func_entry(pfn)
    print("Function has %d renamed registers" % pfn.regvarqty)
    for rv in pfn.regvars:
        print("%08X..%08X '%s'->'%s'" % (rv.start_ea, rv.end_ea, rv.canon, rv.user))

def dump_regargs(pfn):
    "dump register arguments information"
    assert ida_funcs.is_func_entry(pfn)
    print("Function has %d register arguments" % pfn.regargqty)
    for ra in pfn.regargs:
        print("  register #=%d, argument name=\"%s\", (serialized) type=\"%s\"" % (
            ra.reg,
            ra.name,
            binascii.hexlify(ra.type)))


def dump_tails(pfn):
    "dump function tails for entry chunk pfn"
    assert ida_funcs.is_func_entry(pfn)
    print("Function has %d tails" % pfn.tailqty)
    for i in range(pfn.tailqty):
        ft = pfn.tails[i]
        print("  tail %i: %08X..%08X" % (i, ft.start_ea, ft.end_ea))


def dump_stkpnts(pfn):
    "dump function stack points"
    print("Function has %d stack points" % pfn.pntqty)
    for i in range(pfn.pntqty):
        pnt = pfn.points[i]
        print("  stkpnt %i @%08X: %d" % (i, pnt.ea, pnt.spd))


def dump_frame(fn):
    "dump function frame info"
    assert ida_funcs.is_func_entry(fn)
    print("frame structure id: %08X" % fn.frame)
    print("local variables area size: %8X" % fn.frsize)
    print("saved registers area size: %8X" % fn.frregs)
    print("bytes purged on return   : %8X" % fn.argsize)
    print("frame pointer delta      : %8X" % fn.fpd)


def dump_parents(fn):
    "dump parents of a function tail"
    assert ida_funcs.is_func_tail(fn)
    print("owner function: %08X" % fn.owner)
    print("tail has %d referers" % fn.refqty)
    for i in range(fn.refqty):
        print("  referer %i: %08X" % (i, fn.referers[i]))


def dump_func_info(ea):
    "dump info about function chunk at address 'ea'"
    pfn = ida_funcs.get_fchunk(ea)
    if pfn is None:
        print("No function at %08X!" % ea)
        return
    print("current chunk boundaries: %08X..%08X" % (pfn.start_ea, pfn.end_ea))
    dump_flags(pfn)
    if (ida_funcs.is_func_entry(pfn)):
        print ("This is an entry chunk")
        dump_tails(pfn)
        dump_frame(pfn)
        dump_regvars(pfn)
        dump_regargs(pfn)
        dump_stkpnts(pfn)
    elif (ida_funcs.is_func_tail(pfn)):
        print ("This is a tail chunk")
        dump_parents(pfn)


ea = ida_kernwin.get_screen_ea()
dump_func_info(ea)
