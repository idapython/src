
#<pycode_BC695(py_frame)>
add_auto_stkpnt2=add_auto_stkpnt
# in fact, we cannot simulate add_stkvar[23] here, because we simply
# don't have the insn_t object -- and no way of retrieving it, either,
# since cmd is gone
@bc695redef
def get_stkvar(*args):
    if len(args) == 2:
        import ida_ua
        insn, op, v = ida_ua.cmd, args[0], args[1]
    else:
        insn, op, v = args
    return _ida_frame.get_stkvar(insn, op, v)

@bc695redef
def get_frame_part(*args):
    import ida_funcs
    if isinstance(args[0], ida_funcs.func_t): # 6.95: pfn, part, range
        rnge, pfn, part = args[2], args[0], args[1]
    else:                                     # 7.00: range, pfn, part
        rnge, pfn, part = args
    return _ida_frame.get_frame_part(rnge, pfn, part)
#</pycode_BC695(py_frame)>
