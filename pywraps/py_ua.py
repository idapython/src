#<pycode(py_ua)>
ua_mnem = print_insn_mnem
#</pycode(py_ua)>

#<pycode_BC695(py_ua)>
import ida_idaapi
def codeSeg(ea, opnum):
    insn = insn_t()
    if decode_insn(insn, ea):
        return _ida_ua.map_code_ea(insn, insn.ops[opnum])
    else:
        return ida_idaapi.BADADDR
get_dtyp_by_size=get_dtype_by_size
get_dtyp_flag=get_dtype_flag
get_dtyp_size=get_dtype_size
get_operand_immvals=get_immvals
op_t.dtyp = op_t.dtype
cmd = insn_t()
@bc695redef
def decode_insn(*args):
    if len(args) == 1:
        tmp = insn_t()
        rc = _ida_ua.decode_insn(tmp, args[0])
        cmd.assign(tmp)
        return rc
    else:
        return _ida_ua.decode_insn(*args)
@bc695redef
def create_insn(*args):
    if len(args) == 1:
        tmp = insn_t()
        rc = _ida_ua.create_insn(args[0], tmp)
        cmd.assign(tmp)
        return rc
    else:
        return _ida_ua.create_insn(*args)
@bc695redef
def decode_prev_insn(*args):
    if len(args) == 1:
        tmp = insn_t()
        rc = _ida_ua.decode_prev_insn(tmp, args[0])
        cmd.assign(tmp)
        return rc
    else:
        return _ida_ua.decode_prev_insn(*args)
@bc695redef
def decode_preceding_insn(*args):
    if len(args) == 1:
        tmp = insn_t()
        rc = _ida_ua.decode_preceding_insn(tmp, args[0])
        cmd.assign(tmp)
        return rc
    else:
        return _ida_ua.decode_preceding_insn(*args)
import ida_ida
UA_MAXOP=ida_ida.UA_MAXOP
dt_3byte=dt_byte
tbo_123=0
tbo_132=0
tbo_213=0
tbo_231=0
tbo_312=0
tbo_321=0
def ua_add_cref(opoff, to, rtype):
    return cmd.add_cref(to, opoff, rtype)
def ua_add_dref(opoff, to, rtype):
    return cmd.add_dref(to, opoff, rtype)
def ua_add_off_drefs(x, rtype):
    return cmd.add_off_drefs(x, rtype, 0)
def ua_add_off_drefs2(x, rtype, outf):
    return cmd.add_off_drefs(x, rtype, outf)
def ua_dodata(ea, dtype):
    return cmd.create_op_data(ea, 0, dtype)
def ua_dodata2(opoff, ea, dtype):
    return cmd.create_op_data(ea, opoff, dtype)
def ua_stkvar2(x, v, flags):
    return cmd.create_stkvar(x, v, flags)
#</pycode_BC695(py_ua)>
