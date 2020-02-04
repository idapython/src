#<pycode(py_dbg)>
import ida_idaapi
import ida_idd
import ida_expr

def get_tev_reg_val(tev, reg):
    rv = ida_idd.regval_t()
    if get_insn_tev_reg_val(tev, reg, rv):
        if rv.rvtype == ida_idd.RVT_INT:
            return rv.ival

def get_tev_reg_mem_qty(tev):
    ti = tev_info_t()
    if get_tev_info(tev, ti):
        mis = memreg_infos_t()
        if get_insn_tev_reg_mem(tev, mis):
            return mis.size()

def get_tev_reg_mem(tev, idx):
    mis = memreg_infos_t()
    if get_insn_tev_reg_mem(tev, mis):
        if idx < mis.size():
            return mis[idx].bytes

def get_tev_reg_mem_ea(tev, idx):
    ti = tev_info_t()
    if get_tev_info(tev, ti):
        mis = memreg_infos_t()
        if get_insn_tev_reg_mem(tev, mis):
            if idx >= 0 and idx < mis.size():
                return mis[idx].ea

def send_dbg_command(command):
    """
    Send a direct command to the debugger backend, and
    retrieve the result as a string.

    Note: any double-quotes in 'command' must be backslash-escaped.
    Note: this only works with some debugger backends: Bochs, WinDbg, GDB.

    Returns: (True, <result string>) on success, or (False, <Error message string>) on failure
    """
    rv = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, """send_dbg_command("%s");""" % command)
    if err:
        return False, "eval_idc_expr() failed: %s" % err
    vtype = ord(rv.vtype)
    if vtype == ida_expr.VT_STR:
        s = rv.c_str()
        if "IDC_FAILURE" in s:
            return False, "eval_idc_expr() reported an error: %s" % s
        return True, s
    elif vtype == ida_expr.VT_LONG:
        return True, str(rv.num)
    else:
        return False, "eval_idc_expr(): wrong return type: %d" % vtype

#</pycode(py_dbg)>

#<pycode_BC695(py_dbg)>
import ida_idd
def get_process_info(n, pi):
    pis = ida_idd.procinfo_vec_t()
    cnt = get_processes(pis)
    if n >= cnt:
        return ida_idd.NO_PROCESS
    pi.name = pis[n].name
    pi.pid = pis[n].pid
    return pi.pid
def get_process_qty():
    pis = ida_idd.procinfo_vec_t()
    return get_processes(pis)
#</pycode_BC695(py_dbg)>
