#<pycode(py_nalt)>
_real_get_switch_info = get_switch_info
def get_switch_info(*args):
    if len(args) == 1:
        si, ea = switch_info_t(), args[0]
    else:
        si, ea = args
    return None if _real_get_switch_info(si, ea) <= 0 else si
def get_abi_name():
    import ida_typeinf
    return ida_typeinf.get_abi_name()
# for backward compatibility
get_initial_version = get_initial_idb_version
#</pycode(py_nalt)>
