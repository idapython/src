
#<pycode_BC695(py_offset)>
calc_reference_basevalue=calc_basevalue
calc_reference_target=calc_target
def set_offset(ea, n, base):
    import ida_idaapi
    otype = get_default_reftype(ea)
    return op_offset(ea, n, otype, ida_idaapi.BADADDR, base) > 0
#</pycode_BC695(py_offset)>
