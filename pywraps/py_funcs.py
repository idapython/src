#<pycode(py_funcs)>
#</pycode(py_funcs)>

#<pycode_BC695(py_funcs)>
FUNC_STATIC=FUNC_STATICDEF
add_regarg2=add_regarg
clear_func_struct=lambda *args: True
@bc695redef
def del_func_cmt(pfn, rpt):
    set_func_cmt(pfn, "", rpt)
func_parent_iterator_set2=func_parent_iterator_set
func_setend=set_func_end
func_setstart=set_func_start
func_tail_iterator_set2=func_tail_iterator_set
@bc695redef
def get_func_limits(pfn, limits):
    import ida_range
    rs = ida_range.rangeset_t()
    if get_func_ranges(rs, pfn) == ida_idaapi.BADADDR:
        return False
    limits.start_ea = rs.begin().start_ea
    limits.end_ea = rs.begin().end_ea
    return True
get_func_name2=get_func_name
#</pycode_BC695(py_funcs)>
