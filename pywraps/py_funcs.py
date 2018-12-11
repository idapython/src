#<pycode(py_funcs)>
import ida_idaapi
@ida_idaapi.replfun
def calc_thunk_func_target(*args):
    if len(args) == 2:
        pfn, rawptr = args
        target, fptr = calc_thunk_func_target.__dict__["orig"](pfn)
        import ida_pro
        ida_pro.ea_pointer.frompointer(rawptr).assign(fptr)
        return target
    else:
        return calc_thunk_func_target.__dict__["orig"](*args)
#</pycode(py_funcs)>

#<pycode_BC695(py_funcs)>
FUNC_STATIC=FUNC_STATICDEF
add_regarg2=add_regarg
clear_func_struct=lambda *args: True
def del_func_cmt(pfn, rpt):
    set_func_cmt(pfn, "", rpt)
func_parent_iterator_set2=func_parent_iterator_set
func_setend=set_func_end
func_setstart=set_func_start
func_tail_iterator_set2=func_tail_iterator_set
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
