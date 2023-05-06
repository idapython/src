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
