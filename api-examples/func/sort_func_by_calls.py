"""
summary: Print the list of the functions in the currently loaded
    IDB sorted (descending) by the number of code reference to 
    each of them.

description:
    In this script, we iterate through the list of function entry
    points and fore each of them we:
    * get its name
    * get the number of code reference made to it
    * put it in the map.
    Once done we:
    * sort the map in descending number of calls
    * print it.
"""
import ida_kernwin
import ida_funcs
import idc
import idautils

ida_kernwin.msg_clear()

func_map = {}
for funcea in idautils.Functions():
    func_name = ida_funcs.get_func_name(funcea)
    if not func_name:
        func_name = hex(funcea)
    else:
        func_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_LONG_DN))
    call_count = 0
    for xref in idautils.CodeRefsTo(funcea, 1):
        call_count += 1
    if call_count:
        func_map[func_name] = call_count

func_map_by_calls = sorted(func_map.items(), key=lambda x:x[1], reverse=True)
for func, calls in func_map_by_calls:
    print(f'{func} called {calls} time(s)')
