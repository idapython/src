"""
summary: List all the functions called by the one in which the
    cursor is currently located.

description:
    If the cursor is located inside a function:
    * get the function object
    * get the function name
    * get a function item iterator
    * iterate through the items, and for each one decode it
    * if the item is a call get the address of the callee
        - get its name
        - display its name its address and address of the call.
    * if no calle is found print a statement indicating this fact. 
"""
import idautils
import ida_kernwin
import ida_funcs
import ida_ua
import ida_allins
import ida_ida
import idc

ida_kernwin.msg_clear()

if ida_ida.inf_get_procname() == 'metapc':
    func = ida_funcs.get_func(idc.here())
    if func:
        has_callee = False
        func_name = ida_funcs.get_func_name(func.start_ea)
        if not func_name:
            func_name = hex(func.start_ea)
        print(f'Function {func_name} [{func.start_ea:x}] calls:')

        items = ida_funcs.func_item_iterator_t(func)
        for item in items:
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, item):
                continue

            if not insn.itype == ida_allins.NN_call:
                continue

            if not has_callee:
                has_callee = True
        
            for xref in idautils.CodeRefsFrom(item, 0):
                print(f'\t- {ida_funcs.get_func_name(xref)} [{xref:x}] @{item:x}')
        
        if not has_callee:
            print('\t- no function.')
    else:
        print('Please place the cursor inside a function and retry.')
else:
    print('This script will propely work for "metapc" procmod only.')
