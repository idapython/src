import idautils
import ida_kernwin
import ida_funcs
import ida_ua
import ida_allins
import ida_ida
import ida_hexrays
import ida_lines
import idc

def build_function_list(func):
    func_list = []

    items = ida_funcs.func_item_iterator_t(func)
    for item in items:
        is_jmp = False

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, item):
            continue

        if not insn.itype == ida_allins.NN_call and not insn.itype == ida_allins.NN_jmp:
            continue

        if insn.itype == ida_allins.NN_jmp:
            is_jmp = True
        
        for xref in idautils.CodeRefsFrom(item, 0):
            callee = ida_funcs.get_func(xref)
            if not callee:
                print(f'Unable to retrieve function object for {xref:x}. Skipping.')
                continue

            if is_jmp and callee.start_ea == func.start_ea:
                continue
            
            if callee not in func_list:
                func_list.append(callee)
        
    return func_list


def print_pseudo_code(cfunc):
    sv = cfunc.get_pseudocode()
    for sline in sv:
        print(ida_lines.tag_remove(sline.line))
    print('')


def decompile_and_print(func):
    func_list = build_function_list(func)
    func_list = [func, *func_list]

    for item in func_list:
        cfunc = ida_hexrays.decompile(item)
        if not cfunc:
            print(f'Unable to decompile function {ida_funcs.get_func_name(item.start_ea)}')
            return False
        print_pseudo_code(cfunc)
        

def main():
    if not ida_ida.inf_get_procname() == 'metapc':
        return False
    
    if not ida_hexrays.init_hexrays_plugin():
        return False
    
    func = ida_funcs.get_func(idc.here())
    if not func:
        print('Please put the cursor inside a function and retry.')
    
    decompile_and_print(func)
    
ida_kernwin.msg_clear()
main()