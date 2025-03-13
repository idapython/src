"""
summary: Print argument location information.

description:
    In this script, we iterate through a function
    arguments and display information about their
    location and size. For this we:
    * get the function type information
    * iterate through the arguments
    * for each of them we print its location (register or stack),
    offset (if in stack) and size
"""
import ida_nalt
import ida_funcs
import ida_typeinf
import idc
import ida_kernwin

def print_argument_locations(func):
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea):
        fi = ida_typeinf.func_type_data_t()
        if tif.get_func_details(fi):
            if fi.size():
                print('Argument location:')
                for item in fi:
                    if item.name:
                        ida_kernwin.msg(f'\t{item.name}: ')
                    else:
                        ida_kernwin.msg(f'\t????: ')
                    location = ida_typeinf.print_argloc(item.argloc)
                    if location:
                        ida_kernwin.msg(f'{location}.')
                    elif item.argloc.in_stack:
                        ida_kernwin.msg(f'stack({item.argloc.stkoff():x}).')
                    print(f'{item.type.get_size()}')
            else:
                print('No arguments')
        else:
            print('Problems retrieving function details')
    else:
        print('Problem retrieving function type info.')


if __name__ == '__main__':
    func = ida_funcs.get_func(idc.here())
    if not func:
        print('Place the cursor inside a function and retry.')
    else:
        print_argument_locations(func)