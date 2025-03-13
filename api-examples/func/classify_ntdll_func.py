"""
summary: This script shows an example of function clasification
    using the dirtree API.

description:
    In this example we calssify the functions of ntdll.dll into
    three categories (there are more but three is enough for this
    example):
    * Runtime library (Rtl).
    * System calls (Zw).
    * Kernel internal (Ki)
    For each category we create a corresponding folder in the functions
    dirtreee. Then we iterates through all the functions and use the
    folder name as filter: namely if a function name starts with 'Rtl'
    it is moved to the Rtl folder and so on.

level: intermediate.
"""
import ida_funcs
import ida_dirtree
import idautils

lst = ['Rtl', 'Zw', 'Ki']

def main():
    #
    # Get the functions standard dirtree.
    #
    dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)

    #
    # Create the folders.
    #
    for folder in lst:
        result = dt.mkdir(folder)
        if result != ida_dirtree.DTE_OK and result != ida_dirtree.DTE_ALREADY_EXISTS:
            print(f'Not able to create folder {folder} ({result:x})')
            return
    
    #
    # For all the function in the base directory, check that the function name
    # starts with the provided prefix. If it does we try to move it to the
    # corresponding folder.
    #
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea)
        for func_prefix in lst:
            if name and name.startswith(func_prefix):
                if dt.isfile(name):
                    if dt.rename(name, f'{func_prefix}/{name}') != ida_dirtree.DTE_OK:
                        print(f'Not able to move {name} inside {func_prefix} folder')
                    else:
                        print(f'{name} moved in {func_prefix} folder')

if __name__ == '__main__':
    main()