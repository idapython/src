'''
summary: Use bin_search to find the occurences of 
    "mov rax, cs:___security_cookie"

description:
    This example shows a way of finding the 
    "mov rax, cs:___security_cookie" instruction in a x64 database using
    bin_search. For this we:
    * check that the database is, indeed an x64 one
    * build the binary pattern vector
    * search for the pattern
    * for each result we validate that operand 1 (Op2.addr) points to 
    __security_cookie
    * once the list is built, print it ([index] func_name @ address)
'''

import ida_bytes
import ida_idaapi
import ida_name
import ida_funcs
import ida_ua
import ida_ida

message = 'Pattern \"mov     rax, cs:__security_cookie\" found:'

pattern_bytes = b'\x48\x8B\x05\x56\xAF\x35\x00'
pattern_mask = b'\x01\x01\x01\x00\x00\x00\x01'

def is_pc_64():
    if ida_ida.inf_get_procname() != 'metapc' and not ida_ida.inf_is64bit():
        return False
    return True

def build_pattern_vec(bytes, mask = None):
    pattern = ida_bytes.compiled_binpat_t()
    pattern.bytes = bytes
    if mask:
        pattern.mask = mask
    
    pattern_vec = ida_bytes.compiled_binpat_vec_t()
    pattern_vec.push_back(pattern)

    return pattern_vec

def is_valid(ea, sc_ea):
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, ea)

    op = insn.Op2
    if op.type == 2 and op.dtype == 7 and op.addr == sc_ea:
        return True
    
    return False

def build_ea_list(start_ea, end_ea, pattern_vec, flags, sc_ea):
    ea_list = []
    
    while start_ea < end_ea:
        start_ea, _ = ida_bytes.bin_search(start_ea, end_ea, pattern_vec, flags)
        if start_ea == ida_idaapi.BADADDR:
            break

        if is_valid(start_ea, sc_ea):
            ea_list.append(start_ea)
        
        start_ea += 1
    
    return ea_list

def print_result(str, lst):
    print(str)

    idx = 0
    for ea in lst:
        fname = ida_funcs.get_func_name(ea)
        dname = ida_name.demangle_name(fname, 0)
        pname = fname
        if dname:
            pname = dname

        print(f'[{idx}] {pname} @ {ea:x}')
        idx += 1


def main():
    if not is_pc_64():
        print('This script will only work for x64 databases.')
        return
    
    security_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, '__security_cookie')
    if security_ea == ida_idaapi.BADADDR:
        print('No reference to __security_cookie.')
        return
    
    pv = build_pattern_vec(pattern_bytes, pattern_mask)

    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOCASE | ida_bytes.BIN_SEARCH_NOBREAK
    lst = build_ea_list(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea(), pv, flags, security_ea)

    print_result(message, lst)

if __name__ == '__main__':
    main()
