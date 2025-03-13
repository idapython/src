import ida_ida
import ida_idaapi
import ida_bytes
import ida_funcs

def main():
    if ida_ida.inf_get_filetype() != ida_ida.f_PE or not ida_ida.inf_is_64bit() or ida_ida.inf_get_procname() != 'metapc':
        return
    
    pattern_bytes = b'\x75\x03\x0F\x05'
    rstart = ida_ida.inf_get_min_ea()

    found = False
    while True:
        rstart = ida_bytes.find_bytes(pattern_bytes, rstart)
        if rstart == ida_idaapi.BADADDR:
            break
        fname = ida_funcs.get_func_name(rstart)
        if fname and not found:
            found = True
            print('Syscall found:')
        if fname:
            print(f'\t@ {rstart + 2:x} ({fname})')
        rstart += 1
        
if __name__ == '__main__':
    main()