"""
summary: Print basic information about the currently loaded IDB.

description:
    In this script we display some basic information about the
    current IDB:
    * the compiler name and the size of some datatypes
    * Other general IDB information including: application bitness,
    file type, various address ranges, main address and start 
    addresses if exist.
    For this we use some of the inf_get_xxx functions from the
    ida_ida module. 
"""
import ida_ida
import ida_kernwin
import ida_typeinf
import ida_idaapi

ft_dict = {
    ida_ida.f_EXE_old: 'MS DOS EXE File',
    ida_ida.f_COM_old: 'MS DOS COM File',
    ida_ida.f_BIN: 'Binary File',
    ida_ida.f_DRV: 'MS DOS Driver',
    ida_ida.f_WIN: 'New Executable (NE)',
    ida_ida.f_HEX: 'Intel Hex Object File',
    ida_ida.f_MEX: 'MOS Technology Hex Object File',
    ida_ida.f_LX: 'Linear Executable (LX)',
    ida_ida.f_LE: 'Linear Executable (LE)',
    ida_ida.f_NLM: 'Netware Loadable Module (NLM)',
    ida_ida.f_COFF: 'Common Object File Format (COFF)',
    ida_ida.f_PE: 'Portable Executable (PE)',
    ida_ida.f_OMF: 'Object Module Format',
    ida_ida.f_SREC: 'Motorola SREC (S-record)',
    ida_ida.f_ZIP: 'ZIP file (this file is never loaded to IDA database)',
    ida_ida.f_OMFLIB: 'Library of OMF Modules',
    ida_ida.f_AR: 'ar library',
    ida_ida.f_LOADER: 'file is loaded using LOADER DLL',
    ida_ida.f_ELF: 'Executable and Linkable Format (ELF)',
    ida_ida.f_W32RUN: 'Watcom DOS32 Extender (W32RUN)',
    ida_ida.f_AOUT: 'Linux a.out (AOUT)',
    ida_ida.f_PRC: 'PalmPilot program file',
    ida_ida.f_EXE: 'MS DOS EXE File',
    ida_ida.f_COM: 'MS DOS COM File',
    ida_ida.f_AIXAR: 'AIX ar library',
    ida_ida.f_MACHO: 'Mac OS X Mach-O',
    ida_ida.f_PSXOBJ: 'Sony Playstation PSX object file',
    ida_ida.f_MD1IMG: 'Mediatek Firmware Image'
}

def main():
    print('\nCompiler info:')
    cc = ida_ida.compiler_info_t()
    ida_ida.inf_get_cc(cc)
    print(f'\tCompilateur: {ida_typeinf.get_compiler_name(cc.id)}')
    print(f'\t\tByte size: {ida_ida.inf_get_cc_size_b()}')
    print(f'\t\tShort size: {ida_ida.inf_get_cc_size_s()}')
    print(f'\t\tEnum size: {ida_ida.inf_get_cc_size_e()}')
    print(f'\t\tInteger size: {ida_ida.inf_get_cc_size_i()}')
    print(f'\t\tLong size: {ida_ida.inf_get_cc_size_l()}')
    print(f'\t\tLong double size: {ida_ida.inf_get_cc_size_ldbl()}')
    print(f'\t\tLong long size: {ida_ida.inf_get_cc_size_ll()}')

    print('\nGeneral IDB information:')
    print(f'\tApplication bitness: {ida_ida.inf_get_app_bitness()}-bit')
    if ida_ida.inf_is_kernel_mode():
        land = 'Kernel'
    else:
        land = 'User'
    print(f'\tExecution mode: {land}')
    print(f'\tFile type: {ft_dict[ida_ida.inf_get_filetype()]}')
    main_ea = ida_ida.inf_get_main()
    if not  main_ea == ida_idaapi.BADADDR:
        print(f'\tMain entry point: {main_ea:x}')
    start_ea = ida_ida.inf_get_start_ea()
    if not start_ea == ida_idaapi.BADADDR:
        print(f'Start entry: {start_ea:x}')
    print(f'\tMinimum effective address: {ida_ida.inf_get_min_ea():x}')
    print(f'\tMaximum effective address: {ida_ida.inf_get_max_ea():x}')
    print(f'\tPrivate range start: {ida_ida.inf_get_privrange_start_ea():x}')
    print(f'\tPrivate range end: {ida_ida.inf_get_privrange_end_ea():x}')
    
    
ida_kernwin.msg_clear()
main()