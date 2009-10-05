#
# Demonstrates some functions from the "dbg" class
#

import idaapi
#from idaapi import dbg_write_memory, dbg_read_memory, dbg_get_thread_sreg_base, dbg_get_registers, dbg_get_memory_info

def dump_meminfo(L):
    # startEA, endEA, name, sclass, sbase, bitness, perm
    for (startEA, endEA, name, sclass, sbase, bitness, perm) in L:
        print "%x: %x name=<%s> sclass=<%s> sbase=%x bitness=%2x perm=%2x" % (startEA, endEA, name, sclass, sbase, bitness, perm)

def test_getmeminfo():
    L = idaapi.dbg_get_memory_info()
    dump_meminfo(L)

def test_getregs():
    L = idaapi.dbg_get_registers()
    # name flags class dtyp bit_strings bit_strings_default_mask
    for (name, flags, cls, dtype, bit_strings, bit_strings_default_mask) in L:
        print "name=<%s> flags=%x class=%x dtype=%x bit_strings_mask=%x" % (name, flags, cls, dtype, bit_strings_default_mask)
        if bit_strings:
            for s in bit_strings:
                print "  %s" % s

def test_manual_regions():
    L = idaapi.get_manual_regions()
    if not L:
        print "no manual regions!"
    else:
        dump_meminfo(L)

def test_readwrite():
    ea  = cpu.Eip
    buf = idaapi.dbg_read_memory(ea, 5)
    print "read: ", [hex(ord(x)) for x in buf]
    idaapi.dbg_write_memory(ea, buf)

test_manual_regions()

if idaapi.dbg_can_query():
    print "%x: fs" % (idaapi.dbg_get_thread_sreg_base(idc.GetCurrentThreadId(), cpu.fs))
    test_getmeminfo()
    test_getregs()
    test_readwrite()

else:
    print "run and suspend the debugger first"