import idaapi

def main():
    if not idaapi.is_debugger_on():
        print "Please run the process first!"
        return
    if idaapi.get_process_state() != -1:
        print "Please suspend the debugger first!"
        return

    dn = idaapi.get_debug_names(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA)
    for i in dn:
        print "%08x: %s" % (i, dn[i])

main()
