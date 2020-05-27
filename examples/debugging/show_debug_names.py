from __future__ import print_function

import ida_dbg
import ida_ida
import ida_name

def main():
    if not ida_dbg.is_debugger_on():
        print("Please run the process first!")
        return
    if ida_dbg.get_process_state() != -1:
        print("Please suspend the debugger first!")
        return

    dn = ida_name.get_debug_names(
        ida_ida.inf_get_min_ea(),
        ida_ida.inf_get_max_ea())
    for i in dn:
        print("%08x: %s" % (i, dn[i]))

main()
