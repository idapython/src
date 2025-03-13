
import ida_dbg
import ida_idaapi
import ida_idd
import ida_kernwin
import ida_typeinf
import ida_name

def log(msg):
    print(">>> %s" % msg)

class appcall_hooks_t(ida_dbg.DBG_Hooks):
    def __init__(self, name_funcs=[]):
        ida_dbg.DBG_Hooks.__init__(self) # important

        for ea, func_name in name_funcs:
            log("Renaming 0x%08x to \"%s\"" % (ea, func_name))
            ida_name.set_name(ea, func_name)

        for func_name, func_proto in [
                ("ref4", "int ref4(int *);"),
                ("ref8", "int ref8(long long int *);"),
        ]:
            log("Setting '%s's prototype" % func_name)
            func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
            assert(ida_typeinf.apply_cdecl(None, func_ea, func_proto))


    def dbg_run_to(self, pid, tid, ea):
        log("'run_to' reached its target location. Performing appcalls.")

        for func_name in ["ref4", "ref8"]:
            int_value = ida_idd.Appcall.int64(5)
            int_ptr = ida_idd.Appcall.byref(int_value)
            if ida_idd.Appcall[func_name](int_ptr):
                log("Appcall (%s) succeeded: int_value.value=%s, int_ptr.value=%s" % (
                    func_name,
                    int_value.value,
                    int_ptr.value))
            else:
                log("Appcall (%s) failed" % func_name)


    def run(self):
        log("Running program up to current address, and letting the hooks do the rest")
        assert(ida_dbg.run_to(ida_kernwin.get_screen_ea()))
