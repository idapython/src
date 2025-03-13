import ida_idaapi
import ida_dbg
import ida_kernwin
import ida_name
import ida_idd
import ida_bytes
import ida_ida
import ida_ua
import idc
import os

ST_NONE = 0
ST_RUNTO = 1
ST_ADD_BPT = 2
ST_MONITOR = 3

func_name = 'kernelbase_CreateFileW'

class filemon_dbg_hook_t(ida_dbg.DBG_Hooks):
    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)
        self.func_entry_ea = ida_idaapi.BADADDR
        ida_dbg.run_to(ida_ida.inf_get_start_ea())
        self.stage = ST_RUNTO

    def dbg_process_start(self, pid, tid, ea, path, base, size):
        name = os.path.basename(path)
        ida_kernwin.msg(f'Process started: {name}.\n\tLoad address: {base:x}\n\tPID: {pid:x}\n')

    def dbg_run_to(self, pid, tid=0, ea=0):
        if self.stage == ST_RUNTO:
            ida_kernwin.msg(f'Run to: {ea:x}\n')
            self.stage = ST_ADD_BPT
    
    def dbg_suspend_process(self):
        all_good = True
        if self.stage == ST_ADD_BPT:
            ida_dbg.refresh_debugger_memory()
            
            self.func_entry_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
            if self.func_entry_ea == ida_idaapi.BADADDR:
                all_good = False
                ida_kernwin.msg('Could not resolve \n')
            else:
                ida_kernwin.msg(f'{func_name} found @ {self.func_entry_ea:x}. Setting breakpoint.\n')
                if ida_dbg.add_bpt(self.func_entry_ea):
                    ida_kernwin.msg('Breakpoint added\n')
                else:
                    ida_kernwin.msg('Failed to add the breakpoint.\n')
            
            if not all_good:
                ida_dbg.request_exit_process()
                ida_dbg.run_requests()
            else:
                ida_dbg.continue_process()
                self.stage = ST_MONITOR

    def dbg_bpt(self, tid, bpt_ea):
        if self.stage == ST_MONITOR:
            ida_kernwin.msg(f'In dbg_bpt {bpt_ea:x}.\n')
        
            if bpt_ea == self.func_entry_ea:
                ida_kernwin.msg('Trying to retreive RCX: ')
                rcx_val = ida_idd.regval_t()
                if not ida_dbg.get_reg_val('rcx', rcx_val):
                    ida_kernwin.msg('Could not get rcx register.\n')
                    return 0
                
                fn_ea = rcx_val.ival
                ida_kernwin.msg(f'{fn_ea:x}\n')
                if not ida_bytes.is_mapped(fn_ea):
                    ida_dbg.invalidate_dbgmem_config()
                
                ida_dbg.invalidate_dbgmem_contents(fn_ea, 1024)
                len = ida_bytes.get_max_strlit_length(fn_ea, idc.STRTYPE_C_16)
                ida_kernwin.msg(f'String length: {len}.\n')
                if len:
                    raw = ida_bytes.get_strlit_contents(fn_ea, len, idc.STRTYPE_C_16)
                    ida_kernwin.msg(f' CreateFile -> {raw.decode('UTF-8')}\n')
                
                ida_dbg.continue_process()

                return 0
    
    def dbg_process_exit(self, pid, tid, ea, code):
        if not self.func_entry_ea == ida_idaapi.BADADDR:
            ida_dbg.del_bpt(self.func_entry_ea)
        self.func_entry_ea = ida_idaapi.BADADDR
        self.stage = ST_NONE

try:
    dbg_hook_stat = "un"
    print("Filemon DBG hook: checking for hook...")
    dbg_hook
    print("Filemon DBG hook: unhooking....")
    dbg_hook_stat2 = ""
    dbg_hook.unhook()
    del dbg_hook
except:
    print("Filemon DBG hook: not installed, installing now....")
    dbg_hook_stat = ""
    dbg_hook_stat2 = "un"
    dbg_hook = filemon_dbg_hook_t()
    dbg_hook.hook()