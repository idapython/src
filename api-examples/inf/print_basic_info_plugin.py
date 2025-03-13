"""
summary: Python plugin that print basic IDB information.

description:
    Demonstrates how to turn an IDA python script into
    an IDA Python plugin.
"""
import ida_idaapi
import ida_kernwin
import print_basic_info

class pbi_plugmod_t(ida_idaapi.plugmod_t):
    def __del__(self):
        ida_kernwin.msg("PBI >> unloaded pbi_plugmod\n")

    def run(self, arg):
        ida_kernwin.msg("PBI >> run() called with %d!\n" % arg)
        print_basic_info.main()
        return True

class pbi_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "This is a simple plugin printing basic info"
    help = ""
    wanted_name = "Print Basic Info (PBI) plugin"
    wanted_hotkey = "Ctrl-Alt-F12"


    def init(self):
        ida_kernwin.msg("PBI >> init() called!\n")
        return pbi_plugmod_t()

    def term(self):
        ida_kernwin.msg("PBI >> ERROR: term() called (should never be called)\n")

def PLUGIN_ENTRY():
    return pbi_plugin_t()