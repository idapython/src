"""
summary: print notifications about function prototype changes

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we will create an IDB hook that intercepts `ti_changed`
    IDB events, and if it is a function prototype that changed, print it.

level: intermediate
"""
import ida_funcs
import ida_idp
import ida_typeinf

class ti_changed_t(ida_idp.IDB_Hooks):

    def print_details(self, tif, ea):
        if tif.is_func():
            func_name = ida_funcs.get_func_name(ea)
            print(f"\t{tif._print(func_name)}")

    def ti_changed(self, ea, types, fields):
        tif = ida_typeinf.tinfo_t()
        tif.deserialize(None, types, fields)
        if tif.is_func():
            print(f"Function type information changed @ {ea:x}")
            self.print_details(tif, ea)

try:
    idbhook.unhook()
    del idbhook
    print(f"IDB hook uninstalled. Run the script again to install")
except:
    idbhook = ti_changed_t()
    idbhook.hook()
    print(f"IDB hook installed. Run the script again to uninstall")
