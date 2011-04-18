#---------------------------------------------------------------------
# UI hook example
#
# (c) Hex-Rays
#
# Maintained By: IDAPython Team
#
#---------------------------------------------------------------------

import idaapi

class MyUiHook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
        self.cmdname = "<no command>"

    def preprocess(self, name):
        print("IDA preprocessing command: %s" % name)
        self.cmdname = name
        return 0

    def postprocess(self):
        print("IDA finished processing command: %s" % self.cmdname)
        return 0


#---------------------------------------------------------------------
# Remove an existing hook on second run
try:
    ui_hook_stat = "un"
    print("UI hook: checking for hook...")
    uihook
    print("UI hook: unhooking....")
    uihook.unhook()
    del uihook
except:
    print("UI hook: not installed, installing now....")
    ui_hook_stat = ""
    uihook = MyUiHook()
    uihook.hook()

print("UI hook %sinstalled. Run the script again to %sinstall" % (ui_hook_stat, ui_hook_stat))
