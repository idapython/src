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

    def saving(self):
        """
        The kernel is saving the database.

        @return: Ignored
        """
        print("Saving....")

    def saved(self):
        """
        The kernel has saved the database.

        @return: Ignored
        """
        print("Saved")

    def term(self):
        """
        IDA is terminated and the database is already closed.
        The UI may close its windows in this callback.

        This callback is best used within the context of a plugin_t with PLUGIN_FIX flags
        """
        print("IDA terminated")

    def get_ea_hint(self, ea):
        """
        The UI wants to display a simple hint for an address in the navigation band

        @param ea: The address
        @return: String with the hint or None
        """
        print("get_ea_hint(%x)" % ea)

    def populating_widget_popup(self, widget, popup, ctx):
        """
        The UI is currently populating the widget popup. Now is a good time to
        attach actions.
        """
        print("populating_widget_popup; title: %s" % (ctx.widget_title,))

    def finish_populating_widget_popup(self, widget, popup, ctx):
        """
        The UI is done populating the widget popup. Now is the last chance to
        attach actions.
        """
        print("finish_populating_widget_popup; title: %s" % (ctx.widget_title,))


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
