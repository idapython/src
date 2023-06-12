"""
summary: being notified, and logging a few UI events

description:
  hooks to be notified about certain UI events, and
  dump their information to the "Output" window
"""

import inspect

import ida_kernwin

class MyUiHook(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        self.cmdname = "<no command>"
        self.inhibit_log = 0;

    def _format_value(self, v):
        return str(v)

    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(">>> MyUiHook: %s" % msg)
            else:
                stack = inspect.stack()
                frame, _, _, _, _, _ = stack[1]
                args, _, _, values = inspect.getargvalues(frame)
                method_name = inspect.getframeinfo(frame)[2]
                argstrs = []
                for arg in args[1:]:
                    argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
                print(">>> MyUiHook.%s: %s" % (method_name, ", ".join(argstrs)))
        return 0

    def preprocess_action(self, name):
        self._log("IDA preprocessing command: %s" % name)
        self.cmdname = name
        return 0

    def postprocess_action(self):
        self._log("IDA finished processing command: %s" % self.cmdname)
        return 0

    def saving(self):
        """
        The kernel is saving the database.

        @return: Ignored
        """
        self._log("Saving....")

    def saved(self):
        """
        The kernel has saved the database.

        @return: Ignored
        """
        self._log("Saved")

    def term(self):
        """
        IDA is terminated and the database is already closed.
        The UI may close its windows in this callback.

        This callback is best used within the context of a plugin_t with PLUGIN_FIX flags
        """
        self._log("IDA terminated")

    def get_ea_hint(self, ea):
        """
        The UI wants to display a simple hint for an address in the navigation band

        @param ea: The address
        @return: String with the hint or None
        """
        self._log("get_ea_hint(%x)" % ea)

    def populating_widget_popup(self, widget, popup, ctx):
        """
        The UI is currently populating the widget popup. Now is a good time to
        attach actions.
        """
        self._log("populating_widget_popup; title: %s" % (ctx.widget_title,))

    def finish_populating_widget_popup(self, widget, popup, ctx):
        """
        The UI is done populating the widget popup. Now is the last chance to
        attach actions.
        """
        self._log("finish_populating_widget_popup; title: %s" % (ctx.widget_title,))

    def range(self):
        self._log()

    def idcstart(self):
        self._log()

    def idcstop(self):
        self._log()

    def suspend(self):
        self._log()

    def resume(self):
        self._log()

    def debugger_menu_change(self, enable):
        self._log()

    def widget_visible(self, widget):
        self._log()

    def widget_closing(self, widget):
        self._log()

    def widget_invisible(self, widget):
        self._log()

    def get_item_hint(self, ea, max_lines):
        self._log()

    def get_custom_viewer_hint(self, viewer, place):
        self._log()

    def database_inited(self, is_new_database, idc_script):
        self._log()

    def ready_to_run(self):
        self._log()

    def get_chooser_item_attrs(self, chooser, n, attrs):
        self._log()

    def updating_actions(self, ctx):
        self._log()

    def updated_actions(self):
        self._log()

    def plugin_loaded(self, plugin_info):
        self._log()

    def plugin_unloading(self, plugin_info):
        self._log()

    def current_widget_changed(self, widget, prev_widget):
        self._log()

    def screen_ea_changed(self, ea, prev_ea):
        self._log()

    def create_desktop_widget(self, title, cfg):
        self._log()

    def get_lines_rendering_info(self, out, widget, info):
        self._log()

    def get_widget_config(self, widget, cfg):
        self._log()

    def set_widget_config(self, widget, cfg):
        self._log()

    def initing_database(self):
        self._log()

    def destroying_procmod(self, procmod):
        self._log()

    def destroying_plugmod(self, plugmod, entry):
        self._log()

    def desktop_applied(self, name, from_idb, type):
        self._log()


#---------------------------------------------------------------------
# Remove an existing hook on second run
try:
    ui_hook_stat = "un"
    print("UI hook: checking for hook...")
    uihook
    print("UI hook: unhooking....")
    ui_hook_stat2 = ""
    uihook.unhook()
    del uihook
except:
    print("UI hook: not installed, installing now....")
    ui_hook_stat = ""
    ui_hook_stat2 = "un"
    uihook = MyUiHook()
    uihook.hook()

print("UI hook %sinstalled. Run the script again to %sinstall" % (ui_hook_stat, ui_hook_stat2))
