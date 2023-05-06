"""
summary: better integrating custom widgets in the desktop layout

description:
  This is an example demonstrating how one can create widgets from a plugin,
  and have them re-created automatically at IDA startup-time or at desktop load-time.

  This example should be placed in the 'plugins' directory of the
  IDA installation, for it to work.

  There are 2 ways to use this example:
  1) reloading an IDB, where the widget was opened
     - open the widget ('View > Open subview > ...')
     - save this IDB, and close IDA
     - restart IDA with this IDB
       => the widget will be visible

  2) reloading a desktop, where the widget was opened
     - open the widget ('View > Open subview > ...')
     - save the desktop ('Windows > Save desktop...') under, say, the name 'with_auto'
     - start another IDA instance with some IDB, and load that desktop
       => the widget will be visible

keywords: desktop
"""

import ida_idaapi
import ida_kernwin

title = "Auto-instantiable at IDA startup"

# -----------------------------------------------------------------------
class auto_inst_t(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        ida_kernwin.simplecustviewer_t.__init__(self)

    def Create(self):
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False

        text = __doc__
        for l in text.split("\n"):
            self.AddLine(l)
        return True

# -----------------------------------------------------------------------
auto_inst = None

# -----------------------------------------------------------------------
def register_open_action():
    """
    Provide the action that will create the widget
    when the user asks for it.
    """
    class create_widget_t(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            if ida_kernwin.find_widget(title) is None:
                global auto_inst
                auto_inst = auto_inst_t()
                assert(auto_inst.Create())
                assert(auto_inst.Show())

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    action_name = "autoinst:create"
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            action_name,
            title,
            create_widget_t()))
    ida_kernwin.attach_action_to_menu(
        "View/Open subviews/Strings",
        action_name,
        ida_kernwin.SETMENU_APP)

# -----------------------------------------------------------------------
auto_inst_hooks = None
def register_autoinst_hooks():
    """
    Register hooks that will create the widget when IDA
    requires it because of the IDB/desktop
    """
    class auto_inst_hooks_t(ida_kernwin.UI_Hooks):
        def create_desktop_widget(self, ttl, cfg):
            if ttl == title:
                global auto_inst
                auto_inst = auto_inst_t()
                assert(auto_inst.Create())
                return auto_inst.GetWidget()

    global auto_inst_hooks
    auto_inst_hooks = auto_inst_hooks_t()
    auto_inst_hooks.hook()

# -----------------------------------------------------------------------
class auto_inst_plugin_t(ida_idaapi.plugin_t):
    flags = 0
    comment = "This plugin creates a widget that will be recreated automatically if needed, either at startup or when loading a desktop that requires it"
    help = "No help, really"
    wanted_name = "autoinst"
    wanted_hotkey = ""

    def init(self):
        register_open_action()
        register_autoinst_hooks()

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return auto_inst_plugin_t()
