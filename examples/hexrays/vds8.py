"""
summary: using `ida_hexrays.udc_filter_t`

description:
  Registers an action that uses a `ida_hexrays.udc_filter_t` to decompile
  `svc 0x900001` and `svc 0x9000F8` as function calls to
  `svc_exit()` and `svc_exit_group()` respectively.

  You will need to have an ARM + Linux IDB for this script to be usable

  In addition to having a shortcut, the action will be present
  in the context menu.
"""

import ida_idaapi
import ida_hexrays
import ida_kernwin
import ida_allins

ACTION_NAME = "vds8.py:udcall"
ACTION_SHORTCUT = "Ctrl+Shift+U"

# --------------------------------------------------------------------------
class udc_exit_t(ida_hexrays.udc_filter_t):
    def __init__(self, code, name):
        ida_hexrays.udc_filter_t.__init__(self)
        if not self.init("int __usercall %s@<R0>(int status@<R1>);" % name):
            raise Exception("Couldn't initialize udc_exit_t instance")
        self.code = code
        self.installed = False

    def match(self, cdg):
        return cdg.insn.itype == ida_allins.ARM_svc and cdg.insn.Op1.value == self.code

    def install(self):
        ida_hexrays.install_microcode_filter(self, True);
        self.installed = True

    def uninstall(self):
        ida_hexrays.install_microcode_filter(self, False);
        self.installed = False

    def toggle_install(self):
        if self.installed:
            self.uninstall()
        else:
            self.install()


# --------------------------------------------------------------------------
class toggle_udc_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        udc_exit.toggle_install();
        udc_exit_group.toggle_install();
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        vu.refresh_view(True)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET


# --------------------------------------------------------------------------
class my_hooks_t(ida_kernwin.UI_Hooks):
    def populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME)
my_hooks = my_hooks_t()
my_hooks.hook()


# --------------------------------------------------------------------------
SVC_EXIT       = 0x900001
SVC_EXIT_GROUP = 0x9000f8

if ida_hexrays.init_hexrays_plugin():
    udc_exit = udc_exit_t(SVC_EXIT, "svc_exit")
    udc_exit.toggle_install()

    udc_exit_group = udc_exit_t(SVC_EXIT_GROUP, "svc_exit_group")
    udc_exit_group.toggle_install()

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "vds8.py:Toggle UDC",
            toggle_udc_ah_t(),
            ACTION_SHORTCUT))

