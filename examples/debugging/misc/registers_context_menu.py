"""
summary: adding actions to the "registers" widget(s)

description:
  It's possible to add actions to the context menu of
  pretty much all widgets in IDA.

  This example shows how to do just that for
  registers-displaying widgets (e.g., "General registers")
"""

import ida_dbg
import ida_idd
import ida_kernwin
import ida_ua

ACTION_NAME = "registers_context_menu:dump_reg"

class dump_reg_ah_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        name = ctx.regname
        value = ida_dbg.get_reg_val(name)
        rtype = "integer"
        rinfo = ida_idd.register_info_t()
        if ida_dbg.get_dbg_reg_info(name, rinfo):
            if rinfo.dtype == ida_ua.dt_byte:
                value = "0x%02x" % value
            elif rinfo.dtype == ida_ua.dt_word:
                value = "0x%04x" % value
            elif rinfo.dtype == ida_ua.dt_dword:
                value = "0x%08x" % value
            elif rinfo.dtype == ida_ua.dt_qword:
                value = "0x%016x" % value
            else:
                rtype = "float"
        print("> Register %s (of type %s): %s" % (name, rtype, value))

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_CPUREGS \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


if ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Dump register info",
            dump_reg_ah_t())):

    class registers_hooks_t(ida_kernwin.UI_Hooks):
        def finish_populating_widget_popup(self, form, popup):
            if ida_kernwin.get_widget_type(form) == ida_kernwin.BWN_CPUREGS:
                ida_kernwin.attach_action_to_popup(form, popup, ACTION_NAME)

    hooks = registers_hooks_t()
    hooks.hook()
else:
    print("Failed to register action")
