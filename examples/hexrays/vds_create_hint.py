"""
summary: decompiler hints

description:
  Handle `ida_hexrays.hxe_create_hint` notification using hooks,
  to return our own.

  If the object under the cursor is:

  * a function call, prefix the original decompiler hint with `==> `
  * a local variable declaration, replace the hint with our own in
    the form of `!{varname}` (where `{varname}` is replaced with the
    variable name)
  * an `if` statement, replace the hint with our own, saying "condition"
"""

import ida_idaapi
import ida_hexrays

class hint_hooks_t(ida_hexrays.Hexrays_Hooks):
    def create_hint(self, vu):
        if vu.get_current_item(ida_hexrays.USE_MOUSE):
            cit = vu.item.citype
            if cit == ida_hexrays.VDI_LVAR:
                return 1, "!%s" % vu.item.l.name, 1
            elif cit == ida_hexrays.VDI_EXPR:
                ce = vu.item.e
                if ce.op == ida_hexrays.cot_call:
                    return 0, "==> ", 1
                if ce.op == ida_hexrays.cit_if:
                    return 1, "condition", 1
        return 0

vds_hooks = hint_hooks_t()
vds_hooks.hook()
