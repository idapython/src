"""'Hints' plugin for Hexrays Decompiler

Hijack the 'hxe_create_hint' notification, to return our own.
If the object under the cursor is:
 - a function call, prefix the original decompiler hint with "==> "
 - a local variable declaration, replace the hint with our own in the form of "!{varname}" (where '{varname}' is replaced w/ the variable name)
 - an 'if' statement, replace the hint with our own, saying "condition"
"""

import ida_hexrays

def create_hint_cb(event, *args):
    if event == ida_hexrays.hxe_create_hint:
        vu = args[0]
        if vu.get_current_item(ida_hexrays.USE_MOUSE):
            cit = vu.item.citype
            if cit == ida_hexrays.VDI_LVAR:
                return 1, "!%s" % vu.item.l.name, 1
            elif cit == ida_hexrays.VDI_EXPR:
                ce = vu.item.e
                if ce.op == ida_hexrays.cot_call:
                    return 2, "==> ", 1
                if ce.op == ida_hexrays.cit_if:
                    return 1, "condition", 1
            return 0
    return 0

if ida_hexrays.init_hexrays_plugin():
    ida_hexrays.install_hexrays_callback(create_hint_cb)
else:
    print 'hexrays is not available.'

