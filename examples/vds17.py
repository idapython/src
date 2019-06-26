#
#      Hex-Rays Decompiler project
#      Copyright (c) 2007-2019 by Hex-Rays, support@hex-rays.com
#      ALL RIGHTS RESERVED.
#
#      Sample plugin for Hex-Rays Decompiler.
#      It shows how to use "Select offsets" widget (select_udt_by_offset() call).
#      This plugin repeats the Alt-Y functionality.
#      Usage: place cursor on the union field and press Shift-T
#
#      This is a rewrite in Python of the vds17 example that comes with hexrays sdk.
#

import ida_idaapi
import ida_hexrays

# --------------------------------------------------------------------------
class func_stroff_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # get current item
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        # check the current item is union field
        if not vu.item.is_citem():
            return 0
        e = vu.item.e
        while True:
            op = e.op
            if op != ida_hexrays.cot_memptr and op != ida_hexrays.cot_memref:
                return 0
            e = e.x
            if op == ida_hexrays.cot_memptr:
                if e.type.is_union():
                    break
            else:
                if ida_typeinf.remove_pointer(e.type).is_union():
                    break
            if not e.type.is_udt():
                return 0

        # calculate member's offset
        off = 0
        e = vu.item.e
        while True:
            e2 = e.x
            tif = ida_typeinf.remove_pointer(e2.type)
            if not tif.is_union():
                off += e.m
            e = e2
            if e2.op != ida_hexrays.cot_memptr and e2.op != ida_hexrays.cot_memref:
                break
            if not e2.type.is_udt():
                break

        # go up and collect more member references (in order to calculate the final offset)
        p = vu.item.e
        while True:
            p2 = vu.cfunc.body.find_parent_of(p)
            if p2.op == ida_hexrays.cot_memptr:
                break
            if p2.op == ida_hexrays.cot_memref:
                e2 = p2
                tif = remove_pointer(e2.x.type)
                if not tif.is_union():
                    off += e2.m
                p = p2
                continue
            if p2.op == ida_hexrays.cot_ref:
                # handle &a.b + N (this expression may appear if the user previously selected
                #                  a wrong field)
                delta = 0
                add = vu.cfunc.body.find_parent_of(p2)
                if add.op == ida_hexrays.cot_cast:
                    add = vu.cfunc.body.find_parent_of(add)
                if add.op == ida_hexrays.cot_add and add.y.op == ida_hexrays.cot_num:
                    delta = add.y.numval()
                    objsize = add.type.get_ptrarr_objsize()
                    nbytes = delta * objsize
                    off += nbytes
            # we can use the calling helpers like WORD/BYTE/...
            # to calculate the more precise offset
            # if ( p2->op == cot_call && (e2->exflags & EXFL_LVALUE) != 0 )
            break

        ea = vu.item.e.ea
        # the item itself may be unaddressable.
        # TODO: find its addressable parent
        if ea == idaapi.BADADDR:
            return 0

        # prepare the text representation for the item,
        # use the neighborhoods of cursor
        line = idaapi.tag_remove(ida_kernwin.get_custom_viewer_curline(vu.ct, False))
        line_len = len(line)
        x = max(0, vu.cpos.x - 10)
        l = min(10, line_len - vu.cpos.x) + 10
        line = line[x:x+l]

        ops = ida_hexrays.ui_stroff_ops_t()
        op = ops.push_back()
        op.offset = off
        op.text = line

        class set_union_sel_t(ida_hexrays.ui_stroff_applicator_t):
            def __init__(self, eas):
                ida_hexrays.ui_stroff_applicator_t.__init__(self)
                self.eas = eas

            def apply(self, opnum, path):
                vu.cfunc.set_user_union_selection(self.eas[opnum], path)
                vu.cfunc.save_user_unions()
                return True

        su = set_union_sel_t([ea])
        res = ida_hexrays.select_udt_by_offset(None, ops, su)
        if res != 0:
            # regenerate ctree
            vu.refresh_view(True)

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET


# --------------------------------------------------------------------------
if ida_hexrays.init_hexrays_plugin():
    print("Hex-rays version %s has been detected, Structure offsets ready to use" % idaapi.get_hexrays_version())
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "vds17:strchoose",
            "Structure offsets",
            func_stroff_ah_t(),
            "Shift+T"))
else:
    print('vds17: Hex-rays is not available.')
