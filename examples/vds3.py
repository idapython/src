""" Invert the then and else blocks of a cif_t.

Author: EiNSTeiN_ <einstein@g3nius.org>

This is a rewrite in Python of the vds3 example that comes with hexrays sdk.
"""
from __future__ import print_function

import idautils
import idaapi
import idc

import traceback

NETNODE_NAME = '$ hexrays-inverted-if'

inverter_actname = "vds3:invert"

class invert_action_handler_t(idaapi.action_handler_t):
    def __init__(self, inverter):
        idaapi.action_handler_t.__init__(self)
        self.inverter = inverter

    def activate(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        self.inverter.invert_if_event(vdui)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == idaapi.BWN_PSEUDOCODE else \
            idaapi.AST_DISABLE_FOR_WIDGET


class hexrays_callback_info(object):

    def __init__(self):
        self.vu = None

        self.node = idaapi.netnode()
        if not self.node.create(NETNODE_NAME):
            # node exists
            self.load()
        else:
            self.stored = []

        return

    def load(self):

        self.stored = []

        try:
            data = self.node.getblob(0, 'I')
            if data:
                self.stored = eval(data)
                print('Invert-if: Loaded %s' % (repr(self.stored), ))
        except:
            print('Failed to load invert-if locations')
            traceback.print_exc()
            return

        return

    def save(self):

        try:
            self.node.setblob(repr(self.stored), 0, 'I')
        except:
            print('Failed to save invert-if locations')
            traceback.print_exc()
            return

        return

    def invert_if(self, cfunc, insn):

        if insn.opname != 'if':
            return False

        cif = insn.details

        if not cif.ithen or not cif.ielse:
            return False

        idaapi.qswap(cif.ithen, cif.ielse)
        # Make a copy of 'cif.expr': 'lnot' might destroy its toplevel
        # cexpr_t and return a pointer to its direct child (but we'll want to
        # 'swap' it later, the 'cif.expr' cexpr_t object must remain valid.)
        cond = idaapi.cexpr_t(cif.expr)
        notcond = idaapi.lnot(cond)

        cif.expr.swap(notcond)

        return True

    def add_location(self, ea):
        if ea in self.stored:
            self.stored.remove(ea)
        else:
            self.stored.append(ea)
        self.save()
        return

    def find_if_statement(self, vu):

        vu.get_current_item(idaapi.USE_KEYBOARD)
        item = vu.item

        if item.is_citem() and item.it.op == idaapi.cit_if and item.it.to_specific_type.cif.ielse is not None:
            return item.it.to_specific_type

        if vu.tail.citype == idaapi.VDI_TAIL and vu.tail.loc.itp == idaapi.ITP_ELSE:
            # for tail marks, we know only the corresponding ea,
            # not the pointer to if-statement
            # find it by walking the whole ctree
            class if_finder_t(idaapi.ctree_visitor_t):
                def __init__(self, ea):
                    idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST | idaapi.CV_INSNS)

                    self.ea = ea
                    self.found = None
                    return

                def visit_insn(self, i):
                    if i.op == idaapi.cit_if and i.ea == self.ea:
                        self.found = i
                        return 1 # stop enumeration
                    return 0

            iff = if_finder_t(vu.tail.loc.ea)
            if iff.apply_to(vu.cfunc.body, None):
                return iff.found

        return

    def invert_if_event(self, vu):

        cfunc = vu.cfunc.__deref__()
        i = self.find_if_statement(vu)
        if not i:
            return False

        if self.invert_if(cfunc, i):
            vu.refresh_ctext()
            self.add_location(i.ea)

        return True

    def restore(self, cfunc):

        class visitor(idaapi.ctree_visitor_t):

            def __init__(self, inverter, cfunc):
                idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST | idaapi.CV_INSNS)
                self.inverter = inverter
                self.cfunc = cfunc
                return

            def visit_insn(self, i):
                try:
                    if i.op == idaapi.cit_if and i.ea in self.inverter.stored:
                        self.inverter.invert_if(self.cfunc, i)
                except:
                    traceback.print_exc()
                return 0 # continue enumeration

        visitor(self, cfunc).apply_to(cfunc.body, None)

        return


class vds3_hooks_t(idaapi.Hexrays_Hooks):
    def __init__(self, i):
        idaapi.Hexrays_Hooks.__init__(self)
        self.i = i

    def populating_popup(self, widget, phandle, vu):
        idaapi.attach_action_to_popup(vu.ct, None, inverter_actname)
        return 0

    def maturity(self, cfunc, maturity):
        if maturity == idaapi.CMAT_FINAL:
            self.i.restore(cfunc)
        return 0


if idaapi.init_hexrays_plugin():
    i = hexrays_callback_info()
    idaapi.register_action(
        idaapi.action_desc_t(
            inverter_actname,
            "Invert then/else",
            invert_action_handler_t(i),
            "I"))
    vds3_hooks = vds3_hooks_t(i)
    vds3_hooks.hook()
else:
    print('invert-if: hexrays is not available.')

