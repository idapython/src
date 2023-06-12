"""
summary: invert if/else blocks

description:
  Registers an action that can be used to invert the `if`
  and `else` blocks of a `ida_hexrays.cif_t`.

  For example, a statement like

      if ( cond )
      {
        statements1;
      }
      else
      {
        statements2;
      }

  will be displayed as

      if ( !cond )
      {
        statements2;
      }
      else
      {
        statements1;
      }

  The modifications are persistent: the user can quit & restart
  IDA, and the changes will be present.

author: EiNSTeiN_ (einstein@g3nius.org)
"""

import idautils

import ida_kernwin
import ida_hexrays
import ida_netnode
import ida_idaapi
import ida_idp

import traceback

NETNODE_NAME = '$ hexrays-inverted-if'

inverter_actname = "vds3:invert"

class invert_action_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, inverter):
        ida_kernwin.action_handler_t.__init__(self)
        self.inverter = inverter

    def activate(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        self.inverter.invert_if_event(vdui)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET


class hexrays_callback_info(object):

    def __init__(self):
        self.vu = None

        self.node = ida_netnode.netnode()
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
                self.stored = eval(data.decode("UTF-8"))
                print('Invert-if: Loaded %s' % (repr(self.stored), ))
        except:
            print('Failed to load invert-if locations')
            traceback.print_exc()
            return

        return

    def save(self):

        try:
            self.node.setblob(repr(self.stored).encode("UTF-8"), 0, 'I')
        except:
            print('Failed to save invert-if locations')
            traceback.print_exc()
            return

        return

    def invert_if(self, insn):

        if insn.opname != 'if':
            return False

        cif = insn.details

        if not cif.ithen or not cif.ielse:
            return False

        ida_hexrays.qswap(cif.ithen, cif.ielse)
        # Make a copy of 'cif.expr': 'lnot' might destroy its toplevel
        # cexpr_t and return a pointer to its direct child (but we'll want to
        # 'swap' it later, the 'cif.expr' cexpr_t object must remain valid.)
        cond = ida_hexrays.cexpr_t(cif.expr)
        notcond = ida_hexrays.lnot(cond)

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

        vu.get_current_item(ida_hexrays.USE_KEYBOARD)
        item = vu.item

        if item.is_citem() and item.it.op == ida_hexrays.cit_if and item.it.to_specific_type.cif.ielse is not None:
            return item.it.to_specific_type

        if vu.tail.citype == ida_hexrays.VDI_TAIL and vu.tail.loc.itp == ida_hexrays.ITP_ELSE:
            # for tail marks, we know only the corresponding ea,
            # not the pointer to if-statement
            # find it by walking the whole ctree
            class if_finder_t(ida_hexrays.ctree_visitor_t):
                def __init__(self, ea):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)

                    self.ea = ea
                    self.found = None
                    return

                def visit_insn(self, i):
                    if i.op == ida_hexrays.cit_if and i.ea == self.ea:
                        self.found = i
                        return 1 # stop enumeration
                    return 0

            iff = if_finder_t(vu.tail.loc.ea)
            if iff.apply_to(vu.cfunc.body, None):
                return iff.found

        return

    def invert_if_event(self, vu):

        i = self.find_if_statement(vu)
        if not i:
            return False

        if self.invert_if(i):
            vu.refresh_ctext()
            self.add_location(i.ea)

        return True

    def restore(self, cfunc):

        class visitor(ida_hexrays.ctree_visitor_t):

            def __init__(self, inverter, cfunc):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
                self.inverter = inverter
                self.cfunc = cfunc
                return

            def visit_insn(self, i):
                try:
                    if i.op == ida_hexrays.cit_if and i.ea in self.inverter.stored:
                        self.inverter.invert_if(i)
                except:
                    traceback.print_exc()
                return 0 # continue enumeration

        visitor(self, cfunc).apply_to(cfunc.body, None)

        return


class vds3_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self, i):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.i = i

    def populating_popup(self, widget, phandle, vu):
        ida_kernwin.attach_action_to_popup(vu.ct, None, inverter_actname)
        return 0

    def maturity(self, cfunc, maturity):
        if maturity == ida_hexrays.CMAT_FINAL:
            self.i.restore(cfunc)
        return 0

class idp_hooks_t(ida_idp.IDP_Hooks):
    def __init__(self, i):
        ida_idp.IDP_Hooks.__init__(self)
        self.i = i

    # 'node' refers to index of the named node, this index became invalid after
    # privrange moving, so we recreate the node here to update nodeidx
    def ev_privrange_changed(self, old_privrange, delta):
        i.node.create(NETNODE_NAME)


# a plugin interface, boilerplate code
class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Hex-Rays if-inverter (IDAPython)"
    wanted_hotkey = ""
    comment = "Sample plugin3 for Hex-Rays decompiler"
    help = ""
    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            i = hexrays_callback_info()
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    inverter_actname,
                    "Invert then/else",
                    invert_action_handler_t(i),
                    "I"))
            self.vds3_hooks = vds3_hooks_t(i)
            self.vds3_hooks.hook()
            # we need this hook to react to privrange moving event
            self.idp_hooks = idp_hooks_t(i)
            self.idp_hooks.hook()
            return ida_idaapi.PLUGIN_KEEP # keep us in the memory
    def term(self):
        self.vds3_hooks.unhook()
    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return my_plugin_t()
