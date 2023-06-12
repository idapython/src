"""
summary: various decompiler hooks

description:
  Shows how to hook to many notifications sent by the decompiler.

  This plugin doesn't really accomplish anything: it just prints
  the parameters.

  The list of notifications handled below should be exhaustive,
  and is there to hint at what is possible to accomplish by
  subclassing `ida_hexrays.Hexrays_Hooks`

see_also: curpos_details
"""

import inspect

import ida_idaapi
import ida_typeinf
import ida_hexrays

class vds_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.display_shortened_cfuncs = False
        self.display_vdui_curpos = False
        self.inhibit_log = 0;

    def _format_lvar(self, v):
        parts = []
        if v:
            if v.name:
                parts.append("name=%s" % v.name)
            if v.cmt:
                parts.append("cmt=%s" % v.cmt)
            parts.append("width=%s" % v.width)
            parts.append("defblk=%s" % v.defblk)
            parts.append("divisor=%s" % v.divisor)
        return "{%s}" % ", ".join(parts)

    def _format_vdui_curpos(self, v):
        return "cpos={lnnum=%d, x=%d, y=%d}" % (v.cpos.lnnum, v.cpos.x, v.cpos.y)

    def _format_value(self, v):
        if isinstance(v, ida_hexrays.lvar_t):
            v = self._format_lvar(v)
        elif isinstance(v, ida_hexrays.cfunc_t):
            if self.display_shortened_cfuncs:
                self.inhibit_log += 1
                v = str(v)
                if len(v) > 20:
                    v = v[0:20] + "[...snipped...]"
                self.inhibit_log -= 1
            else:
                v = "<cfunc>" # cannot print contents: we'll end up being called recursively
        elif isinstance(v, ida_hexrays.vdui_t) and self.display_vdui_curpos:
            v = str(v) + " " + self._format_vdui_curpos(v)
        return str(v)

    def _log(self):
        if self.inhibit_log <= 0:
            stack = inspect.stack()
            frame, _, _, _, _, _ = stack[1]
            args, _, _, values = inspect.getargvalues(frame)
            method_name = inspect.getframeinfo(frame)[2]
            argstrs = []
            for arg in args[1:]:
                argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
            print("### %s: %s" % (method_name, ", ".join(argstrs)))
        return 0

    def flowchart(self, fc):
        return self._log()

    def stkpnts(self, mba, stkpnts):
        return self._log()

    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        return self._log()

    def microcode(self, mba):
        return self._log()

    def preoptimized(self, mba):
        return self._log()

    def locopt(self, mba):
        return self._log()

    def prealloc(self, mba):
        return self._log()

    def glbopt(self, mba):
        return self._log()

    def structural(self, ctrl_graph):
        return self._log()

    def maturity(self, cfunc, maturity):
        return self._log()

    def interr(self, code):
        return self._log()

    def combine(self, blk, insn):
        return self._log()

    def print_func(self, cfunc, printer):
        return self._log()

    def func_printed(self, cfunc):
        return self._log()

    def resolve_stkaddrs(self, mba):
        return self._log()

    def open_pseudocode(self, vu):
        return self._log()

    def switch_pseudocode(self, vu):
        return self._log()

    def refresh_pseudocode(self, vu):
        return self._log()

    def close_pseudocode(self, vu):
        return self._log()

    def keyboard(self, vu, key_code, shift_state):
        return self._log()

    def right_click(self, vu):
        return self._log()

    def double_click(self, vu, shift_state):
        return self._log()

    def curpos(self, vu):
        return self._log()

    def create_hint(self, vu):
        return self._log()

    def text_ready(self, vu):
        return self._log()

    def populating_popup(self, widget, popup, vu):
        return self._log()

    def lvar_name_changed(self, vu, v, name, is_user_name):
        return self._log()

    def lvar_type_changed(self, vu, v, tif):
        return self._log()

    def lvar_cmt_changed(self, vu, v, cmt):
        return self._log()

    def lvar_mapping_changed(self, vu, _from, to):
        return self._log()

    def cmt_changed(self, cfunc, loc, cmt):
        return self._log()

    def build_callinfo(self, *args):
        return self._log()

vds_hooks = vds_hooks_t()
vds_hooks.hook()
