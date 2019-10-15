"""
Various hooks for Hexrays Decompiler
"""
from __future__ import print_function

import ida_idaapi
import ida_typeinf
import ida_hexrays

class vds_hooks_t(ida_hexrays.Hexrays_Hooks):
    def _shorten(self, cfunc):
        raw = str(cfunc)
        if len(raw) > 20:
            raw = raw[0:20] + "[...snipped...]"
        return raw

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

    def _log(self, msg):
        print("### %s" % msg)
        return 0

    def flowchart(self, fc):
        return self._log("flowchart: fc=%s" % fc)

    def stkpnts(self, mba, stkpnts):
        return self._log("stkpnts: mba=%s, stkpnts=%s" % (mba, stkpnts))

    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        return self._log("prolog: mba=%s, fc=%s, reachable_blocks=%s, decomp_flags=%x" % (mba, fc, reachable_blocks, decomp_flags))

    def microcode(self, mba):
        return self._log("microcode: mba=%s" % (mba,))

    def preoptimized(self, mba):
        return self._log("preoptimized: mba=%s" % (mba,))

    def locopt(self, mba):
        return self._log("locopt: mba=%s" % (mba,))

    def prealloc(self, mba):
        return self._log("prealloc: mba=%s" % (mba,))

    def glbopt(self, mba):
        return self._log("glbopt: mba=%s" % (mba,))

    def structural(self, ctrl_graph):
        return self._log("structural: ctrl_graph: %s" % (ctrl_graph,))

    def maturity(self, cfunc, maturity):
        return self._log("maturity: cfunc=%s, maturity=%s" % (self._shorten(cfunc), maturity))

    def interr(self, code):
        return self._log("interr: code=%s" % (code,))

    def combine(self, blk, insn):
        return self._log("combine: blk=%s, insn=%s" % (blk, insn))

    def print_func(self, cfunc, printer):
        # Note: we can't print/str()-ify 'cfunc' here,
        # because that'll call print_func() us recursively.
        return self._log("print_func: cfunc=..., printer=%s" % (printer,))

    def func_printed(self, cfunc):
        return self._log("func_printed: cfunc=%s" % (cfunc,))

    def resolve_stkaddrs(self, mba):
        return self._log("resolve_stkaddrs: mba=%s" % (mba,))

    def open_pseudocode(self, vu):
        return self._log("open_pseudocode: vu=%s" % (vu,))

    def switch_pseudocode(self, vu):
        return self._log("switch_pseudocode: vu=%s" % (vu,))

    def refresh_pseudocode(self, vu):
        return self._log("refresh_pseudocode: vu=%s" % (vu,))

    def close_pseudocode(self, vu):
        return self._log("close_pseudocode: vu=%s" % (vu,))

    def keyboard(self, vu, key_code, shift_state):
        return self._log("keyboard: vu=%s, key_code=%s, shift_state=%s" % (vu, key_code, shift_state))

    def right_click(self, vu):
        return self._log("right_click: vu=%s" % (vu,))

    def double_click(self, vu, shift_state):
        return self._log("double_click: vu=%s, shift_state=%s" % (vu, shift_state))

    def curpos(self, vu):
        return self._log("curpos: vu=%s (vu.cpos.lnnum=%d, vu.cpos.x=%d, vu.cpos.y=%d)" % (
            vu, vu.cpos.lnnum, vu.cpos.x, vu.cpos.y))

    def create_hint(self, vu):
        return self._log("create_hint: vu=%s: " % (vu,))

    def text_ready(self, vu):
        return self._log("text_ready: vu=%s" % (vu,))

    def populating_popup(self, widget, popup, vu):
        return self._log("populating_popup: widget=%s, popup=%s, vu=%s" % (widget, popup, vu))

    def lvar_name_changed(self, vu, v, name, is_user_name):
        return self._log("lvar_name_changed: vu=%s, v=%s, name=%s, is_user_name=%s" % (vu, self._format_lvar(v), name, is_user_name))

    def lvar_type_changed(self, vu, v, tif):
        return self._log("lvar_type_changed: vu=%s, v=%s, tinfo=%s" % (vu, self._format_lvar(v), tif._print()))

    def lvar_cmt_changed(self, vu, v, cmt):
        return self._log("lvar_cmt_changed: vu=%s, v=%s, cmt=%s" % (vu, self._format_lvar(v), cmt))

    def lvar_mapping_changed(self, vu, _from, to):
        return self._log("lvar_mapping_changed: vu=%s, from=%s, to=%s" % (vu, _from, to))

    def cmt_changed(self, cfunc, loc, cmt):
        return self._log("cmt_changed: cfunc=%s, loc=%s, cmt=%s" % (self._shorten(cfunc),loc, cmt))

vds_hooks = vds_hooks_t()
vds_hooks.hook()

