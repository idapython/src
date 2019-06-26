#
#      Hex-Rays Decompiler project
#      Copyright (c) 2007-2019 by Hex-Rays, support@hex-rays.com
#      ALL RIGHTS RESERVED.
#
#      Sample plugin for Hex-Rays Decompiler.
#      It shows list of direct references to a register from the current
#      instruction.
#
#      This is a rewrite in Python of the vds12 example that comes with hexrays sdk.
#

import ida_pro
import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_lines

def collect_block_xrefs(out, mlist, blk, ins, find_uses):
    p = ins
    while p and not mlist.empty():
        use = blk.build_use_list(p, ida_hexrays.MUST_ACCESS); # things used by the insn
        _def = blk.build_def_list(p, ida_hexrays.MUST_ACCESS); # things defined by the insn
        plst = use if find_uses else _def
        if mlist.has_common(plst):
            if not p.ea in out:
                out.append(p.ea) # this microinstruction seems to use our operand
        mlist.sub(_def)
        p = p.next if find_uses else p.prev


def collect_xrefs(out, ctx, mop, mlist, du, find_uses):
    # first collect the references in the current block
    start = ctx.topins.next if find_uses else ctx.topins.prev;
    collect_block_xrefs(out, mlist, ctx.blk, start, find_uses)

    # then find references in other blocks
    serial = ctx.blk.serial; # block number of the operand
    bc = du[serial]          # chains of that block
    voff = ida_hexrays.voff_t(mop)
    ch = bc.get_chain(voff)   # chain of the operand
    if not ch:
        return # odd
    for bn in ch:
        b = ctx.mba.get_mblock(bn)
        ins = b.head if find_uses else b.tail
        tmp = ida_hexrays.mlist_t()
        tmp.add(mlist)
        collect_block_xrefs(out, tmp, b, ins, find_uses)


class xref_chooser_t(ida_kernwin.Choose):
    def __init__(self, xrefs, t, n, ea, gco):
        ida_kernwin.Choose.__init__(
            self,
            t,
            [["Type", 3], ["Address", 16], ["Instruction", 60]])

        self.xrefs = xrefs
        self.ndefs = n
        self.curr_ea = ea
        self.gco = gco
        self.items = [ self._make_item(idx) for idx in xrange(len(xrefs)) ]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def _make_item(self, idx):
        ea = self.xrefs[idx]
        both_mask = ida_hexrays.GCO_USE|ida_hexrays.GCO_DEF
        both = (self.gco.flags & both_mask) == both_mask
        if ea == self.curr_ea and both:
            type_str = "use/def"
        elif idx < self.ndefs:
            type_str = "def"
        else:
            type_str = "use"
        insn = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
        return [type_str, "%08x" % ea, insn]


def show_xrefs(ea, gco, xrefs, ndefs):
    title = "xrefs to %s at %08x" % (gco.name, ea)
    xc = xref_chooser_t(xrefs, title, ndefs, ea, gco)
    i = xc.Show(True)
    if i >= 0:
        ida_kernwin.jumpto(xrefs[i])


if ida_hexrays.init_hexrays_plugin():
    ea = ida_kernwin.get_screen_ea()
    pfn = ida_funcs.get_func(ea)
    w = ida_kernwin.warning
    if pfn:
        F = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(F):
            gco = ida_hexrays.gco_info_t()
            if ida_hexrays.get_current_operand(gco):
                # generate microcode
                hf = ida_hexrays.hexrays_failure_t()
                mbr = ida_hexrays.mba_ranges_t(pfn)
                mba = ida_hexrays.gen_microcode(
                    mbr,
                    hf,
                    None,
                    ida_hexrays.DECOMP_WARNINGS,
                    ida_hexrays.MMAT_PREOPTIMIZED)
                if mba:
                    merr = mba.build_graph()
                    if merr == ida_hexrays.MERR_OK:
                        ncalls = mba.analyze_calls(ida_hexrays.ACFL_GUESS)
                        if ncalls < 0:
                            print("%08x: failed to determine some calling conventions", pfn.start_ea)
                        mlist = ida_hexrays.mlist_t()
                        if gco.append_to_list(mlist, mba):
                            ctx = ida_hexrays.op_parent_info_t()
                            mop = mba.find_mop(ctx, ea, gco.is_def(), mlist)
                            if mop:
                                xrefs = ida_pro.eavec_t()
                                ndefs = 0
                                graph = mba.get_graph()
                                ud = graph.get_ud(ida_hexrays.GC_REGS_AND_STKVARS)
                                du = graph.get_du(ida_hexrays.GC_REGS_AND_STKVARS)
                                if gco.is_use():
                                    collect_xrefs(xrefs, ctx, mop, mlist, ud, False)
                                    ndefs = xrefs.size()
                                    if ea not in xrefs:
                                        xrefs.append(ea)
                                if gco.is_def():
                                    if ea not in xrefs:
                                        xrefs.append(ea)
                                        ndefs = len(xrefs)
                                    collect_xrefs(xrefs, ctx, mop, mlist, du, True)
                                show_xrefs(ea, gco, xrefs, ndefs)
                            else:
                                w("Could not find the operand in the microcode, sorry")
                        else:
                            w("Failed to represent %s as microcode list" % gco.name)
                    else:
                        w("%08x: %s" % (errea, ida_hexrays.get_merror_desc(merr, mba)))
                else:
                    w("%08x: %s" % (hf.errea, hf.str))
            else:
                w("Could not find a register or stkvar in the current operand")
        else:
            w("Please position the cursor on an instruction")
    else:
        w("Please position the cursor within a function")
else:
    print('vds12: Hex-rays is not available.')

