# -*- coding: utf-8 -*-
"""
summary: dump function flowchart

description:
  Dumps the current function's flowchart, using 2 methods:

    * the low-level `ida_gdl.qflow_chart_t` type
    * the somewhat higher-level, and slightly more pythonic
      `ida_gdl.FlowChart` type.
"""

import ida_gdl
import ida_funcs
import ida_kernwin

def out(p, msg):
    if p:
        print(msg)

def out_succ(p, start_ea, end_ea):
    out(p, "  SUCC:  %x - %x" % (start_ea, end_ea))

def out_pred(p, start_ea, end_ea):
    out(p, "  PRED:  %x - %x" % (start_ea, end_ea))


# -----------------------------------------------------------------------
# Using ida_gdl.qflow_chart_t
def using_qflow_chart_t(ea, p=True):
    f = ida_funcs.get_func(ea)
    if not f:
        return

    q = ida_gdl.qflow_chart_t("The title", f, 0, 0, 0)
    for n in range(q.size()):
        b = q[n]
        out(p, "%x - %x [%d]:" % (b.start_ea, b.end_ea, n))
        for ns in range(q.nsucc(n)):
            b2 = q[q.succ(n, ns)]
            out_succ(p, b2.start_ea, b2.end_ea)

        for ns in range(q.npred(n)):
            b2 = q[q.pred(n, ns)]
            out_pred(p, b2.start_ea, b2.end_ea)

# -----------------------------------------------------------------------
# Using ida_gdl.FlowChart
def using_FlowChart(ea, p=True):
    f = ida_gdl.FlowChart(ida_funcs.get_func(ea))

    for block in f:
        out(p, "%x - %x [%d]:" % (block.start_ea, block.end_ea, block.id))
        for succ_block in block.succs():
            out_succ(p, succ_block.start_ea, succ_block.end_ea)

        for pred_block in block.preds():
            out_pred(p, pred_block.start_ea, pred_block.end_ea)

ea = ida_kernwin.get_screen_ea()

print(">>> Dumping flow chart using ida_gdl.qflow_chart_t")
using_qflow_chart_t(ea)

print(">>> Dumping flow chart using the higher-level ida_gdl.FlowChart")
using_FlowChart(ea)

