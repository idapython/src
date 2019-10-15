""" It demonstrates how to iterate a cblock_t object.

Author: EiNSTeiN_ <einstein@g3nius.org>

This is a rewrite in Python of the vds7 example that comes with hexrays sdk.
"""
from __future__ import print_function

import idautils
import idaapi
import idc

import traceback

class cblock_visitor_t(idaapi.ctree_visitor_t):

    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        return

    def visit_insn(self, ins):

        try:
            if ins.op == idaapi.cit_block:
                self.dump_block(ins.ea, ins.cblock)
        except:
            traceback.print_exc()

        return 0

    def dump_block(self, ea, b):
        # iterate over all block instructions
        print("dumping block %x" % (ea, ))
        for ins in b:
            print("  %x: insn %s" % (ins.ea, ins.opname))

        return


class vds7_hooks_t(idaapi.Hexrays_Hooks):
    def maturity(self, cfunc, maturity):
        if maturity == idaapi.CMAT_BUILT:
            cbv = cblock_visitor_t()
            cbv.apply_to(cfunc.body, None)
        return 0


if idaapi.init_hexrays_plugin():
    vds7_hooks = vds7_hooks_t()
    vds7_hooks.hook()
else:
    print('cblock visitor: hexrays is not available.')
