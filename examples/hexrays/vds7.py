"""
summary: iterate a cblock_t object

description:
  Using a `ida_hexrays.ctree_visitor_t`, search for
  `ida_hexrays.cit_block` instances and dump them.

author: EiNSTeiN_ (einstein@g3nius.org)
"""

import ida_hexrays

class cblock_visitor_t(ida_hexrays.ctree_visitor_t):

    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

    def visit_insn(self, ins):
        if ins.op == ida_hexrays.cit_block:
            self.dump_block(ins.ea, ins.cblock)
        return 0

    def dump_block(self, ea, b):
        # iterate over all block instructions
        print("dumping block %x" % (ea, ))
        for ins in b:
            print("  %x: insn %s" % (ins.ea, ins.opname))


class vds7_hooks_t(ida_hexrays.Hexrays_Hooks):
    def maturity(self, cfunc, maturity):
        if maturity == ida_hexrays.CMAT_BUILT:
            cbv = cblock_visitor_t()
            cbv.apply_to(cfunc.body, None)
        return 0


if ida_hexrays.init_hexrays_plugin():
    vds7_hooks = vds7_hooks_t()
    vds7_hooks.hook()
else:
    print('cblock visitor: hexrays is not available.')
