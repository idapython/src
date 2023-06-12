"""
summary: override some parts of the processor module

description:
  Implements disassembly of BUG_INSTR used in Linux kernel
  BUG() macro, which is architecturally undefined and is not
  disassembled by IDA's ARM module

  See Linux/arch/arm/include/asm/bug.h for more info
"""

import ida_idp
import ida_bytes
import ida_segregs

ITYPE_BUGINSN = ida_idp.CUSTOM_INSN_ITYPE + 10
MNEM_WIDTH = 16

class MyHooks(ida_idp.IDP_Hooks):

    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)
        self.reported = []

    def ev_ana_insn(self, insn):
        t_reg = ida_idp.str2reg("T")
        t = ida_segregs.get_sreg(insn.ea, t_reg)
        if t==0 and ida_bytes.get_wide_dword(insn.ea) == 0xE7F001F2:
            insn.itype = ITYPE_BUGINSN
            insn.size = 4
        elif t!=0 and ida_bytes.get_wide_word(insn.ea) == 0xde02:
            insn.itype = ITYPE_BUGINSN
            insn.size = 2
        return insn.size

    def ev_emu_insn(self, insn):
        if insn.itype == ITYPE_BUGINSN:
            return 1 # do not add any xrefs (stop code flow)
        # use default processing for all other functions
        return 0

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype == ITYPE_BUGINSN:
            outctx.out_custom_mnem("BUG_INSTR", MNEM_WIDTH)
            return 1
        return 0

if ida_idp.ph.id == ida_idp.PLFM_ARM:
    bahooks = MyHooks()
    bahooks.hook()
    print("BUG_INSTR processor extension installed")
else:
    warning("This script only supports ARM files")
