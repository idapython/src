# this script implements disassembly of BUG_INSTR used in Linux kernel BUG() macro 
# normally it's architecturally undefined and is not disassembled by IDA's ARM module
# see Linux/arch/arm/include/asm/bug.h

import idaapi

ITYPE_BUGINSN = idaapi.CUSTOM_CMD_ITYPE + 10
MNEM_WIDTH = 16

class MyHooks(idaapi.IDP_Hooks):

    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)
        self.reported = []

    def ev_ana_insn(self, insn):
        t = get_sreg(insn.ea, "T")
        if t==0 and get_wide_dword(insn.ea) == 0xE7F001F2:
            insn.itype = ITYPE_BUGINSN
            insn.size = 4
        elif t!=0 and get_wide_word(insn.ea) == 0xde02:
            insn.itype = ITYPE_BUGINSN
            insn.size = 2
        return insn.size

    def ev_emu_insn(self, insn):
        if insn.ea == ITYPE_BUGINSN:
            return 1
        return 0

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype == ITYPE_BUGINSN:
            outctx.out_custom_mnem("BUG_INSTR", MNEM_WIDTH)
            return 1
        return 0

if idaapi.ph.id == idaapi.PLFM_ARM:
    bahooks = MyHooks()
    bahooks.hook()
    print "BUG_INSTR processor extension installed"
else:
    warning("This script only supports ARM files")

