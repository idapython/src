"""
summary: a custom microcode instruction optimization rule (`x | ~x => -1`)

description:
  Installs a custom microcode instruction optimization rule,
  to transform:

      x | ~x

  into

      -1

  To see this plugin in action please use be_ornot_be.idb
"""

import ida_hexrays
import ida_idaapi

# recognize "x | ~x" and replace by -1
class subinsn_optimizer_t(ida_hexrays.minsn_visitor_t):
    cnt = 0
    def visit_minsn(self):      # for each instruction...
        ins = self.curins       # take a reference to the current instruction

        # THE CORE OF THE PLUGIN IS HERE:
        # check the pattern "x | ~x"
        if ins.opcode == ida_hexrays.m_or and ins.r.is_insn(ida_hexrays.m_bnot) and ins.l == ins.r.d.l:
            if not ins.l.has_side_effects(): # avoid destroying side effects
                # pattern matched, convert to "mov -1, ..."
                ins.opcode = ida_hexrays.m_mov
                ins.l.make_number(-1, ins.r.size)
                ins.r = ida_hexrays.mop_t()
                self.cnt = self.cnt + 1 # number of changes we made
        return 0 # continue traversal

# a custom instruction optimizer, boilerplate code
class sample_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk, ins, optflags):
        opt = subinsn_optimizer_t()
        ins.for_all_insns(opt)
        if opt.cnt != 0:                # if we modified microcode,
            blk.mba.verify(True)        # run the verifier
        return opt.cnt                  # report the number of changes

# a plugin interface, boilerplate code
class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "optimize x|~x"
    wanted_hotkey = ""
    comment = ""
    help = ""
    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            self.optimizer = sample_optimizer_t()
            self.optimizer.install()
            print("Installed sample optimizer for 'x | ~x'")
            return ida_idaapi.PLUGIN_KEEP # keep us in the memory
    def term(self):
        self.optimizer.remove()
    def run(self, arg):
        if arg == 1:
            return self.optimizer.remove()
        elif arg == 2:
            return self.optimizer.install()

def PLUGIN_ENTRY():
    return my_plugin_t()
