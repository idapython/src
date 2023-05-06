"""
summary: a custom microcode instruction optimization rule

description:
  Installs a custom microcode instruction optimization rule,
  to transform:

      call   !DbgRaiseAssertionFailure <fast:>.0

  into

      call   !DbgRaiseAssertionFailure <fast:"char *" "assertion text">.0

  To see this plugin in action please use arm64_brk.i64
"""

import ida_bytes
import ida_range
import ida_kernwin
import ida_hexrays
import ida_typeinf
import ida_idaapi

class nt_assert_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk, ins, optflags):
        if self.handle_nt_assert(ins):
            return 1
        return 0

    def handle_nt_assert(self, ins):
        # recognize call   !DbgRaiseAssertionFailure <fast:>.0
        if not ins.is_helper("DbgRaiseAssertionFailure"):
            return False

        # did we already add an argument?
        fi = ins.d.f;
        if not fi.args.empty():
            return False

        # use a comment from the disassembly listing as the call argument
        cmt = ida_bytes.get_cmt(ins.ea, False)
        if not cmt:
            return False

        # remove "NT_ASSERT("...")" to make the listing nicer
        if cmt.startswith("NT_ASSERT(\""):
            cmt = cmt[11:]
            if cmt.endswith("\")"):
                cmt = cmt[:-2]

        # all ok, transform the instruction by adding one more call argument
        fa = fi.args.push_back()
        fa.t = ida_hexrays.mop_str;
        fa.cstr = cmt
        fa.type = ida_typeinf.tinfo_t.get_stock(ida_typeinf.STI_PCCHAR) # const char *
        fa.size = fa.type.get_size()
        return True

# --------------------------------------------------------------------------
# a plugin interface, boilerplate code
class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Optimize DbgRaiseAssertionFailure (IDAPython)"
    wanted_hotkey = ""
    comment = "Sample plugin10 for Hex-Rays decompiler"
    help = ""
    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            self.optimizer = nt_assert_optimizer_t()
            self.optimizer.install()
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

