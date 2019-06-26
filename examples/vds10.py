#
#      Hex-Rays Decompiler project
#      Copyright (c) 2007-2019 by Hex-Rays, support@hex-rays.com
#      ALL RIGHTS RESERVED.
#
#      Sample plugin for Hex-Rays Decompiler.
#      It installs a custom microcode optimization rule:
#        call   !DbgRaiseAssertionFailure <fast:>.0
#      =>
#        call   !DbgRaiseAssertionFailure <fast:"char *" "assertion text">.0
#
#      To see this plugin in action please use arm64_brk.i64, in the hexrays sdk
#
#      This is a rewrite in Python of the vds10 example that comes with hexrays sdk.
#

import ida_bytes
import ida_range
import ida_kernwin
import ida_hexrays
import ida_typeinf

class nt_assert_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk, ins):
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


if ida_hexrays.init_hexrays_plugin():
    optimizer = nt_assert_optimizer_t()
    optimizer.install()
else:
    print('vds10: Hex-rays is not available.')

