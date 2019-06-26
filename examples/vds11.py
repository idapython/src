#
#      Hex-Rays Decompiler project
#      Copyright (c) 2007-2019 by Hex-Rays, support@hex-rays.com
#      ALL RIGHTS RESERVED.
#
#      Sample plugin for Hex-Rays Decompiler.
#      It installs a custom block optimization rule:
#
#        goto L1     =>        goto L2
#        ...
#      L1:
#        goto L2
#
#      In other words we fix a goto target if it points to a chain of gotos.
#      This improves the decompiler output in some cases.
#
#      This is a rewrite in Python of the vds11 example that comes with hexrays sdk.
#

import ida_bytes
import ida_range
import ida_kernwin
import ida_hexrays
import ida_typeinf

class goto_optimizer_t(ida_hexrays.optblock_t):
    def func(self, blk):
        if self.handle_goto_chain(blk):
            return 1
        return 0

    def handle_goto_chain(self, blk):
        mgoto = blk.tail
        if not mgoto or mgoto.opcode != ida_hexrays.m_goto:
            return False

        visited = []
        t0 = mgoto.l.b
        i = t0
        mba = blk.mba

        # follow the goto chain
        while True:
            if i in visited:
                return False
            visited.append(i)
            b = mba.get_mblock(i)
            m2 = ida_hexrays.getf_reginsn(b.head)
            if not m2 or m2.opcode != ida_hexrays.m_goto:
                break
            i = m2.l.b

        if i == t0:
            return False # not a chain

        # all ok, found a goto chain
        mgoto.l.b = i # jump directly to the end of the chain

        # fix the successor/predecessor lists
        blk.succset[0] = i
        mba.get_mblock(i).predset.add(blk.serial)
        mba.get_mblock(t0).predset._del(blk.serial)

        # since we changed the control flow graph, invalidate the use/def chains.
        # stricly speaking it is not really necessary in our plugin because
        # we did not move around any microcode operands.
        mba.mark_chains_dirty()

        # it is a good idea to verify microcode after each change
        # however, it may be time consuming, so comment it out eventually
        mba.verify(True);
        return True


if ida_hexrays.init_hexrays_plugin():
    optimizer = goto_optimizer_t()
    optimizer.install()
else:
    print('vds11: Hex-rays is not available.')
