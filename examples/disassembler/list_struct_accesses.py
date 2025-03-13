"""
summary: list operands representing a "path" to a (possibly nested) structure member

description:
  It is possible to assign, to instruction operands, the notion of "structure
  offset", which really is a pointer to a specific offset in a type, leading
  to a possible N-deep path within types.

  E.g., assuming the following types

          struct c
          {
              int foo;
              int bar;
              int baz;
              int quux;
              int trail;
          };

          struct b
          {
              int gap;
              c c_instance;
          };

          struct a
          {
              int count;
              b b_instance;
          };

  and assuming an instruction that initially looks like this:

          mov eax, 10h

  by pressing `t`, the user will be able set the "structure offset"
  to either:

    * `c.trail`
    * `b.c_instance.quux`
    * `a.b_inscance.c_instance.baz`

  Here's why IDA offers `a.b_inscance.c_instance.baz`:

          0000   struct a
                 {
          0000       int count;
          0004       struct b
                     {
          0004           int gap;
          0008           struct c
                         {
          0008               int foo;
          000C               int bar;
          0010               int baz;
          0014               int quux;
          0018               int trail;
                         };
                     };
                 };

  This sample shows how to programmatically retrieve information about
  that "structure member path" that an operand was made pointing to.

keywords: bookmarks

level: advanced
"""
from typing import List

import ida_bytes
import ida_pro
import ida_ua
import ida_typeinf
import ida_nalt
import ida_netnode


def get_struct_paths(ea: int, opnum: int) -> List[str]:
    flags = ida_bytes.get_full_flags(ea)

    if not ida_bytes.is_stroff(flags, opnum):
        # requested operand not a structure
        return []

    insn = ida_ua.insn_t()
    ins_sz = ida_ua.decode_insn(insn, ea)
    if ins_sz == 0:
        # could not disassemble
        return []

    num_ops = 0
    # ;! nice idea to inject via Swig a '__len__' method to the instruction
    # object that does that.
    while insn.ops[num_ops].type != ida_ua.o_void:
        num_ops += 1

    op = insn.ops[opnum]

    if op.type == ida_ua.o_imm:
        value = op.value
    else:
        value = op.addr

    path, delta = ida_bytes.get_stroff_path(insn.ea, opnum)
    out = []
    for tid in path:
        tif = ida_typeinf.tinfo_t(tid=tid)
        sz = tif.get_size()

        if delta + value == sz:
            out.append(f"size {tif.get_type_name()}")
        else:
            for idx, mem in enumerate(tif.iter_udt()):
                off = mem.offset // 8  # udm.offset is in bits
                size = mem.size // 8  # udm.size is in bits
                if off - delta <= value < off - delta + size:
                    name = ida_typeinf.get_tid_name(tif.get_udm_tid(idx))
                    diff = value - (off - delta)
                    if diff > 0:
                        out.append(f"{name}+{diff}")
                    else:
                        out.append(f"{name}")

    return out
