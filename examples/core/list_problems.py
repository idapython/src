"""
summary: enumerate problems

description:
  Using the API to list all problem[atic situation]s that IDA
  encountered during analysis.
"""

import ida_ida
import ida_idaapi
import ida_problems

for ptype in [
        ida_problems.PR_NOBASE,
        ida_problems.PR_NONAME,
        ida_problems.PR_NOFOP,
        ida_problems.PR_NOCMT,
        ida_problems.PR_NOXREFS,
        ida_problems.PR_JUMP,
        ida_problems.PR_DISASM,
        ida_problems.PR_HEAD,
        ida_problems.PR_ILLADDR,
        ida_problems.PR_MANYLINES,
        ida_problems.PR_BADSTACK,
        ida_problems.PR_ATTN,
        ida_problems.PR_FINAL,
        ida_problems.PR_ROLLED,
        ida_problems.PR_COLLISION,
        ida_problems.PR_DECIMP,
]:
    plistdesc = ida_problems.get_problem_name(ptype)
    ea = ida_ida.inf_get_min_ea()
    while True:
        ea = ida_problems.get_problem(ptype, ea+1)
        if ea == ida_idaapi.BADADDR:
            break
        print("0x%08x: %s" % (ea, plistdesc))
