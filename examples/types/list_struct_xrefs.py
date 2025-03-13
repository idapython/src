"""
summary: list cross-references to a structure

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
    * Ask the user for a structure name. It must already be present in the
    local types.
    * Get its tid
    * Create the list of all the reference.
    * Print it

level: beginner
"""

import ida_kernwin
import ida_typeinf
import ida_xref
import ida_pro

tif = ida_typeinf.tinfo_t()
ref_eas = []
if ida_kernwin.choose_struct(tif, "Choose one structure:"):
    tid = tif.get_tid()
    xrefblk = ida_xref.xrefblk_t()
    for ea in xrefblk.drefs_to(tid):
        ref_eas.append(ea)

    if not len(ref_eas):
        print("No reference found.")
    else:
        for idx, ea in enumerate(ref_eas):
            print(f"Refnum {idx + 1}: {ea:x}")
