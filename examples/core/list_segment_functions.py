"""
summary: list all functions (and xrefs) in segment

description:
  List all the functions in the current segment, as well as
  all the cross-references to them.

keywords: xrefs

see_also: list_segment_functions_using_idautils
"""

#
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented using direct IDA Plugin API calls
#

import ida_kernwin
import ida_segment
import ida_funcs
import ida_xref
import ida_idaapi

def main():
    # Get current ea
    ea = ida_kernwin.get_screen_ea()

    # Get segment class
    seg = ida_segment.getseg(ea)

    # Loop from segment start to end
    func_ea = seg.start_ea

    # Get a function at the start of the segment (if any)
    func = ida_funcs.get_func(func_ea)
    if func is None:
        # No function there, try to get the next one
        func = ida_funcs.get_next_func(func_ea)

    seg_end = seg.end_ea
    while func is not None and func.start_ea < seg_end:
        funcea = func.start_ea
        print("Function %s at 0x%x" % (ida_funcs.get_func_name(funcea), funcea))

        xb = ida_xref.xrefblk_t()
        for ref in xb.crefs_to(funcea):
            print("  called from %s(0x%x)" % (ida_funcs.get_func_name(ref), ref))

        func = ida_funcs.get_next_func(funcea)


main()
