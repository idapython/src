"""
summary: list all functions (and xrefs) in segment

description:
  List all the functions in the current segment, as well as
  all the cross-references to them.

  Contrary to @list_segment_functions, this uses the somewhat
  higher-level `idautils` module.

keywords: xrefs

see_also: list_segment_functions
"""

#
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented with the idautils module
#

import ida_kernwin
import ida_idaapi
import ida_segment
import ida_funcs

import idautils

def main():
    # Get current ea
    ea = ida_kernwin.get_screen_ea()
    if ea == ida_idaapi.BADADDR:
        print("Could not get get_screen_ea()")
        return

    seg = ida_segment.getseg(ea)
    if seg:
        # Loop from start to end in the current segment
        for funcea in idautils.Functions(seg.start_ea, seg.end_ea):
            print("Function %s at 0x%x" % (ida_funcs.get_func_name(funcea), funcea))

            # Find all code references to funcea
            for ref in idautils.CodeRefsTo(funcea, 1):
                print("  called from %s(0x%x)" % (ida_funcs.get_func_name(ref), ref))
    else:
        print("Please position the cursor within a segment")

if __name__=='__main__':
    main()
