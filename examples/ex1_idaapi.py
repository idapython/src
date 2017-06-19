#
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented using direct IDA Plugin API calls
#
from idaapi import *

def main():
    # Get current ea
    ea = get_screen_ea()

    # Get segment class
    seg = getseg(ea)

    # Loop from segment start to end
    func_ea = seg.startEA

    # Get a function at the start of the segment (if any)
    func = get_func(func_ea)
    if func is None:
        # No function there, try to get the next one
        func = get_next_func(func_ea)

    seg_end = seg.endEA
    while func is not None and func.startEA < seg_end:
        funcea = func.startEA
        print "Function %s at 0x%x" % (GetFunctionName(funcea), funcea)

        ref = get_first_cref_to(funcea)

        while ref != BADADDR:
            print "  called from %s(0x%x)" % (get_func_name(ref), ref)
            ref = get_next_cref_to(funcea, ref)

        func = get_next_func(funcea)


main()