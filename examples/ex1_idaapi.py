#
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented using direct IDA Plugin API calls
#
from idaapi import *

# Get current ea
ea = get_screen_ea()

# Get segment class
seg = getseg(ea)

# Loop from segment start to end
func = get_func(seg.startEA)

while func != None and func.startEA < seg.endEA:
	funcea = func.startEA
	print "Function %s at 0x%x" % (GetFunctionName(funcea), funcea)

	ref = get_first_cref_to(funcea)

	while ref != BADADDR:
		print "  called from %s(0x%x)" % (get_func_name(ref), ref)
		ref = get_next_cref_to(funcea, ref)

	func = get_next_func(funcea)
