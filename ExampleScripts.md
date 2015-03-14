# Script Examples #

This little script enumerates all functions in the current segment (section) and lists all places that reference them.
The following are three different implementations of the same functionality. First using IDC, then idapython with low-level
IDA API calls and last using IDAPython's **idautils** helper module.


## IDC version ##
```
//
// Reference Lister
//
// List all functions and all references to them in the current section.
//
// Implemented in IDC
//
#include <idc.idc>

static main()
{
	auto ea, func, ref;

	// Get current ea
	ea = ScreenEA();

	// Loop from start to end in the current segment
	for (func=SegStart(ea); 
			func != BADADDR && func < SegEnd(ea); 
			func=NextFunction(func)) 
	{
		// If the current address is function process it
		if (GetFunctionFlags(func) != -1)
		{
			Message("Function %s at 0x%x\n", GetFunctionName(func), func);

			// Find all code references to func
			for (ref=RfirstB(func); ref != BADADDR; ref=RnextB(func, ref))
			{
				Message("  called from %s(0x%x)\n", GetFunctionName(ref), ref);
			}

		}
	}
}
```

## Python with low-level API calls ##

```
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

while func is not None and func.startEA < seg.endEA:
	funcea = func.startEA
	print "Function %s at 0x%x" % (GetFunctionName(funcea), funcea)

	ref = get_first_cref_to(funcea)

	while ref != BADADDR:
		print "  called from %s(0x%x)" % (get_func_name(ref), ref)
		ref = get_next_cref_to(funcea, ref)

	func = get_next_func(funcea)
```

## Python with the idautils module ##

```
#
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented with the idautils module
#
from idautils import *

# Get current ea
ea = ScreenEA()

# Loop from start to end in the current segment
for funcea in Functions(SegStart(ea), SegEnd(ea)):
	print "Function %s at 0x%x" % (GetFunctionName(funcea), funcea)

	# Find all code references to funcea
	for ref in CodeRefsTo(funcea, 1):
		print "  called from %s(0x%x)" % (GetFunctionName(ref), ref)
```