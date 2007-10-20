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
