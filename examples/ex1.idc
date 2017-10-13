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
	ea = get_screen_ea();

	// Loop from start to end in the current segment
	for (func=get_segm_start(ea); 
			func != BADADDR && func < get_segm_end(ea); 
			func=get_next_func(func)) 
	{
		// If the current address is function process it
		if (get_func_flags(func) != -1)
		{
			msg("Function %s at 0x%x\n", get_func_name(func), func);

			// Find all code references to func
			for (ref=get_first_cref_to(func); ref != BADADDR; ref=get_next_cref_to(func, ref))
			{
				msg("  called from %s(0x%x)\n", get_func_name(ref), ref);
			}

		}
	}
}
