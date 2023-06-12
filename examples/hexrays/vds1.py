"""
summary: decompile & print current function.
"""

import ida_hexrays
import ida_lines
import ida_funcs
import ida_kernwin

def main():
    if not ida_hexrays.init_hexrays_plugin():
        return False

    print("Hex-rays version %s has been detected" % ida_hexrays.get_hexrays_version())

    f = ida_funcs.get_func(ida_kernwin.get_screen_ea());
    if f is None:
        print("Please position the cursor within a function")
        return True

    cfunc = ida_hexrays.decompile(f);
    if cfunc is None:
        print("Failed to decompile!")
        return True

    sv = cfunc.get_pseudocode();
    for sline in sv:
        print(ida_lines.tag_remove(sline.line));

    return True

main()
