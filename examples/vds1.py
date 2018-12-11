from __future__ import print_function
import idaapi

def main():
    if not idaapi.init_hexrays_plugin():
        return False

    print("Hex-rays version %s has been detected" % idaapi.get_hexrays_version())

    f = idaapi.get_func(idaapi.get_screen_ea());
    if f is None:
        print("Please position the cursor within a function")
        return True

    cfunc = idaapi.decompile(f);
    if cfunc is None:
        print("Failed to decompile!")
        return True

    sv = cfunc.get_pseudocode();
    for sline in sv:
        print(idaapi.tag_remove(sline.line));

    return True

main()
