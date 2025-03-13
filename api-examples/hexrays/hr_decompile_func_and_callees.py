"""
summary: Python plugin that decompiles a function and its callees.

description:
    This script does the same as decompile_func_and_callee but instead
    of using the cross-references, uses a ctree visitor to build the
    list of callees.
"""
import ida_hexrays
import ida_lines
import ida_funcs
import ida_kernwin


def find_calls(cfunc):
    class finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)

            self.results = []
            return

        def visit_insn(self, inst):
            if inst.op == ida_hexrays.cit_expr and inst.cexpr.op == ida_hexrays.cot_call:
                self.results.append(inst.cexpr.x.obj_ea)
            return 0

    finder = finder_t()
    finder.apply_to(cfunc.body, None)
    return finder.results


def print_pseudo_code(cfunc):
    sv = cfunc.get_pseudocode();
    for sline in sv:
        print(ida_lines.tag_remove(sline.line))


def main():
    if not ida_hexrays.init_hexrays_plugin():
        return False

    print("Hex-rays version %s has been detected" % ida_hexrays.get_hexrays_version())

    f = ida_funcs.get_func(ida_kernwin.get_screen_ea())
    if f is None:
        print("Please position the cursor within a function")
        return True

    cfunc = ida_hexrays.decompile(f);
    if cfunc is None:
        print("Failed to decompile!")
        return True
    
    print_pseudo_code(cfunc)
    
    lst = find_calls(cfunc)
    lst = list(set(lst))
    already = []
    for ea in lst:
        f = ida_funcs.get_func(ea)
        if f is None:
            continue
        
        cfunc = ida_hexrays.decompile(f);
        if cfunc is None:
            print("Failed to decompile!")
            return True
        print_pseudo_code(cfunc)

    return True

if __name__ == '__main__':
    main()