
import os, shutil, sys, optparse

if __name__ == "__main__":

    p = optparse.OptionParser(description='Patch calling conventions for some functions, so it builds on windows')
    p.add_option('-v', "--verbose", dest="verbose", action="store_true")
    p.add_option('-f', "--file", dest="path", type="string", help="File name, without extension.")
    opts, _ = p.parse_args(sys.argv[1:])

    if not opts.path:
        p.print_help()
        sys.exit(1)

    patches = [
        # user_lvar_visitor_t
        "virtual int idaapi handle_retrieved_info",
        "virtual int idaapi handle_retrieved_mapping",
        "virtual int idaapi get_info_qty_for_saving",
        "virtual bool idaapi get_info_for_saving",
        "virtual lvar_mapping_t const *idaapi get_info_mapping_for_saving",

        # ctree_visitor_t
        "virtual int idaapi visit_insn",
        "virtual int idaapi visit_expr",
        "virtual int idaapi leave_insn",
        "virtual int idaapi leave_expr",

        # ctree_parentee_t
        "virtual int idaapi visit_insn",
        "virtual int idaapi visit_expr",
        "virtual int idaapi leave_insn",
        "virtual int idaapi leave_expr",

        # cfunc_parentee_t
        "virtual int idaapi visit_insn",
        "virtual int idaapi visit_expr",
        "virtual int idaapi leave_insn",
        "virtual int idaapi leave_expr",
        ]

    path = opts.path
    outlines = []
    outpath = "%s.cc" % path
    with open(path, "r") as f:
        lines = f.readlines()
        for line in lines:
            for patch in patches:
                from_text = patch.replace("idaapi ", "")
                if line.find(from_text) > -1:
                    line = line.replace(from_text, patch)
                    patches.remove(patch)
                    break
            outlines.append(line)
    with open(outpath, "w") as f:
        f.writelines(outlines)
    shutil.move(outpath, path)
