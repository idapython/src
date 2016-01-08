
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
        # text_sink_t
        "virtual int idaapi print",

        # user_lvar_modifier_t
        "virtual bool idaapi modify_lvars",

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

        # enum_member_visitor_t
        "virtual int idaapi visit_enum_member",

        # struct_field_visitor_t
        "virtual int idaapi visit_field",

        # tinfo_visitor_t
        "virtual int idaapi visit_type",

        # aloc_visitor_t
        "virtual int idaapi visit_location",

        # const_aloc_visitor_t
        "virtual int idaapi visit_location",

        # area_visitor2_t
        "virtual int idaapi visit_area",

        # highlighter_cbs_t
        "virtual void idaapi set_style",
        "virtual int32 idaapi prev_block_state",
        "virtual int32 idaapi cur_block_state",
        "virtual void idaapi set_block_state",
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
