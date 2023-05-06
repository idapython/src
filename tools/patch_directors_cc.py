from __future__ import print_function

from argparse import ArgumentParser

parser = ArgumentParser(description='Patch calling conventions for some functions, so it builds on windows')
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
args = parser.parse_args()

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

    # range_visitor_t
    "virtual int idaapi visit_range",

    # highlighter_cbs_t
    "virtual void idaapi set_style",
    "virtual int32 idaapi prev_block_state",
    "virtual int32 idaapi cur_block_state",
    "virtual void idaapi set_block_state",

    # predicate_t
    "virtual bool idaapi should_display",

    # graph_visitor_t
    "virtual int idaapi visit_node",
    "virtual int idaapi visit_edge",

    # graph_node_visitor_t
    "virtual int idaapi visit_node",
    "virtual bool idaapi is_forbidden_edge",

    # graph_path_visitor_t
    "virtual int idaapi walk_forward",
    "virtual int idaapi walk_backward",

    # mutable_graph_t
    "virtual rect_t &idaapi nrect",
    "virtual edge_info_t *idaapi get_edge",
    "virtual abstract_graph_t *idaapi clone",
    "virtual bool idaapi set_nrect",
    "virtual bool idaapi set_edge",
    "virtual int idaapi add_node",
    "virtual ssize_t idaapi del_node",
    "virtual bool idaapi add_edge",
    "virtual bool idaapi del_edge",
    "virtual bool idaapi replace_edge",
    "virtual bool idaapi refresh",
    "virtual mutable_graph_t *idaapi clone",
    "virtual bool idaapi redo_layout",
    "virtual void idaapi resize",
    "virtual ea_t idaapi calc_group_ea",
    "virtual bool idaapi is_user_graph",

    # codegen_t
    "virtual mreg_t idaapi load_operand",
    "virtual merror_t idaapi analyze_prolog",
    "virtual merror_t idaapi gen_micro",
    "virtual minsn_t *idaapi emit_micro_mvm",
]


outlines = []
with open(args.file) as f:
    lines = f.readlines()
    for line in lines:
        for patch in patches:
            from_text = patch.replace("idaapi ", "")
            if line.find(from_text) > -1:
                line = line.replace(from_text, patch)
                patches.remove(patch)
                break
        outlines.append(line)

import tempfile
temp = tempfile.NamedTemporaryFile(mode="w", delete=False)
temp.write("".join(outlines))
temp.close()

import shutil
shutil.move(temp.name, args.file)
