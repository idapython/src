
try:
  from argparse import ArgumentParser
except:
  print "Failed to import module 'argparse'. Upgrade to Python 2.7, copy argparse.py to this directory or try 'apt-get install python-argparse'"
  raise

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

    # area_visitor2_t
    "virtual int idaapi visit_area",

    # highlighter_cbs_t
    "virtual void idaapi set_style",
    "virtual int32 idaapi prev_block_state",
    "virtual int32 idaapi cur_block_state",
    "virtual void idaapi set_block_state",
]


outlines = []
with open(args.file, "rb") as f:
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
temp = tempfile.NamedTemporaryFile(delete=False)
temp.writelines(outlines)
temp.close()

import shutil
shutil.move(temp.name, args.file)
