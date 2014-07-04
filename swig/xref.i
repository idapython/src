// Ignore kernel-only functions and variables
%ignore create_xrefs_from;
%ignore create_xrefs_from_data;
%ignore delete_all_xrefs_from;
%ignore delete_data_xrefs_from;
%ignore delete_code_xrefs_from;
%ignore destroy_if_align;
%ignore lastXR;
%ignore has_jump_or_flow_xref;
%ignore has_call_xref;
%ignore destroy_switch_info;
%ignore create_switch_xrefs;
%ignore create_switch_table;
%rename (calc_switch_cases)   py_calc_switch_cases;

// These functions should not be called directly (according to docs)
%ignore xrefblk_t_first_from;
%ignore xrefblk_t_next_from;
%ignore xrefblk_t_first_to;
%ignore xrefblk_t_next_to;

// 'from' is a reserved Python keyword
%rename (frm) from;

%include "xref.hpp"
