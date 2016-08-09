// Ignore kernel-only functions and variables
%ignore create_xrefs_from;
%ignore delete_all_xrefs_from;
%ignore destroy_if_align;
%ignore lastXR;
%ignore create_switch_xrefs;
%rename (create_switch_xrefs) py_create_switch_xrefs;
%ignore create_switch_table;
%rename (create_switch_table) py_create_switch_table;
%ignore calc_switch_cases;
%rename (calc_switch_cases)   py_calc_switch_cases;

// These functions should not be called directly (according to docs)
%ignore xrefblk_t_first_from;
%ignore xrefblk_t_next_from;
%ignore xrefblk_t_first_to;
%ignore xrefblk_t_next_to;

// 'from' is a reserved Python keyword
%rename (frm) from;

%inline %{
//<inline(py_xref)>
//</inline(py_xref)>
%}

%include "xref.hpp"

%template(casevec_t) qvector<qvector<sval_t> >; // signed values

%pythoncode %{
#<pycode(py_xref)>
#</pycode(py_xref)>
%}
