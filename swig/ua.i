%{
#include <ua.hpp>
#include <frame.hpp>
%}

%ignore insn_t;
%ignore op_t;
%ignore cmd;
%ignore showAsChar;
%ignore out_real;
%ignore init_output_buffer;
%ignore term_output_buffer;
%ignore OutValue;
%ignore OutImmChar;
%ignore out_name_expr;
%ignore ua_stkvar2;
%ignore ua_add_off_drefs;
%ignore ua_add_off_drefs2;
%ignore out_snprintf;
%ignore set_output_ptr;
%ignore get_output_ptr;
%ignore out_insert;
%ignore get_immval;
%ignore get_spoiled_reg;
%ignore decode_preceding_insn;
%ignore term_uaterm_ua;
%ignore get_operand_immvals;

%ignore get_immval;
%ignore ua_stkvar;

%ignore construct_macro;
%rename (construct_macro) py_construct_macro;
%ignore get_dtyp_by_size;
%rename (get_dtyp_by_size) py_get_dtyp_by_size;

%include "ua.hpp"

%rename (init_output_buffer) py_init_output_buffer;
%rename (term_output_buffer) py_term_output_buffer;
%rename (OutValue) py_OutValue;
%rename (OutImmChar) py_OutImmChar;
%rename (out_name_expr) py_out_name_expr;
%rename (ua_stkvar2) py_ua_stkvar2;
%rename (ua_add_off_drefs) py_ua_add_off_drefs;
%rename (ua_add_off_drefs2) py_ua_add_off_drefs2;
%rename (decode_preceding_insn) py_decode_preceding_insn;
%rename (get_operand_immvals) py_get_operand_immvals;

%{
//<code(py_ua)>
//</code(py_ua)>
%}

%inline %{
//<inline(py_ua)>
//</inline(py_ua)>
%}

%pythoncode %{
#<pycode(py_ua)>
#</pycode(py_ua)>
%}
