%{
#include <frame.hpp>
%}

%ignore add_frame_spec_member;
%ignore del_stkvars;
%ignore calc_frame_offset;
%ignore set_llabel;
%ignore get_llabel_ea;
%ignore get_llabel;

%ignore get_stkvar;
%rename (get_stkvar) py_get_stkvar;

%ignore calc_frame_offset;
%ignore add_stkvar;

%ignore delete_wrong_frame_info;
%ignore get_frame(ea_t);

%template(xreflist_t) qvector<xreflist_entry_t>;

%inline %{
//<inline(py_frame)>
//</inline(py_frame)>
%}

%include "frame.hpp"
