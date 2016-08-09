%{
#include <frame.hpp>
%}

%import "area.i"

%ignore add_frame_spec_member;
%ignore del_stkvars;
%ignore calc_frame_offset;
%ignore set_llabel;
%ignore get_llabel_ea;
%ignore get_llabel;

%ignore get_stkvar;
%rename (get_stkvar) py_get_stkvar;

%ignore add_stkvar3;
%rename (add_stkvar3) py_add_stkvar3;

%ignore calc_frame_offset;
%ignore add_stkvar;

%template(xreflist_t) qvector<xreflist_entry_t>;

%inline %{
//<inline(py_frame)>
//</inline(py_frame)>
%}

%include "frame.hpp"
