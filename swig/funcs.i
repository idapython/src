
%import "area.i"

%cstring_bounded_output_none(char *buf, MAXSTR);
%cstring_bounded_output_none(char *optlibs, MAXSTR);

// FIXME: Are these really useful?
%ignore iterate_func_chunks;
%ignore get_idasgn_header_by_short_name;

// Kernel-only & unexported symbols
%ignore determine_rtl;
%ignore save_signatures;
%ignore invalidate_sp_analysis;

%ignore get_idasgn_desc;
%rename (get_idasgn_desc) py_get_idasgn_desc;
%rename (get_idasgn_desc_with_matches) py_get_idasgn_desc_with_matches;

%ignore get_func_cmt;
%rename (get_func_cmt) py_get_func_cmt;

%include "funcs.hpp"

%clear(char *buf);
%clear(char *optlibs);

%inline %{
//<inline(py_funcs)>
//</inline(py_funcs)>
%}
