%ignore rangeset_t::count;
%ignore rangeset_t::lower_bound;
%ignore rangeset_t::upper_bound;
%ignore rangeset_t::move_chunk;
%ignore rangeset_t::check_move_args;

%template(rangevec_base_t) qvector<range_t>;

%inline %{
//<inline(py_range)>
//</inline(py_range)>
%}

%include "range.hpp"
