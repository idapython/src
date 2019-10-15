%{
#include <moves.hpp>
%}
// Ignore kernel only symbols
%ignore move_marks;
%ignore curloc_after_segments_moved;
%ignore curloc::rebase_stack;
%ignore DEFINE_CURLOC_HELPERS;
%ignore DEFINE_LOCATION_HELPERS;
%ignore lochist_t::rebase_stack;
%ignore location_t::location_t(bool);
%ignore lochist_t::is_hexrays68_compat;
%ignore lochist_entry_t::set_place(const place_t &);
%ignore lochist_entry_t::serialize;
%ignore lochist_entry_t::deserialize;
%ignore graph_location_info_t::serialize(bytevec_t *) const;
%ignore graph_location_info_t::deserialize(memory_deserializer_t &);
%ignore renderer_info_pos_t::serialize(bytevec_t *) const;
%ignore renderer_info_pos_t::deserialize(memory_deserializer_t &);

%template(segm_move_info_vec_t) qvector<segm_move_info_t>;

%apply SWIGTYPE *DISOWN { place_t *in_p };

%inline %{
//<inline(py_moves)>
//</inline(py_moves)>
%}

%include "moves.hpp"
