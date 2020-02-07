%module(docstring="IDA Plugin SDK API wrapper: moves",directors="1",threads="1") ida_moves
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_MOVES
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_MOVES
  #define HAS_DEP_ON_INTERFACE_MOVES
#endif
%include "header.i"
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
%ignore graph_location_info_t::serialize(bytevec_t *) const;
%ignore graph_location_info_t::deserialize(const uchar **, const uchar *);
%ignore renderer_info_pos_t::serialize(bytevec_t *) const;
%ignore renderer_info_pos_t::deserialize(const uchar **, const uchar *);

%template(segm_move_info_vec_t) qvector<segm_move_info_t>;

%inline %{
//<inline(py_moves)>
//</inline(py_moves)>
%}

%include "moves.hpp"
