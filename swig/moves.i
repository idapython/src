
// Ignore kernel only symbols
%ignore init_marks;
%ignore term_marks;
%ignore change_jumps_stack_format;
%ignore move_marks;
%ignore curloc_after_segments_moved;
%ignore curloc::rebase_stack;
%ignore loc_gtag;
%ignore write_gli;
%ignore read_gli;
%ignore DEFINE_CURLOC_HELPERS;
%ignore DEFINE_LOCATION_HELPERS;
%ignore histories_after_segments_moved;
%ignore lochist_t::rebase_stack;
%ignore location_t::location_t(bool);
%ignore lochist_t::is_hexrays68_compat;
%ignore lochist_entry_t::set_place(const place_t &);

%template(segm_move_info_vec_t) qvector<segm_move_info_t>;

%include "moves.hpp"
