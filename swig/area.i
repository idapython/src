%ignore ANODE;
%ignore ANODE2;
%ignore AREA_LONG_COMMENT_TAG;
%ignore area_visitor_t;
%ignore areacb_t_link_dont_load;
%ignore add_area_from_cache;
%ignore areacb_t_valid_push_back;

// Ignore the private members in areacb_t
%ignore areacb_t::areasCode;
%ignore areacb_t::infosize;
%ignore areacb_t::lastreq;
%ignore areacb_t::reserved;
%ignore areacb_t::areas;
%ignore areacb_t::move_area_comment;
%ignore areacb_t::pack_and_write_area;
%ignore areacb_t::move_away;

%ignore areacb_t::read_cb;
%ignore areacb_t::write_cb;
%ignore areacb_t::delcache_cb;
%ignore areacb_t::edit_cb;
%ignore areacb_t::kill_cb;
%ignore areacb_t::new_cb;

%ignore areacb_t::choose_area;
%ignore areacb_t::choose_area2;
%ignore areacb_t::find_prev_gap;
%ignore areacb_t::find_next_gap;

%ignore areacb_t::move_areas;
%ignore areacb_t::for_all_areas;

%ignore areaset_t::count;
%ignore areaset_t::lower_bound;
%ignore areaset_t::upper_bound;
%ignore areaset_t::move_chunk;
%ignore areaset_t::check_move_args;

%include "area.hpp"
