%ignore sarray;
%ignore lastreq_t;
%ignore AREA_CACHE_SIZE;
%ignore ANODE;
%ignore ANODE2;
%ignore AREA_LONG_COMMENT_TAG;
%ignore area_visitor_t;

// Ignore the private members in areacb_t
%ignore areacb_t::areasCode;
%ignore areacb_t::infosize;
%ignore areacb_t::lastreq;
%ignore areacb_t::reserved;
%ignore areacb_t::sa;
%ignore areacb_t::cache;
%ignore areacb_t::allocate;
%ignore areacb_t::search;
%ignore areacb_t::readArea;
%ignore areacb_t::findCache;
%ignore areacb_t::addCache;
%ignore areacb_t::delCache;
%ignore areacb_t::free_cache;
%ignore areacb_t::find_nth_start;
%ignore areacb_t::build_optimizer;
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

%include "area.hpp"
