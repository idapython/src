%ignore ANODE;
%ignore ANODE2;
%ignore AREA_LONG_COMMENT_TAG;
%ignore area_visitor_t;

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

%inline %{
//<inline(py_area)>
//</inline(py_area)>
%}

%include "area.hpp"

%extend areacb_t {
  areacb_type_t get_type()
  {
    areacb_type_t t = AREACB_TYPE_UNKNOWN;
    if ( $self == &funcs )
      t = AREACB_TYPE_FUNC;
    else if ( $self == &segs )
      t = AREACB_TYPE_SEGMENT;
    else if ( $self == &hidden_areas )
      t = AREACB_TYPE_HIDDEN_AREA;
    return t;
  }
}
