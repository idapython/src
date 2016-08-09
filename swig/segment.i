// Ignore functions with callbacks

%import "area.i"

%ignore enumerate_selectors;
%ignore enumerate_segments_with_selector;

// Kernel-only
%ignore init_groups;
%ignore save_groups;
%ignore term_groups;
%ignore vset_segm_name;
%ignore get_segm_expr;
%ignore is_debugger_segm;
%ignore is_ephemeral_segm;
%ignore correct_address;

%{
//<code(py_segment)>
//</code(py_segment)>
%}

%extend segment_t
{
  ea_t startEA;
  ea_t endEA;
}

%include "segment.hpp"

%inline %{
//<inline(py_segment)>
//</inline(py_segment)>
%}
