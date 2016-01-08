// Ignore functions with callbacks
%ignore enumerate_selectors;
%ignore enumerate_segments_with_selector;

// Kernel-only
%ignore init_groups;
%ignore save_groups;
%ignore term_groups;
%ignore vset_segm_name;
%ignore get_segm_expr;
%ignore get_based_segm_expr;
%ignore createSegmentation;
%ignore initSegment;
%ignore save_segments;
%ignore termSegment;
%ignore DeleteAllSegments;
%ignore delete_debug_segments;
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
