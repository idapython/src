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

%include "segment.hpp"

%inline %{
sel_t get_defsr(segment_t *s, int reg)
{
    return s->defsr[reg];
}
void set_defsr(segment_t *s, int reg, sel_t value)
{
    s->defsr[reg] = value;
}
%}
