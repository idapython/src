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
void segment_t_startEA_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->startEA) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify startEA, please use set_segm_start() instead");
  }
  else
  {
    segm->startEA = newea;
  }
}

ea_t segment_t_startEA_get(segment_t *segm)
{
  return segm->startEA;
}

void segment_t_endEA_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->startEA) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify endEA, please use set_segm_end() instead");
  }
  else
  {
    segm->endEA = newea;
  }
}

ea_t segment_t_endEA_get(segment_t *segm)
{
  return segm->endEA;
}
%}
%extend segment_t
{
  ea_t startEA;
  ea_t endEA; 
}

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
