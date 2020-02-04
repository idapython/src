%module(docstring="IDA Plugin SDK API wrapper: segment",directors="1",threads="1") ida_segment
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_SEGMENT
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_SEGMENT
  #define HAS_DEP_ON_INTERFACE_SEGMENT
#endif
#ifndef HAS_DEP_ON_INTERFACE_RANGE
  #define HAS_DEP_ON_INTERFACE_RANGE
#endif
%include "header.i"
// Ignore functions with callbacks

%import "range.i"

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
%ignore rebase_program;
%rename (rebase_program) py_rebase_program;

%{
//<code(py_segment)>
void segment_t_start_ea_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->start_ea) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify start_ea, please use set_segm_start() instead");
  }
  else
  {
    segm->start_ea = newea;
  }
}

ea_t segment_t_start_ea_get(segment_t *segm)
{
  return segm->start_ea;
}

void segment_t_end_ea_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->start_ea) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify end_ea, please use set_segm_end() instead");
  }
  else
  {
    segm->end_ea = newea;
  }
}

ea_t segment_t_end_ea_get(segment_t *segm)
{
  return segm->end_ea;
}
//</code(py_segment)>
%}

%extend segment_t
{
  ea_t start_ea;
  ea_t end_ea;
}

#ifdef __EA64__
%apply ulonglong *OUTPUT { sel_t *sel, ea_t *base }; // getn_selector()
#else
%apply unsigned int *OUTPUT { sel_t *sel, ea_t *base }; // getn_selector()
#endif

%typemap(check) (sel_t *sel, ea_t *base) {
  // getn_selector() check
  *($1) = BADSEL;
  *($2) = BADADDR;
}

//<typemaps(py_segment)>
//</typemaps(py_segment)>

%include "segment.hpp"

%inline %{
//<inline(py_segment)>
sel_t get_defsr(segment_t *s, int reg)
{
  return s->defsr[reg];
}
void set_defsr(segment_t *s, int reg, sel_t value)
{
  s->defsr[reg] = value;
}
int py_rebase_program(PyObject *delta, int flags)
{
  int rc = MOVE_SEGM_PARAM;
  bool is_64 = false;
  uint64 num_delta;
  if ( PyW_GetNumber(delta, &num_delta, &is_64) )
    rc = rebase_program(adiff_t(num_delta), flags);
  else
    PyErr_SetString(PyExc_TypeError, "Expected a delta in bytes");
  return rc;
}
//</inline(py_segment)>
%}
%pythoncode %{
if _BC695:
    CSS_NOAREA=CSS_NORANGE
    SEGDEL_KEEP=SEGMOD_KEEP
    SEGDEL_KEEP0=SEGMOD_KEEP0
    SEGDEL_PERM=SEGMOD_KILL
    SEGDEL_SILENT=SEGMOD_SILENT
    def del_segment_cmt(s, rpt):
        set_segment_cmt(s, "", rpt)
    ask_selector=sel2para
    # In 7.0, those were renamed
    #  - get_true_segm_name -> get_segm_name
    #  - get_segm_name -> get_visible_segm_name
    # alas, since they have the same prototypes, we cannot do much,
    # but redirect all to get_segm_name and hope for the best
    get_true_segm_name=get_segm_name

%}