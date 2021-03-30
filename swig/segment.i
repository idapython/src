// Ignore functions with callbacks

%ignore enumerate_selectors;
%ignore enumerate_segments_with_selector;

// Kernel-only
%ignore vset_segm_name;
%ignore get_segm_expr;
%ignore is_debugger_segm;
%ignore is_ephemeral_segm;
%ignore correct_address;
%ignore rebase_program;
%rename (rebase_program) py_rebase_program;

%{
//<code(py_segment)>
//</code(py_segment)>
%}

%extend segment_t
{
  ea_t start_ea;
  ea_t end_ea;

  %pythoncode {
      use64 = is_64bit
  }
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
//</inline(py_segment)>
%}
