%cstring_bounded_output_none(char *buf, MAXSTR);
%cstring_bounded_output_none(char *optlibs, MAXSTR);

// FIXME: These should probably be fixed
%ignore iterate_func_chunks;
%ignore get_idasgn_desc;
%ignore get_sig_filename;
%ignore get_idasgn_header_by_short_name;
%ignore get_idasgn_title;

// Kernel-only & unexported symbols
%ignore del_regargs;
%ignore write_regargs;
%ignore find_regarg;
%ignore free_regarg;
%ignore determine_rtl;
%ignore init_signatures;
%ignore save_signatures;
%ignore term_signatures;
%ignore init_funcs;
%ignore save_funcs;
%ignore term_funcs;
%ignore move_funcs;
%ignore copy_noret_info;
%ignore recalc_func_noret_flag;
%ignore plan_for_noret_analysis;
%ignore invalidate_sp_analysis;

%ignore create_func_eas_array;
%ignore auto_add_func_tails;
%ignore read_tails;

%include "funcs.hpp"

%clear(char *buf);
%clear(char *optlibs);

%inline %{
ea_t get_fchunk_referer(ea_t ea, size_t idx)
{
  func_t *pfn = get_fchunk(ea);
  func_parent_iterator_t dummy(pfn); // read referer info
  if ( idx >= pfn->refqty || pfn->referers == NULL )
    return BADADDR;
  return pfn->referers[idx];
}
%}
