%module(docstring="IDA Plugin SDK API wrapper: xref",directors="1",threads="1") ida_xref
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_XREF
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_XREF
  #define HAS_DEP_ON_INTERFACE_XREF
#endif
%include "header.i"
// Ignore kernel-only functions and variables
%ignore create_xrefs_from;
%ignore delete_all_xrefs_from;
%ignore destroy_if_align;
%ignore lastXR;
%ignore create_switch_xrefs;
%rename (create_switch_xrefs) py_create_switch_xrefs;
%ignore create_switch_table;
%rename (create_switch_table) py_create_switch_table;
%ignore calc_switch_cases;
%rename (calc_switch_cases)   py_calc_switch_cases;

// These functions should not be called directly (according to docs)
%ignore xrefblk_t_first_from;
%ignore xrefblk_t_next_from;
%ignore xrefblk_t_first_to;
%ignore xrefblk_t_next_to;

// 'from' is a reserved Python keyword
%rename (frm) from;

%inline %{
//<inline(py_xref)>

// important for SWiG to generate properly-wrapped vector classes
typedef qvector<svalvec_t> casevec_t;
typedef qvector<ea_t> eavec_t;
//

/*
#<pydoc>
def create_switch_xrefs(ea, si):
    """
    This function creates xrefs from the indirect jump.

    Usually there is no need to call this function directly because the kernel
    will call it for switch tables

    Note: Custom switch information are not supported yet.

    @param ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass
#</pydoc>
*/
bool py_create_switch_xrefs(ea_t ea, const switch_info_t &si)
{
  create_switch_xrefs(ea, si);
  return true;
}


//-------------------------------------------------------------------------
struct cases_and_targets_t
{
  casevec_t cases;
  eavec_t targets;
};

//-------------------------------------------------------------------------
/*
#<pydoc>
def calc_switch_cases(ea, si):
    """
    Get information about a switch's cases.

    The returned information can be used as follows:

        for idx in xrange(len(results.cases)):
            cur_case = results.cases[idx]
            for cidx in xrange(len(cur_case)):
                print "case: %d" % cur_case[cidx]
            print "  goto 0x%x" % results.targets[idx]

    @param ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: a structure with 2 members: 'cases', and 'targets'.
    """
    pass
#</pydoc>
*/
cases_and_targets_t *py_calc_switch_cases(
        ea_t ea,
        const switch_info_t &si)
{
  cases_and_targets_t *ct = new cases_and_targets_t;
  if ( !calc_switch_cases(&ct->cases, &ct->targets, ea, si) )
  {
    delete ct;
    return NULL;
  }
  return ct;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def create_switch_table(ea, si):
    """
    Create switch table from the switch information

    @param ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass
#</pydoc>
*/
bool py_create_switch_table(ea_t ea, const switch_info_t &si)
{
  create_switch_table(ea, si);
  return true;
}
//</inline(py_xref)>
%}

%include "xref.hpp"

%template(casevec_t) qvector<qvector<sval_t> >; // signed values

%pythoncode %{
#<pycode(py_xref)>

import ida_idaapi
ida_idaapi._listify_types(
        casevec_t)

#</pycode(py_xref)>
%}
