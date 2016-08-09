
//-------------------------------------------------------------------------
//<inline(py_xref)>

// important for SWiG to generate properly-wrapped vector classes
typedef qvector<sval_t> svalvec_t;
typedef qvector<svalvec_t> casevec_t;
typedef qvector<ea_t> eavec_t;
//

/*
#<pydoc>
def create_switch_xrefs(insn_ea, si):
    """
    This function creates xrefs from the indirect jump.

    Usually there is no need to call this function directly because the kernel
    will call it for switch tables

    Note: Custom switch information are not supported yet.

    @param insn_ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass
#</pydoc>
*/
idaman bool ida_export py_create_switch_xrefs(
        ea_t insn_ea,
        PyObject *py_swi)
{
  switch_info_ex_t *swi = switch_info_ex_t_get_clink(py_swi);
  if ( swi == NULL )
    return false;

  create_switch_xrefs(insn_ea, swi);
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
def calc_switch_cases(insn_ea, si):
    """
    Get information about a switch's cases.

    The returned information can be used as follows:

        for idx in xrange(len(results.cases)):
            cur_case = results.cases[idx]
            for cidx in xrange(len(cur_case)):
                print "case: %d" % cur_case[cidx]
            print "  goto 0x%x" % results.targets[idx]

    @param insn_ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: a structure with 2 members: 'cases', and 'targets'.
    """
    pass
#</pydoc>
*/
idaman cases_and_targets_t *ida_export py_calc_switch_cases(
        ea_t insn_ea,
        PyObject *py_swi)
{
  switch_info_ex_t *swi = switch_info_ex_t_get_clink(py_swi);
  if ( swi == NULL )
    return NULL;

  cases_and_targets_t *ct = new cases_and_targets_t;
  if ( !calc_switch_cases(insn_ea, swi, &ct->cases, &ct->targets) )
  {
    delete ct;
    return NULL;
  }

  return ct;
}


//-------------------------------------------------------------------------
/*
#<pydoc>
def create_switch_table(insn_ea, si):
    """
    Create switch table from the switch information

    @param insn_ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass
#</pydoc>
*/
idaman bool ida_export py_create_switch_table(
        ea_t insn_ea,
        PyObject *py_swi)
{
  switch_info_ex_t *swi = switch_info_ex_t_get_clink(py_swi);
  if ( swi == NULL )
    return false;

  create_switch_table(insn_ea, swi);
  return true;
}
//</inline(py_xref)>
