
//-------------------------------------------------------------------------
//<inline(py_xref)>

// important for SWiG to generate properly-wrapped vector classes
typedef qvector<svalvec_t> casevec_t;
typedef qvector<ea_t> eavec_t;
//

//-------------------------------------------------------------------------
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
cases_and_targets_t *py_calc_switch_cases(
        ea_t ea,
        const switch_info_t &si)
{
  cases_and_targets_t *ct = new cases_and_targets_t;
  if ( !calc_switch_cases(&ct->cases, &ct->targets, ea, si) )
  {
    delete ct;
    return nullptr;
  }
  return ct;
}

//-------------------------------------------------------------------------
bool py_create_switch_table(ea_t ea, const switch_info_t &si)
{
  create_switch_table(ea, si);
  return true;
}
//</inline(py_xref)>
