//<inline(py_frame)>

//-------------------------------------------------------------------------
inline bool is_funcarg_off(const func_t *pfn, uval_t frameoff)
{
  processor_t &ph = PH;
  return ph.is_funcarg_off(pfn, frameoff);
}

//-------------------------------------------------------------------------
inline sval_t lvar_off(const func_t *pfn, uval_t frameoff)
{
  processor_t &ph = PH;
  return ph.lvar_off(pfn, frameoff);
}
//</inline(py_frame)>
