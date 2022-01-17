//<inline(py_frame)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_stkvar(op, v):
    """
    Get pointer to stack variable
    @param op: reference to instruction operand
    @param v: immediate value in the operand (usually op.addr)
    @return:
        - None on failure
        - tuple(member_t, actval)
          where actval: actual value used to fetch stack variable
    """
    pass
#</pydoc>
*/
PyObject *py_get_stkvar(const insn_t &insn, const op_t &op, sval_t v)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  sval_t actval;
  member_t *member = get_stkvar(&actval, insn, op, v);
  if ( member == nullptr )
    Py_RETURN_NONE;

  return Py_BuildValue("(O" PY_BV_SVAL ")",
                       SWIG_InternalNewPointerObj(SWIG_as_voidptr(member), SWIGTYPE_p_member_t, 0),
                       bvsval_t(actval));
}

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
