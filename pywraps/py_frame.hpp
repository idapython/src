//<inline(py_frame)>
//-------------------------------------------------------------------------
/*
header: frame.hpp
#<pydoc>
def add_stkvar3(op, v, flags):
    """
    Automatically add stack variable if doesn't exist
    Processor modules should use ua_stkvar2()
    @param op: reference to instruction operand
    @param v: immediate value in the operand (usually op.addr)
    @param flags: combination of STKVAR_... constants
    @return: Boolean
    """
    pass
#</pydoc>
*/
bool py_add_stkvar3(PyObject *py_op, PyObject *py_v, int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  op_t *op = op_t_get_clink(py_op);
  uint64 v;
  return ( op == NULL || !PyW_GetNumber(py_v, &v) || !add_stkvar3(*op, sval_t(v), flags)) ? false : true;
}

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
PyObject *py_get_stkvar(PyObject *py_op, PyObject *py_v)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  op_t *op = op_t_get_clink(py_op);
  uint64 v;
  if ( op == NULL || !PyW_GetNumber(py_v, &v) )
    Py_RETURN_NONE;

  sval_t actval;
  member_t *member = get_stkvar(*op, sval_t(v), &actval);
  if ( member == NULL )
    Py_RETURN_NONE;

  return Py_BuildValue("(O" PY_SFMT64 ")",
                       SWIG_NewPointerObj(SWIG_as_voidptr(member), SWIGTYPE_p_member_t, 0),
                       pyl_t(actval));
}
//</inline(py_frame)>
