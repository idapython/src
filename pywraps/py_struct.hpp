
#ifndef __PY_STRUCT__
#define __PY_STRUCT__

//<inline(py_struct)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_innermost_member(sptr, offset):
    """
    Get the innermost member at the given offset
    @param sptr: the starting structure
    @param offset: offset into the starting structure
    @return:
        - None on failure
        - tuple(member_t, struct_t, offset)
          where member_t: a member in SPTR (it is not a structure),
                struct_t: the innermost structure,
                offset:   remaining offset into the returned member
    """
    pass
#</pydoc>
*/
PyObject *py_get_innermost_member(struc_t *sptr, asize_t offset)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  member_t *mptr = get_innermost_member(&sptr, &offset);
  if ( mptr == nullptr )
    Py_RETURN_NONE;
  return Py_BuildValue("(OO" PY_BV_ASIZE ")",
           SWIG_NewPointerObj(SWIG_as_voidptr(mptr), SWIGTYPE_p_member_t, 0),
           SWIG_NewPointerObj(SWIG_as_voidptr(sptr), SWIGTYPE_p_struc_t, 0),
           bvasize_t(offset));
}

//</inline(py_struct)>

#endif // __PY_STRUCT__
