#ifndef __PY_IDA_NALT__
#define __PY_IDA_NALT__

//<code(py_nalt)>

//-------------------------------------------------------------------------
// callback for enumerating imports
// ea:   import address
// name: import name (nullptr if imported by ordinal)
// ord:  import ordinal (0 for imports by name)
// param: user parameter passed to enum_import_names()
// return: 1-ok, 0-stop enumeration
static int idaapi py_import_enum_cb(
        ea_t ea,
        const char *name,
        uval_t ord,
        void *param)
{
  // If no name, try to get the name associated with the 'ea'. It may be coming from IDS
  qstring name_buf;
  if ( name == nullptr && get_name(&name_buf, ea) > 0 )
    name = name_buf.begin();

  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_name;
  if ( name == nullptr )
    py_name = borref_t(Py_None);
  else
    py_name = newref_t(PyUnicode_FromString(name));

  newref_t py_ord(Py_BuildValue(PY_BV_UVAL, bvuval_t(ord)));
  newref_t py_ea(Py_BuildValue(PY_BV_EA, bvea_t(ea)));
  newref_t py_result(
          PyObject_CallFunctionObjArgs(
                  (PyObject *)param,
                  py_ea.o,
                  py_name.o,
                  py_ord.o,
                  nullptr));
  return py_result && PyObject_IsTrue(py_result.o) ? 1 : 0;
}
//</code(py_nalt)>

//<inline(py_nalt)>

//-------------------------------------------------------------------------
static PyObject *py_get_import_module_name(int mod_index)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring qbuf;
  if ( !get_import_module_name(&qbuf, mod_index) )
    Py_RETURN_NONE;

  return PyUnicode_FromStringAndSize(qbuf.begin(), qbuf.length());
}

//-------------------------------------------------------------------------
static int py_enum_import_names(int mod_index, PyObject *callback)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCallable_Check(callback) )
    return -1;
  return enum_import_names(mod_index, py_import_enum_cb, callback);
}

//-------------------------------------------------------------------------
static switch_info_t *switch_info_t__from_ptrval__(size_t ptrval)
{
  return (switch_info_t *) ptrval;
}
//</inline(py_nalt)>

#endif
