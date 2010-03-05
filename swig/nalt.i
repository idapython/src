%ignore nmSerEA;
%ignore nmSerN;
%ignore maxSerialName;
%ignore get_import_module_name;
%rename (get_import_module_name) py_get_import_module_name;
%ignore NALT_EA;
%ignore enum_import_names;
%rename (enum_import_names) py_enum_import_names;

%include "nalt.hpp"

%{
//<code(py_nalt)>

//-------------------------------------------------------------------------
// callback for enumerating imports
// ea:   import address
// name: import name (NULL if imported by ordinal)
// ord:  import ordinal (0 for imports by name)
// param: user parameter passed to enum_import_names()
// return: 1-ok, 0-stop enumeration
static int idaapi py_import_enum_cb(
  ea_t ea, 
  const char *name, 
  uval_t ord, 
  void *param)
{
  PyObject *py_ea = Py_BuildValue(PY_FMT64, pyul_t(ea));
  PyObject *py_name = PyString_FromString(name);
  PyObject *py_ord = Py_BuildValue(PY_FMT64, pyul_t(ord));
  PyObject *py_result = PyObject_CallFunctionObjArgs((PyObject *)param, py_ea, py_name, py_ord, NULL);
  int r = py_result != NULL && PyObject_IsTrue(py_result) ? 1 : 0;
  Py_DECREF(py_ea);
  Py_DECREF(py_name);
  Py_DECREF(py_ord);
  Py_XDECREF(py_result);
  return r;
}
//</code(py_nalt)>
%}

%inline %{
//<inline(py_nalt)>
//-------------------------------------------------------------------------
PyObject *py_get_import_module_name(int mod_index)
{
  char buf[MAXSTR];
  if ( !get_import_module_name(mod_index, buf, sizeof(buf)) )
    Py_RETURN_NONE;
  return PyString_FromString(buf);
}

//-------------------------------------------------------------------------
// enumerate imports from specific module
// return: 1-finished ok, -1 on error, otherwise callback return value (<=0)
int py_enum_import_names(int mod_index, PyObject *py_cb)
{
  if ( !PyCallable_Check(py_cb) )
    return -1;
  return enum_import_names(mod_index, py_import_enum_cb, py_cb);
}

//</inline(py_nalt)>
%}