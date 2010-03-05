%module(docstring="IDA Pro Plugin SDK API wrapper",directors="1") idaapi
// Suppress 'previous definition of XX' warnings
#pragma SWIG nowarn=302
// Enable automatic docstring generation
%feature(autodoc);
%{
#include <Python.h>
#define USE_DANGEROUS_FUNCTIONS 1
#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif
#if defined(__NT__) && !defined(_WINDOWS_)
  #define _WINDOWS_ // kernwin.hpp needs it to declare create_tform()
  typedef void *HWND; // we don't need to include windows.h for just this definition
#endif
#include "ida.hpp"
#include "idp.hpp"
#include "allins.hpp"
#include "auto.hpp"
#include "bytes.hpp"
#include "dbg.hpp"
#include "diskio.hpp"
#include "entry.hpp"
#include "enum.hpp"
#include "expr.hpp"
#include "frame.hpp"
#include "fixup.hpp"
#include "funcs.hpp"
#include "gdl.hpp"
#include "idd.hpp"
#include "ints.hpp"
#include "kernwin.hpp"
#include "lines.hpp"
#include "loader.hpp"
#include "moves.hpp"
#include "netnode.hpp"
#include "nalt.hpp"
#include "name.hpp"
#include "offset.hpp"
#include "queue.hpp"
#include "search.hpp"
#include "srarea.hpp"
#include "strlist.hpp"
#include "struct.hpp"
#include "typeinf.hpp"
#include "ua.hpp"
#include "xref.hpp"
#include "ieee.h"
#include "err.h"
#include "fpro.h"
#include <map>
#ifdef __NT__
  #include "graph.hpp"
#endif

//<code(py_idaapi)>

#include "pywraps.hpp"

//------------------------------------------------------------------------
// String constants used
static const char PY_IDC_CLASS_NAME[]        = "py_idc_object_class";
static const char PY_IDC_GLOBAL_VAR_FMT[]    = "__py_cvt_gvar_%d";
static const char PY_IDCCVT_ID_ATTR[]        = "__idc_cvt_id__";
static const char PY_IDCCVT_VALUE_ATTR[]     = "__idc_cvt_value__";
static const char S_PY_IDC_OPAQUE_T[]        = "py_idc_cvt_helper_t";
static const char S_PROPS[]                  = "props";
static const char S_NAME[]                   = "name";
static const char S_ASM_KEYWORD[]            = "asm_keyword";
static const char S_MENU_NAME[]              = "menu_name";
static const char S_HOTKEY[]                 = "hotkey";
static const char S_VALUE_SIZE[]             = "value_size";
static const char S_MAY_CREATE_AT[]          = "may_create_at";
static const char S_CALC_ITEM_SIZE[]         = "calc_item_size";
static const char S_ID[]                     = "id";
static const char S_PRINTF[]                 = "printf";
static const char S_TEXT_WIDTH[]             = "text_width";
static const char S_SCAN[]                   = "scan";
static const char S_ANALYZE[]                = "analyze";
static const char S_CBSIZE[]                 = "cbsize";
static const char S_ON_CLICK[]               = "OnClick";
static const char S_ON_CLOSE[]               = "OnClose";
static const char S_ON_DBL_CLICK[]           = "OnDblClick";
static const char S_ON_CURSOR_POS_CHANGED[]  = "OnCursorPosChanged";
static const char S_ON_KEYDOWN[]             = "OnKeydown";
static const char S_ON_POPUP[]               = "OnPopup";
static const char S_ON_HINT[]                = "OnHint";
static const char S_ON_POPUP_MENU[]          = "OnPopupMenu";
static const char S_ON_EDIT_LINE[]           = "OnEditLine";
static const char S_ON_INSERT_LINE[]         = "OnInsertLine";
static const char S_ON_GET_LINE[]            = "OnGetLine";
static const char S_ON_DELETE_LINE[]         = "OnDeleteLine";
static const char S_ON_REFRESH[]             = "OnRefresh";
static const char S_ON_SELECT_LINE[]         = "OnSelectLine";
static const char S_ON_COMMAND[]             = "OnCommand";
static const char S_ON_GET_ICON[]            = "OnGetIcon";
static const char S_ON_GET_LINE_ATTR[]       = "OnGetLineAttr";
static const char S_ON_GET_SIZE[]            = "OnGetSize";
static const char S_ON_GETTEXT[]             = "OnGetText";
static const char S_ON_ACTIVATE[]            = "OnActivate";
static const char S_ON_DEACTIVATE[]          = "OnDeactivate";
static const char S_ON_SELECT[]              = "OnSelect";
static const char S_M_EDGES[]                = "_edges";
static const char S_M_NODES[]                = "_nodes";
static const char S_M_THIS[]                 = "_this";
static const char S_M_TITLE[]                = "_title";

#ifdef __PYWRAPS__
static const char S_PY_IDAAPI_MODNAME[]      = "__main__";
#else
static const char S_PY_IDAAPI_MODNAME[]      = "idaapi";
#endif

//------------------------------------------------------------------------
// Constants used by get_idaapi_class_reference()
#define PY_CLSID_CVT_INT64                       0
#define PY_CLSID_APPCALL_SKEL_OBJ                1
#define PY_CLSID_CVT_BYREF                       2
#define PY_CLSID_LAST                            3

//------------------------------------------------------------------------
static PyObject *py_cvt_helper_module = NULL;
static bool pywraps_initialized = false;

//------------------------------------------------------------------------
static idc_class_t *get_py_idc_cvt_opaque()
{
  return find_idc_class(S_PY_IDC_OPAQUE_T);
}

//------------------------------------------------------------------------
// IDC Opaque object destructor: when the IDC object dies we kill the 
// opaque Python object along with it
static const char py_idc_cvt_helper_dtor_args[] = { VT_OBJ, 0 };
static error_t idaapi py_idc_opaque_dtor(
  idc_value_t *argv,
  idc_value_t *res)
{
  // Get the value from the object
  idc_value_t idc_val;
  VarGetAttr(&argv[0], PY_IDCCVT_VALUE_ATTR, &idc_val);

  // Extract the Python object reference
  PyObject *py_obj = (PyObject *)idc_val.pvoid;
  // Decrease its reference (and eventually destroy it)
  Py_DECREF(py_obj);
  return eOk;
}

//------------------------------------------------------------------------
// This function must be called on initialization
bool init_pywraps()
{
  if (pywraps_initialized)
    return true;

  // Take a reference to the idaapi python module
  // (We need it to create instances of certain classes)
  if (py_cvt_helper_module == NULL)
  {
    // Take a reference to the module so we can create the needed class instances
    py_cvt_helper_module = PyImport_TryImportModule(S_PY_IDAAPI_MODNAME);
    if (py_cvt_helper_module == NULL)
      return false;
  }

  if (get_py_idc_cvt_opaque() == NULL)
  {
    // Add the class
    idc_class_t *idc_cvt_opaque = add_idc_class(S_PY_IDC_OPAQUE_T);
    if (idc_cvt_opaque == NULL)
      return false;

    // Form the dtor name
    char dtor_name[MAXSTR];
    qsnprintf(dtor_name, sizeof(dtor_name), "%s.dtor", S_PY_IDC_OPAQUE_T);

    // register the dtor function
    if (!set_idc_func(dtor_name, py_idc_opaque_dtor, py_idc_cvt_helper_dtor_args))
      return false;

    // Link the dtor function to the class
    set_idc_dtor(idc_cvt_opaque, dtor_name);
  }
  pywraps_initialized = true;
  return true;
}

//------------------------------------------------------------------------
// This function must be called on de-initialization
void deinit_pywraps()
{
  if (!pywraps_initialized)
    return;
  pywraps_initialized = false;
  Py_XDECREF(py_cvt_helper_module);
  py_cvt_helper_module = NULL;
}
//------------------------------------------------------------------------
// Gets a class type reference in idaapi
// With the class type reference we can create a new instance of that type
// This function takes a reference to the idaapi module and keeps the reference
static PyObject *get_idaapi_class_reference(const int class_id)
{
  if (class_id >= PY_CLSID_LAST)
    return NULL;

  // Some class names. The array is parallel with the PY_CLSID_xxx consts
  static const char *class_names[]=
  {
    "PyIdc_cvt_int64__",
    "Appcall_object__",
    "PyIdc_cvt_refclass__"
  };
  return PyObject_GetAttrString(py_cvt_helper_module, class_names[class_id]);
}

//------------------------------------------------------------------------
// Returns an attribute or NULL
// No errors will be set if the attribute did not exist
PyObject *PyObject_TryGetAttrString(PyObject *py_var, const char *attr)
{
  if (!PyObject_HasAttrString(py_var, attr))
    return NULL;
  return PyObject_GetAttrString(py_var, attr);
}

//------------------------------------------------------------------------
// Tries to import a module and clears the exception on failure
PyObject *PyImport_TryImportModule(const char *name)
{
  PyObject *result = PyImport_ImportModule(name);
  if (result != NULL)
    return result;
  if (PyErr_Occurred())
    PyErr_Clear();
  return NULL;
}

//-------------------------------------------------------------------------
// Converts a Python number into an IDC value (32 or 64bits)
// The function will first try to convert the number into a 32bit value
// If the number does not fit then VT_INT64 will be used
// NB: This function cannot properly detect if the Python value should be
// converted to a VT_INT64 or not. For example: 2**32-1 = 0xffffffff which
// can fit in a C long but Python creates a PyLong object for it.
// And because of that we are confused as to whether to convert to 32 or 64
bool PyGetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var)
{
  if (!(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)))
    return false;

  // Can we convert to C long?
  long l = PyInt_AsLong(py_var);
  if (!PyErr_Occurred())
  {
    idc_var->set_long(l);
    return true;
  }
  // Clear last error
  PyErr_Clear();
  // Can be fit into a C unsigned long?
  l = (long) PyLong_AsUnsignedLong(py_var);
  if (!PyErr_Occurred())
  {
    idc_var->set_long(l);
    return true;
  }
  PyErr_Clear();
  idc_var->set_int64(PyLong_AsLongLong(py_var));
  return true;
}

//-------------------------------------------------------------------------
// Parses a Python object as a long or long long
bool PyGetNumber(PyObject *py_var, uint64 *num, bool *is_64)
{
  if (!(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)))
    return false;

  // Can we convert to C long?
  long l = PyInt_AsLong(py_var);
  if (!PyErr_Occurred())
  {
    if (num != NULL)
      *num = uint64(l);
    if (is_64 != NULL)
      *is_64 = false;
    return true;
  }
  // Clear last error
  PyErr_Clear();
  // Can be fit into a C unsigned long?
  unsigned long ul = PyLong_AsUnsignedLong(py_var);
  if (!PyErr_Occurred())
  {
    if (num != NULL)
      *num = uint64(ul);
    if (is_64 != NULL)
      *is_64 = false;
    return true;
  }
  PyErr_Clear();
  PY_LONG_LONG ll = PyLong_AsLongLong(py_var);
  if (!PyErr_Occurred())
  {
    if (num != NULL)
      *num = uint64(ll);
    if (is_64 != NULL)
      *is_64 = true;
    return true;
  }
  PyErr_Clear();
  return false;
}

//-------------------------------------------------------------------------
// Checks if a given object is of sequence type
bool PyIsSequenceType(PyObject *obj)
{
  if (!PySequence_Check(obj))
    return false;
  Py_ssize_t sz = PySequence_Size(obj);
  if (sz == -1 || PyErr_Occurred() != NULL)
  {
    PyErr_Clear();
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
// Returns the string representation of an object
bool PyObjectToString(PyObject *obj, qstring *out)
{
  PyObject *py_str = PyObject_Str(obj);
  if (py_str != NULL)
  {
    *out = PyString_AsString(py_str);
    Py_DECREF(py_str);
    return true;
  }
  else
  {
    out->qclear();
    return false;
  }
}

//--------------------------------------------------------------------------
// Checks if a Python error occured and fills the out parameter with the
// exception string
bool PyGetError(qstring *out)
{
  PyObject *py_err;
  if ((py_err = PyErr_Occurred()) == NULL)
    return false;

  PyObject *err_type, *err_value, *err_traceback;
  PyErr_Fetch(&err_type, &err_value, &err_traceback);
  if ( out != NULL )
    PyObjectToString(err_value, out);
  return true;
}

//-------------------------------------------------------------------------
// A loud version of PyGetError() which gets the error and displays it
bool PyShowErr(const char *cb_name)
{
  static qstring err_str;
  if (!PyGetError(&err_str))
    return false;
  warning("IDAPython: Error while calling Python callback <%s>:\n%s", cb_name, err_str.c_str());
  return true;
}

//-------------------------------------------------------------------------
// Checks if the given py_var is a special PyIdc_cvt_helper object.
// It does that by examining the magic attribute and returns its numeric value.
// It returns -1 if the object is not a recognized helper object.
// Any Python object can be treated as an cvt object if this attribute is created.
static int get_pyidc_cvt_type(PyObject *py_var)
{
  // Check if this our special by reference object
  PyObject *attr = PyObject_TryGetAttrString(py_var, PY_IDCCVT_ID_ATTR);
  if (attr == NULL)
    return -1;
  if (!(PyInt_Check(attr) || PyLong_Check(attr)))
  {
    Py_DECREF(attr);
    return -1;
  }
  int r = (int)PyInt_AsLong(attr);
  Py_DECREF(attr);
  return r;
}

//-------------------------------------------------------------------------
// Utility function to create opaque / convertible Python <-> IDC variables
// The referred Python variable will have its reference increased
static bool create_py_idc_opaque_obj(PyObject *py_var, idc_value_t *idc_var)
{
  // Create an IDC object of this special helper class
  if (VarObject(idc_var, get_py_idc_cvt_opaque()) != eOk)
    return false;

  // Store the CVT id
  idc_value_t idc_val;
  idc_val.set_long(PY_ICID_OPAQUE);
  VarSetAttr(idc_var, PY_IDCCVT_ID_ATTR, &idc_val);

  // Store the value as a PVOID referencing the given Python object
  idc_val.set_pvoid(py_var);
  VarSetAttr(idc_var, PY_IDCCVT_VALUE_ATTR, &idc_val);

  return true;
}

//-------------------------------------------------------------------------
// Converts a Python variable into an IDC variable
// This function returns on one CIP_XXXX
int pyvar_to_idcvar(
  PyObject *py_var,
  idc_value_t *idc_var,
  int *gvar_sn)
{
  PyObject *attr;
  // None / NULL
  if (py_var == NULL || py_var == Py_None)
    idc_var->set_long(0);
  // Numbers?
  else if (PyGetNumberAsIDC(py_var, idc_var))
    return CIP_OK;
  // String
  else if (PyString_Check(py_var))
    idc_var->_set_string(PyString_AsString(py_var), PyString_Size(py_var));
  // Float
  else if (PyBool_Check(py_var))
    idc_var->set_long(py_var == Py_True ? 1 : 0);
  // Boolean
  else if (PyFloat_Check(py_var))
  {
    double dresult = PyFloat_AsDouble(py_var);
    ieee_realcvt((void *)&dresult, idc_var->e, 3);
    idc_var->vtype = VT_FLOAT;
  }
  // void*
  else if (PyCObject_Check(py_var))
    idc_var->set_pvoid(PyCObject_AsVoidPtr(py_var));
  // Is it a Python list?
  else if (PyList_CheckExact(py_var) || PyIsSequenceType(py_var))
  {
    // Create the object
    VarObject(idc_var);

    // Determine list size and type
    bool is_seq = !PyList_CheckExact(py_var);
    Py_ssize_t size = is_seq ? PySequence_Size(py_var) : PyList_Size(py_var);
    bool ok = true;
    qstring attr_name;

    // Convert each item
    for (Py_ssize_t i=0;i<size;i++)
    {
      // Get the item
      PyObject *py_item = is_seq ? PySequence_GetItem(py_var, i) : PyList_GetItem(py_var, i);

      // Convert the item into an IDC variable
      idc_value_t v;
      ok = pyvar_to_idcvar(py_item, &v, gvar_sn) >= CIP_OK;
      if (ok)
      {
        // Form the attribute name
        PyObject *py_int = PyInt_FromSsize_t(i);
        ok = PyObjectToString(py_int, &attr_name);
        if (!ok)
          break;
        Py_DECREF(py_int);
        // Store the attribute
        VarSetAttr(idc_var, attr_name.c_str(), &v);
      }
      // Sequences return a new reference for GetItem()
      if (is_seq)
        Py_DECREF(py_var);
      if (!ok)
        break;
    }
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Dictionary: we convert to an IDC object
  else if (PyDict_Check(py_var))
  {
    // Create an empty IDC object
    VarObject(idc_var);

    // Get the dict.items() list
    PyObject *py_items = PyDict_Items(py_var);

    // Get the size of the list
    qstring key_name;
    bool ok = true;
    Py_ssize_t size = PySequence_Size(py_items);
    for (Py_ssize_t i=0;i<size;i++)
    {
      // Get item[i] -> (key, value)
      PyObject *py_item = PyList_GetItem(py_items, i);

      // Extract key/value
      PyObject *key  = PySequence_GetItem(py_item, 0);
      PyObject *val  = PySequence_GetItem(py_item, 1);

      // Get key's string representation
      PyObjectToString(key, &key_name);

      // Convert the attribute into an IDC value
      idc_value_t v;
      ok = pyvar_to_idcvar(val, &v, gvar_sn) >= CIP_OK;
      if (ok)
      {
        // Store the attribute
        VarSetAttr(idc_var, key_name.c_str(), &v);
      }
      Py_XDECREF(key);
      Py_XDECREF(val);
      if (!ok)
        break;
    }
    // Decrement attribute reference
    Py_DECREF(py_items);
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Possible function?
  else if (PyCallable_Check(py_var))
  {
    idc_var->clear();
    idc_var->vtype = VT_FUNC;
    idc_var->funcidx = -1; // Does not apply
    return CIP_OK;
  }
  // Objects:
  // - pyidc_cvt objects: int64, byref, opaque
  // - other python objects
  else
  {
    // Get the type
    int cvt_id = get_pyidc_cvt_type(py_var);
    switch (cvt_id)
    {
    //
    // INT64
    //
    case PY_ICID_INT64:
      // Get the value attribute
      attr = PyObject_TryGetAttrString(py_var, PY_IDCCVT_VALUE_ATTR);
      if (attr == NULL)
        return false;
      idc_var->set_int64(PyLong_AsLongLong(attr));
      Py_DECREF(attr);
      return CIP_OK;
    //
    // BYREF
    //
    case PY_ICID_BYREF:
      {
        // BYREF always require this parameter
        if (gvar_sn == NULL)
          return CIP_FAILED;

        // Get the value attribute
        attr = PyObject_TryGetAttrString(py_var, PY_IDCCVT_VALUE_ATTR);
        if (attr == NULL)
          return CIP_FAILED;

        // Create a global variable
        char buf[MAXSTR];
        qsnprintf(buf, sizeof(buf), PY_IDC_GLOBAL_VAR_FMT, *gvar_sn);
        idc_value_t *gvar = add_idc_gvar(buf);
        // Convert the python value into the IDC global variable
        bool ok = pyvar_to_idcvar(attr, gvar, gvar_sn) >= CIP_OK;
        if (ok)
        {
          (*gvar_sn)++;
          // Create a reference to this global variable
          VarRef(idc_var, gvar);
        }
        Py_DECREF(attr);
        return ok ? CIP_OK : CIP_FAILED;
      }
    //
    // OPAQUE
    //
    case PY_ICID_OPAQUE:
      {
        if (!create_py_idc_opaque_obj(py_var, idc_var))
          return CIP_FAILED;
        return CIP_OK_NODECREF;
      }
    //
    // Other objects
    //
    default:
      // A normal object?
      PyObject *py_dir = PyObject_Dir(py_var);
      Py_ssize_t size  = PyList_Size(py_dir);
      if (py_dir == NULL || !PyList_Check(py_dir) || size == 0)
      {
        Py_XDECREF(py_dir);
        return CIP_FAILED;
      }
      // Create the IDC object
      VarObject(idc_var);
      for (Py_ssize_t i=0;i<size;i++)
      {
        PyObject *item = PyList_GetItem(py_dir, i);
        const char *field_name = PyString_AsString(item);
        if (field_name == NULL)
          continue;
        size_t len = strlen(field_name);
        // skip private attributes
        if ( (len > 2 )
          && (strncmp(field_name, "__", 2) == 0 )
          && (strncmp(field_name+len-2, "__", 2) == 0) )
        {
          continue;
        }
        idc_value_t v;
        // Get the non-private attribute from the object
        attr = PyObject_GetAttrString(py_var, field_name);
        if (attr == NULL
          // Convert the attribute into an IDC value
          || pyvar_to_idcvar(attr, &v, gvar_sn) < CIP_OK)
        {
          Py_XDECREF(attr);
          return CIP_FAILED;
        }
        // Store the attribute
        VarSetAttr(idc_var, field_name, &v);
        // Decrement attribute reference
        Py_DECREF(attr);
      }
    }
  }
  return CIP_OK;
}

//-------------------------------------------------------------------------
// Converts an IDC variable to a Python variable
// If py_var points to an existing object then the object will be updated
// If py_var points to an existing immutable object then ZERO is returned
// Returns one of CIP_xxxx. Check pywraps.hpp
int idcvar_to_pyvar(
  const idc_value_t &idc_var,
  PyObject **py_var)
{
  switch (idc_var.vtype)
  {
  case VT_PVOID:
    if (*py_var == NULL)
      *py_var = PyCObject_FromVoidPtr(idc_var.pvoid, NULL);
    else
      return CIP_IMMUTABLE;
    break;
  case VT_INT64:
    {
      // Recycle?
      if (*py_var != NULL)
      {
        // Recycling an int64 object?
        int t = get_pyidc_cvt_type(*py_var);
        if (t != PY_ICID_INT64)
          return CIP_IMMUTABLE; // Cannot recycle immutable object
        // Update the attribute
        PyObject_SetAttrString(*py_var, PY_IDCCVT_VALUE_ATTR, PyLong_FromLongLong(idc_var.i64));
        return CIP_OK;
      }
      PyObject *py_cls = get_idaapi_class_reference(PY_CLSID_CVT_INT64);
      if (py_cls == NULL)
        return CIP_FAILED;
      *py_var = PyObject_CallFunctionObjArgs(py_cls, PyLong_FromLongLong(idc_var.i64), NULL);
      Py_DECREF(py_cls);
      break;
    }
#if !defined(NO_OBSOLETE_FUNCS) || defined(__EXPR_SRC)
  case VT_STR:
    *py_var = PyString_FromString(idc_var.str);
    break;
#endif
  case VT_STR2:
    if (*py_var == NULL)
    {
      const qstring &s = idc_var.qstr();
      *py_var = PyString_FromStringAndSize(s.begin(), s.length());
      break;
    }
    else
      return CIP_IMMUTABLE; // Cannot recycle immutable object
  case VT_LONG:
    // Cannot recycle immutable objects
    if (*py_var != NULL)
      return CIP_IMMUTABLE;
#ifdef __EA64__
    *py_var = PyLong_FromLongLong(idc_var.num);
#else
    *py_var = PyLong_FromLong(idc_var.num);
#endif
    break;
  case VT_FLOAT:
    if (*py_var == NULL)
    {
      double x;
      if ( ph.realcvt(&x, (uint16 *)idc_var.e, (sizeof(x)/2-1)|010) != 0 )
        INTERR();
      *py_var = PyFloat_FromDouble(x);
      break;
    }
    else
      return CIP_IMMUTABLE;
  case VT_REF:
    {
      if (*py_var == NULL)
      {
        PyObject *py_cls = get_idaapi_class_reference(PY_CLSID_CVT_BYREF);
        if (py_cls == NULL)
          return CIP_FAILED;
        // Create a byref object with None value. We populate it later
        *py_var = PyObject_CallFunctionObjArgs(py_cls, Py_None, NULL);
        Py_DECREF(py_cls);
      }
      int t = *py_var == NULL ? -1 : get_pyidc_cvt_type(*py_var);
      if (t != PY_ICID_BYREF)
        return CIP_FAILED;

      // Dereference
      // (Since we are not using VREF_COPY flag, we can safely const_cast)
      idc_value_t *dref_v = VarDeref(const_cast<idc_value_t *>(&idc_var), VREF_LOOP);
      if (dref_v == NULL)
        return CIP_FAILED;

      // Can we recycle the object?
      PyObject *new_py_val = PyObject_TryGetAttrString(*py_var, PY_IDCCVT_VALUE_ATTR);
      if (new_py_val != NULL)
      {
        // Recycle
        t = idcvar_to_pyvar(*dref_v, &new_py_val);
        Py_XDECREF(new_py_val); // DECREF because of GetAttrStr
        // Success? Nothing more to be done
        if (t == CIP_OK)
          return CIP_OK;
        // Clear it so we don't recycle it
        new_py_val = NULL;
      }
      // Try to convert (not recycle)
      if (idcvar_to_pyvar(*dref_v, &new_py_val) != CIP_OK)
        return CIP_FAILED;
      // Update the attribute
      PyObject_SetAttrString(*py_var, PY_IDCCVT_VALUE_ATTR, new_py_val);
      Py_DECREF(new_py_val);
      break;
    }
    // Can convert back into a Python object or Python dictionary
    // (Depending if py_var will be recycled and it was a dictionary)
  case VT_OBJ:
    {
      // Check if this IDC object has __cvt_id__ and the __idc_cvt_value__ fields
      idc_value_t idc_val;
      if (    VarGetAttr(&idc_var, PY_IDCCVT_ID_ATTR, &idc_val) == eOk
           && VarGetAttr(&idc_var, PY_IDCCVT_VALUE_ATTR, &idc_val) == eOk )
      {
        // Extract the object
        *py_var = (PyObject *) idc_val.pvoid;
        return CIP_OK_NODECREF;
      }
      PyObject *obj;
      bool is_dict = false;
      // Need to create a new object?
      if (*py_var == NULL)
      {
        PyObject *py_cls = get_idaapi_class_reference(PY_CLSID_APPCALL_SKEL_OBJ);
        if (py_cls == NULL)
          return CIP_FAILED;
        obj = PyObject_CallFunctionObjArgs(py_cls, NULL);
        Py_DECREF(py_cls);
        if (obj == NULL)
          return CIP_FAILED;
      }
      else
      {
        // Recycle existing variable
        obj = *py_var;
        if (PyDict_Check(obj))
          is_dict = true;
      }
      // Walk the IDC attributes and store into python
      for (const char *attr_name = VarFirstAttr(&idc_var);
           attr_name != NULL;
           attr_name=VarNextAttr(&idc_var, attr_name))
      {
        // Get the attribute
        idc_value_t v;
        VarGetAttr(&idc_var, attr_name, &v, true);
        // Convert attribute to a python value
        PyObject *py_attr(NULL);
        int cvt = idcvar_to_pyvar(v, &py_attr);
        if (cvt <= CIP_IMMUTABLE)
        {
          // Delete the object (if we created it)
          if (*py_var == NULL)
            Py_DECREF(obj);
          return CIP_FAILED;
        }
        if (is_dict)
          PyDict_SetItemString(obj, attr_name, py_attr);
        else
          PyObject_SetAttrString(obj, attr_name, py_attr);
        if (cvt == CIP_OK)
          Py_DECREF(py_attr);
      }
      *py_var = obj;
      break;
    }
    // Unhandled type
  default:
    *py_var = NULL;
    return CIP_FAILED;
  }
  return CIP_OK;
}

//</code(py_idaapi)>
%}

// Do not create separate wrappers for default arguments
%feature("compactdefaultargs");

#ifdef __EA64__
#ifdef __GNUC__
%constant ea_t BADADDR = 0xFFFFFFFFFFFFFFFFll;
%constant sel_t BADSEL = 0xFFFFFFFFFFFFFFFFll;
%constant nodeidx_t BADNODE = 0xFFFFFFFFFFFFFFFFll;
#else  // __GNUC__
%constant ea_t BADADDR = 0xFFFFFFFFFFFFFFFFui64;
%constant sel_t BADSEL = 0xFFFFFFFFFFFFFFFFui64;
%constant nodeidx_t BADNODE = 0xFFFFFFFFFFFFFFFFui64;
#endif // __GNUC__
#else  //__EA64__
%constant ea_t BADADDR = 0xFFFFFFFFL;
%constant sel_t BADSEL = 0xFFFFFFFFL;
%constant nodeidx_t BADNODE = 0xFFFFFFFFL;
#endif

// Help SWIG to figure out the ulonglong type
#ifdef SWIGWIN
typedef unsigned __int64 ulonglong;
typedef          __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef          long long longlong;
#endif

typedef int error_t;

%include "typemaps.i"

%include "cstring.i"
%include "carrays.i"
%include "cpointer.i"

%include "typeconv.i"

%include "pro.h"

// Do not move this. We need to override the define from pro.h
#define CASSERT(type)

// Convert all of these
%cstring_output_maxstr_none(char *buf, size_t bufsize);
%binary_output_or_none(void *buf, size_t bufsize);
%binary_output_with_size(void *buf, size_t *bufsize);

// Accept single Python string for const void * + size input arguments
// For example: put_many_bytes() and patch_many_bytes()
%apply (char *STRING, int LENGTH) { (const void *buf, size_t size) };
%apply (char *STRING, int LENGTH) { (const void *buf, size_t len) };
%apply (char *STRING, int LENGTH) { (const void *value, size_t length) };
%apply (char *STRING, int LENGTH) { (const void *dataptr,size_t len) };

// Create wrapper classes for basic type arrays
%array_class(uchar, uchar_array);
%array_class(tid_t, tid_array);
%array_class(ea_t, ea_array);
%array_class(sel_t, sel_array);
%array_class(uval_t, uval_array);
%pointer_class(int, int_pointer);
%pointer_class(ea_t, ea_pointer);
%pointer_class(sval_t, sval_pointer);
%pointer_class(sel_t, sel_pointer);

%include "ida.i"
%include "idd.i"
%include "idp.i"
%include "netnode.i"
%include "nalt.i"

%include "allins.i"
%include "area.i"
%include "auto.i"
%include "bytes.i"
%include "dbg.i"
%include "diskio.i"
%include "entry.i"
%include "enum.i"
%include "expr.i"
%include "fixup.i"
%include "frame.i"
%include "funcs.i"

%inline {
/* Small wrapper to get the inf structure */
idainfo *get_inf_structure(void)
{
    return &inf;
}
}

%include "gdl.i"
%include "ints.i"
%include "kernwin.i"
%include "lines.i"
%include "loader.i"
%include "moves.i"
%include "name.i"
%include "offset.i"
%include "queue.i"
%include "search.i"
%include "segment.i"
%include "srarea.i"
%include "strlist.i"
%include "struct.i"
%include "typeinf.i"
%include "ua.i"
%include "xref.i"
#ifdef __NT__
  %include "graph.i"
#endif
%include "fpro.i"

%inline {
    void set_script_timeout(int timeout);
    void enable_extlang_python(bool enable);
    void enable_python_cli(bool enable);
}

%pythoncode %{
#<pycode(py_idaapi)>
import struct
# -----------------------------------------------------------------------
# Seek constants
SEEK_SET = 0 # from the file start
SEEK_CUR = 1 # from the current position
SEEK_END = 2 # from the file end

# -----------------------------------------------------------------------
# This is a special helper object that helps detect which kind
# of object is this python object wrapping and how to convert it
# back and from IDC.
# This object is characterized by its special attribute and its value
class PyIdc_cvt_helper__(object):
    def __init__(self, cvt_id, value):
        # 0 = int64 object
        # 1 = byref object
        # 2 = opaque object
        self.__idc_cvt_id__ = cvt_id
        self.value = value

    def __set_value(self, v):
        self.__idc_cvt_value__ = v
    def __get_value(self):
        return self.__idc_cvt_value__
    value = property(__get_value, __set_value)

# -----------------------------------------------------------------------
class PyIdc_cvt_int64__(PyIdc_cvt_helper__):
    """Helper class for explicitly representing VT_INT64 values"""
    def __init__(self, v):
        # id = 0 = int64 object
        super(self.__class__, self).__init__(0, v)

    # operation table
    op_table = \
    {
        0: lambda a, b: a + b,
        1: lambda a, b: a - b,
        2: lambda a, b: a * b,
        3: lambda a, b: a / b
    }
    # carries the operation given its number
    def op(self, op_n, other, rev=False):
        a = self.value
        # other operand of same type? then take its value field
        if type(other) == type(self):
            b = other.value
        else:
            b = other
        if rev:
            t = a
            a = b
            b = t
        # construct a new object and return as the result
        return self.__class__(self.op_table[op_n](a, b))

    # overloaded operators
    def __add__(self, other):  return self.op(0, other)
    def __sub__(self, other):  return self.op(1, other)
    def __mul__(self, other):  return self.op(2, other)
    def __div__(self, other):  return self.op(3, other)
    def __radd__(self, other): return self.op(0, other, True)
    def __rsub__(self, other): return self.op(1, other, True)
    def __rmul__(self, other): return self.op(2, other, True)
    def __rdiv__(self, other): return self.op(3, other, True)

# -----------------------------------------------------------------------
class PyIdc_cvt_refclass__(PyIdc_cvt_helper__):
    """Helper class for representing references to immutable objects"""
    def __init__(self, v):
        # id = one = byref object
        super(self.__class__, self).__init__(1, v)

    def cstr(self):
        return as_cstr(self.value)

# -----------------------------------------------------------------------
# This object can be passed to IDC and back to Python transparently
# The attribute "__idc_cvt_value__" is used
class PyIdc_cvt_opaque__(PyIdc_cvt_helper__):
    def __init__(self, v):
        # id = two = opaque object
        super(self.__class__, self).__init__(2, v)

# -----------------------------------------------------------------------
def as_cstr(val):
    """
    Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref())
    It scans for the first \x00 and returns the string value up to that point.
    """
    if isinstance(val, PyIdc_cvt_refclass__):
        val = val.value
    n = 0
    for x in val:
        if ord(x) == 0:
            break
        n = n + 1
    return val[:n]

# -----------------------------------------------------------------------
def as_unicode(s):
    """Convenience function to convert a string into appropriate unicode format"""
    # use UTF16 big/little endian, depending on the environment?
    return unicode(s).encode("UTF-16" + ("BE" if _idaapi.cvar.inf.mf else "LE"))

# -----------------------------------------------------------------------
def as_uint32(v):
    return v & 0xffffffff

# -----------------------------------------------------------------------
def as_int32(v):
    return -((~v & 0xffffffff)+1)

# -----------------------------------------------------------------------
def as_signed(v, nbits = 32):
    return -(( ~v & ((1 << nbits)-1) ) + 1) if v & (1 << nbits-1) else v

# ----------------------------------------------------------------------
# Copy bits from a value
def copy_bits(b, s, e=-1):
    # end-bit not specified? use start bit (thus extract one bit)
    if e == -1:
        e = s
    # swap start and end if start > end
    if s > e:
        e, s = s, e

    mask = 0
    for i in xrange(s, e+1):
        mask |= 1 << i

    return (b & mask) >> s

# ----------------------------------------------------------------------
struct_unpack_table = {
  1: ('b', 'B'),
  2: ('h', 'H'),
  4: ('l', 'L'),
  8: ('q', 'Q')
}

# ----------------------------------------------------------------------
def struct_unpack(value, signed = False, offs = 0):
    """
    Unpack a value given its length and offset using struct.unpack_from().
    This function will know how to unpack the given value by using the lookup table 'struct_unpack_table'
    """
    # Supported length?
    n = len(value)
    if not n in struct_unpack_table:
        return None
    # Conver to number
    signed = 1 if signed else 0

    # Unpack
    return struct.unpack_from(struct_unpack_table[n][signed], value, offs)[0]



#</pycode(py_idaapi)>

%}