#ifndef __PYCVT__
#define __PYCVT__

//<code(py_idaapi)>

//------------------------------------------------------------------------
// String constants used
static const char S_PY_IDCCVT_VALUE_ATTR[]   = "__idc_cvt_value__";
static const char S_PY_IDCCVT_ID_ATTR[]      = "__idc_cvt_id__";
static const char S_PY_IDC_OPAQUE_T[]        = "py_idc_cvt_helper_t";
static const char S_PY_IDC_GLOBAL_VAR_FMT[]  = "__py_cvt_gvar_%d";

// Constants used by get_idaapi_class_reference()
#define PY_CLSID_CVT_INT64                       0
#define PY_CLSID_APPCALL_SKEL_OBJ                1
#define PY_CLSID_CVT_BYREF                       2
#define PY_CLSID_LAST                            3

//---------------------------------------------------------------------------
// Use these macros to define script<->C fields
#define DEFINE_SCFIELDX(name, type, is_opt) { #name, type, qoffsetof(CUR_STRUC, name), is_opt }
#define DEFINE_SCFIELD(name, type) DEFINE_SCFIELDX(name, type, 0)
#define DEFINE_SCFIELD_OPT(name, type) DEFINE_SCFIELDX(name, type, 1)

//---------------------------------------------------------------------------
enum scfield_types_t
{
  // Numeric fields
  FT_FIRST_NUM,
  FT_INT,
  FT_SIZET,
  FT_SSIZET,
  FT_NUM16,
  FT_NUM32,
  FT_LAST_NUM,
  // String field
  FT_STR,
  FT_CHAR,
  // Object fields
  FT_ARR,
  // Allocated array of strings
  FT_STRARR,
  // Allocated array of 16bit numbers
  FT_NUM16ARR,
  // Fixed size character array. The size must be passed in the definition
  FT_CHRARR_STATIC,
};

//---------------------------------------------------------------------------
struct scfld_t
{
  const char *field_name;
  uint32 field_type;
  size_t field_offs;
  bool is_optional;
};

#define FT_VALUE_MASK        0xFFFF0000
// Possible return values of conversion functions
#define FT_NOT_FOUND         -1
#define FT_BAD_TYPE          -2
#define FT_OK                1

//-----------------------------------------------------------------------
class pycvt_t
{
  struct attr_t
  {
    qstring str;
    uint64 u64;
    // User is responsible to release this attribute when done
    PyObject *py_obj;
  };

  //-----------------------------------------------------------------------
  static int get_attr(
    PyObject *py_obj,
    const char *attrname,
    int ft,
    attr_t &val)
  {
    PyObject *py_attr;
    if ( (py_attr = PyW_TryGetAttrString(py_obj, attrname)) == NULL )
      return FT_NOT_FOUND;

    int cvt = FT_OK;
    if ( ft == FT_STR || ft == FT_CHAR && PyString_Check(py_attr) )
      val.str = PyString_AsString(py_attr);
    else if ( (ft > FT_FIRST_NUM && ft < FT_LAST_NUM) && PyW_GetNumber(py_attr, &val.u64) )
      ; // nothing to be done
    // A string array?
    else if ( (ft == FT_STRARR || ft == FT_NUM16ARR || ft == FT_CHRARR_STATIC )
      && (PyList_CheckExact(py_attr) || PyW_IsSequenceType(py_attr)) )
    {
      // Return a reference to the attribute
      val.py_obj = py_attr;
      // Do not decrement the reference to this attribute
      py_attr = NULL;
    }
    else
      cvt = FT_BAD_TYPE;
    Py_XDECREF(py_attr);
    return cvt;
  }

  //-----------------------------------------------------------------------
  static int idaapi make_str_list_cb(
    PyObject *py_item,
    Py_ssize_t index,
    void *ud)
  {
    if ( !PyString_Check(py_item) )
      return CIP_FAILED;
    char **a = (char **)ud;
    a[index] = qstrdup(PyString_AsString(py_item));
    return CIP_OK;
  }

  //-----------------------------------------------------------------------
  // Converts an IDC list of strings to a C string list
  static Py_ssize_t str_list_to_str_arr(
    PyObject *py_list,
    char ***arr)
  {
    // Take the size
    Py_ssize_t size = pyvar_walk_list(py_list);

    // Allocate a buffer
    char **a = (char **)qalloc((size + 1) * sizeof(char *));

    // Walk and populate
    size = pyvar_walk_list(py_list, make_str_list_cb, a);

    // Make the list NULL terminated
    a[size] = NULL;

    // Return the list to the user
    *arr = a;

    // Return the size of items processed
    return size;
  }

  //-----------------------------------------------------------------------
  typedef qvector<uint64> uint64vec_t;
  static int idaapi make_int_list(
    PyObject *py_item,
    Py_ssize_t /*index*/,
    void *ud)
  {
    uint64 val;
    if ( !PyW_GetNumber(py_item, &val) )
      return CIP_FAILED;
    uint64vec_t *vec = (uint64vec_t *)ud;
    vec->push_back(val);
    return CIP_OK;
  }

public:
  //-----------------------------------------------------------------------
  // Frees a NULL terminated list of fields
  static void free_fields(
    const scfld_t *fields,
    void *store_area)
  {
    for ( int i=0; ; i++ )
    {
      // End of list?
      const scfld_t &fd = fields[i];
      if ( fd.field_name == NULL )
        break;

      void *store = (void *)((char *)store_area + fd.field_offs);
      int ft = fd.field_type & ~FT_VALUE_MASK;
      switch ( ft )
      {
      case FT_STR:      // Simple string
        {
          char **s = (char **)store;
          if ( *s != NULL )
          {
            qfree(*s);
            *s = NULL;
          }
        }
        break;

      case FT_STRARR:   // Array of strings
        {
          char ***op = (char ***)store, **p = *op;
          while ( *p != NULL )
            qfree((void *)*p++);
          qfree(*op);
          *op = NULL;
        }
        break;

      case FT_NUM16ARR:
        {
          uint16 **arr = (uint16 **)store;
          if ( *arr != NULL )
          {
            qfree(*arr);
            *arr = NULL;
          }
        }
        break;
      }
    }
  }

  //-----------------------------------------------------------------------
  // Converts from a C structure to Python
  static int from_c(
    const scfld_t *fields,
    void *read_area,
    PyObject *py_obj)
  {
    PyObject *py_attr;
    int i;
    bool ok = false;
    for ( i=0; ; i++ )
    {
      // End of list?
      const scfld_t &fd = fields[i];
      if ( fd.field_name == NULL )
      {
        ok = true;
        break;
      }

      // Point to structure member
      int ft = fd.field_type & ~FT_VALUE_MASK;
      void *read = (void *)((char *)read_area + fd.field_offs);
      // Create the python attribute properly
      if ( ft > FT_FIRST_NUM && ft < FT_LAST_NUM )
      {
        if ( ft == FT_NUM16 )
          py_attr = Py_BuildValue("H", *(uint16 *)read);
        else if ( ft == FT_NUM32 )
          py_attr = Py_BuildValue("I", *(uint32 *)read);
        else if ( ft == FT_INT )
          py_attr = Py_BuildValue("i", *(int *)read);
        else if ( ft == FT_SIZET )
          py_attr = Py_BuildValue(PY_FMT64,*(size_t *)read);
        else if ( ft == FT_SSIZET )
          py_attr = Py_BuildValue(PY_SFMT64,*(ssize_t *)read);
      }
      else if ( ft == FT_STR || ft == FT_CHAR )
      {
        if ( ft == FT_STR )
          py_attr = PyString_FromString(*(char **)read);
        else
          py_attr = Py_BuildValue("c", *(char *)read);
      }
      else if ( ft == FT_STRARR )
      {
        char **arr = *(char ***)read;
        py_attr = PyList_New(0);
        while ( *arr != NULL )
          PyList_Append(py_attr, PyString_FromString(*arr++));
      }
      else
        continue;
      PyObject_SetAttrString(py_obj, fd.field_name, py_attr);
      Py_XDECREF(py_attr);
    }
    return ok ? -1 : i;
  }

  //-----------------------------------------------------------------------
  // Converts fields from IDC and field description into a C structure
  // If 'use_extlang' is specified, then the passed idc_obj is considered
  // to be an opaque object and thus can be queried only through extlang
  static int from_script(
    const scfld_t *fields,
    void *store_area,
    PyObject *py_obj)
  {
    int i;
    bool ok = false;
    attr_t attr;
    for ( i=0; ; i++ )
    {
      // End of list?
      const scfld_t &fd = fields[i];
      if ( fd.field_name == NULL )
      {
        ok = true;
        break;
      }

      // Get field type
      int ft = fd.field_type & ~FT_VALUE_MASK;

      // Point to structure member
      void *store = (void *)((char *)store_area + fd.field_offs);

      // Retrieve attribute and type
      int cvt = get_attr(py_obj, fd.field_name, ft, attr);

      // Attribute not found?
      if ( cvt == FT_NOT_FOUND )
      {
        // Skip optional fields
        if ( fd.is_optional )
          continue;
        break;
      }

      if ( ft == FT_STR )
        *(char **)store = qstrdup(attr.str.c_str());
      else if ( ft == FT_NUM32 )
        *(uint32 *)store = uint32(attr.u64);
      else if ( ft == FT_NUM16 )
        *(uint16 *)store = attr.u64 & 0xffff;
      else if ( ft == FT_INT )
        *(int *)store = int(attr.u64);
      else if ( ft == FT_SIZET )
        *(size_t *)store = size_t(attr.u64);
      else if ( ft == FT_SSIZET )
        *(ssize_t *)store = ssize_t(attr.u64);
      else if ( ft == FT_CHAR )
        *(char *)store = *attr.str.c_str();
      else if ( ft == FT_STRARR )
      {
        str_list_to_str_arr(attr.py_obj, (char ***)store);
        Py_DECREF(attr.py_obj);
      }
      else if ( ft == FT_CHRARR_STATIC )
      {
        size_t sz = (fd.field_type & FT_VALUE_MASK) >> 16;
        if ( sz == 0 )
          break;
        uint64vec_t w;
        char *a = (char *) store;
        if ( pyvar_walk_list(attr.py_obj, make_int_list, &w) )
        {
          sz = qmin(w.size(), sz);
          for ( size_t i=0; i < sz; i++ )
            a[i] = w[i] & 0xFF;
        }
      }
      else if ( ft == FT_NUM16ARR )
      {
        uint64vec_t w;
        if ( pyvar_walk_list(attr.py_obj, make_int_list, &w) > 0 )
        {
          size_t max_sz = (fd.field_type & FT_VALUE_MASK) >> 16;
          bool zero_term;
          if ( max_sz == 0 )
          {
            zero_term = true;
            max_sz = w.size();
          }
          else
          {
            zero_term = false;
            max_sz = qmin(max_sz, w.size());
          }
          // Allocate as much as we parsed elements
          // Add one more element if list was zero terminated
          uint16 *a = (uint16 *)qalloc(sizeof(uint16) * (max_sz + (zero_term ? 1 : 0))) ;
          for ( size_t i=0; i < max_sz; i++ )
            a[i] = w[i] & 0xFF;

          if ( zero_term )
            a[max_sz] = 0;
          *(uint16 **)store = a;
        }
      }
      else
      {
        // Unsupported field type!
        break;
      }
    }
    return ok ? -1 : i;
  }
};

//-------------------------------------------------------------------------
Py_ssize_t pyvar_walk_list(
  PyObject *py_list,
  int (idaapi *cb)(PyObject *py_item, Py_ssize_t index, void *ud),
  void *ud)
{
  if ( !PyList_CheckExact(py_list) && !PyW_IsSequenceType(py_list) )
    return CIP_FAILED;

  bool is_seq = !PyList_CheckExact(py_list);
  Py_ssize_t size = is_seq ? PySequence_Size(py_list) : PyList_Size(py_list);

  if ( cb == NULL )
    return size;

  Py_ssize_t i;
  for ( i=0; i<size; i++ )
  {
    // Get the item
    PyObject *py_item = is_seq ? PySequence_GetItem(py_list, i) : PyList_GetItem(py_list, i);
    if ( py_item == NULL )
      break;

    int r = cb(py_item, i, ud);

    // Decrement reference (if needed)
    if ( r != CIP_OK_NODECREF && is_seq )
        Py_DECREF(py_item); // Only sequences require us to decrement the reference
    if ( r < CIP_OK )
      break;
  }
  return i;
}

//---------------------------------------------------------------------------
PyObject *PyW_IntVecToPyList(const intvec_t &intvec)
{
  size_t c = intvec.size();
  PyObject *py_list = PyList_New(c);

  for ( size_t i=0; i<c; i++ )
    PyList_SetItem(py_list, i, PyInt_FromLong(intvec[i]));

  return py_list;
}

//---------------------------------------------------------------------------
static int idaapi pylist_to_intvec_cb(
    PyObject *py_item,
    Py_ssize_t /*index*/,
    void *ud)
{
  intvec_t &intvec = *(intvec_t *)ud;
  uint64 num;
  if (!PyW_GetNumber(py_item, &num))
    num = 0;

  intvec.push_back(int(num));
  return CIP_OK;
}

//---------------------------------------------------------------------------
bool PyW_PyListToIntVec(PyObject *py_list, intvec_t &intvec)
{
  intvec.clear();
  return pyvar_walk_list(py_list, pylist_to_intvec_cb, &intvec) != CIP_FAILED;
}

//---------------------------------------------------------------------------
static int idaapi pylist_to_strvec_cb(
  PyObject *py_item,
  Py_ssize_t /*index*/,
  void *ud)
{
  qstrvec_t &strvec = *(qstrvec_t *)ud;
  const char *s;
  if ( !PyString_Check(py_item) )
    s = "";
  else
    s = PyString_AsString(py_item);

  strvec.push_back(s);
  return CIP_OK;
}

//---------------------------------------------------------------------------
bool PyW_PyListToStrVec(PyObject *py_list, qstrvec_t &strvec)
{
  strvec.clear();
  return pyvar_walk_list(py_list, pylist_to_strvec_cb, &strvec) != CIP_FAILED;
}

//-------------------------------------------------------------------------
// Checks if the given py_var is a special PyIdc_cvt_helper object.
// It does that by examining the magic attribute and returns its numeric value.
// It returns -1 if the object is not a recognized helper object.
// Any Python object can be treated as an cvt object if this attribute is created.
static int get_pyidc_cvt_type(PyObject *py_var)
{
  // Check if this our special by reference object
  PyObject *attr = PyW_TryGetAttrString(py_var, S_PY_IDCCVT_ID_ATTR);
  if ( attr == NULL )
    return -1;

  if ( !(PyInt_Check(attr) || PyLong_Check(attr)) )
  {
    Py_DECREF(attr);
    return -1;
  }
  int r = (int)PyInt_AsLong(attr);
  Py_DECREF(attr);
  return r;
}

//-------------------------------------------------------------------------
// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
bool convert_pyobj_to_idc_exc(PyObject *py_obj, idc_value_t *idc_obj)
{
  int sn = 0;
  if ( pyvar_to_idcvar(py_obj, idc_obj, &sn) < CIP_OK )
  {
    PyErr_SetString(PyExc_ValueError, "Could not convert Python object to IDC object!");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------
static idc_class_t *get_py_idc_cvt_opaque()
{
  return find_idc_class(S_PY_IDC_OPAQUE_T);
}

//-------------------------------------------------------------------------
// Utility function to create opaque / convertible Python <-> IDC variables
// The referred Python variable will have its reference increased
static bool create_py_idc_opaque_obj(PyObject *py_var, idc_value_t *idc_var)
{
  // Create an IDC object of this special helper class
  if ( VarObject(idc_var, get_py_idc_cvt_opaque()) != eOk )
    return false;

  // Store the CVT id
  idc_value_t idc_val;
  idc_val.set_long(PY_ICID_OPAQUE);
  VarSetAttr(idc_var, S_PY_IDCCVT_ID_ATTR, &idc_val);

  // Store the value as a PVOID referencing the given Python object
  idc_val.set_pvoid(py_var);
  VarSetAttr(idc_var, S_PY_IDCCVT_VALUE_ATTR, &idc_val);

  return true;
}

//------------------------------------------------------------------------
// IDC Opaque object destructor: when the IDC object dies we kill the
// opaque Python object along with it
static const char py_idc_cvt_helper_dtor_args[] = { VT_OBJ, 0 };
static error_t idaapi py_idc_opaque_dtor(
  idc_value_t *argv,
  idc_value_t * /*res*/)
{
  // Get the value from the object
  idc_value_t idc_val;
  VarGetAttr(&argv[0], S_PY_IDCCVT_VALUE_ATTR, &idc_val);

  // Extract the Python object reference
  PyObject *py_obj = (PyObject *)idc_val.pvoid;

  // Decrease its reference (and eventually destroy it)
  Py_DECREF(py_obj);

  return eOk;
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
  if ( py_var == NULL || py_var == Py_None )
    idc_var->set_long(0);
  // Numbers?
  else if ( PyW_GetNumberAsIDC(py_var, idc_var) )
    return CIP_OK;
  // String
  else if ( PyString_Check(py_var) )
    idc_var->_set_string(PyString_AsString(py_var), PyString_Size(py_var));
  // Float
  else if ( PyBool_Check(py_var) )
    idc_var->set_long(py_var == Py_True ? 1 : 0);
  // Boolean
  else if ( PyFloat_Check(py_var) )
  {
    double dresult = PyFloat_AsDouble(py_var);
    ieee_realcvt((void *)&dresult, idc_var->e, 3);
    idc_var->vtype = VT_FLOAT;
  }
  // void*
  else if ( PyCObject_Check(py_var) )
    idc_var->set_pvoid(PyCObject_AsVoidPtr(py_var));
  // Is it a Python list?
  else if ( PyList_CheckExact(py_var) || PyW_IsSequenceType(py_var) )
  {
    // Create the object
    VarObject(idc_var);

    // Determine list size and type
    bool is_seq = !PyList_CheckExact(py_var);
    Py_ssize_t size = is_seq ? PySequence_Size(py_var) : PyList_Size(py_var);
    bool ok = true;
    qstring attr_name;

    // Convert each item
    for ( Py_ssize_t i=0; i<size; i++ )
    {
      // Get the item
      PyObject *py_item = is_seq ? PySequence_GetItem(py_var, i) : PyList_GetItem(py_var, i);

      // Convert the item into an IDC variable
      idc_value_t v;
      ok = pyvar_to_idcvar(py_item, &v, gvar_sn) >= CIP_OK;
      if ( ok )
      {
        // Form the attribute name
        PyObject *py_int = PyInt_FromSsize_t(i);
        ok = PyW_ObjectToString(py_int, &attr_name);
        if ( !ok )
          break;
        Py_DECREF(py_int);
        // Store the attribute
        VarSetAttr(idc_var, attr_name.c_str(), &v);
      }
      // Sequences return a new reference for GetItem()
      if ( is_seq )
        Py_DECREF(py_var);
      if ( !ok )
        break;
    }
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Dictionary: we convert to an IDC object
  else if ( PyDict_Check(py_var) )
  {
    // Create an empty IDC object
    VarObject(idc_var);

    // Get the dict.items() list
    PyObject *py_items = PyDict_Items(py_var);

    // Get the size of the list
    qstring key_name;
    bool ok = true;
    Py_ssize_t size = PySequence_Size(py_items);
    for ( Py_ssize_t i=0; i<size; i++ )
    {
      // Get item[i] -> (key, value)
      PyObject *py_item = PyList_GetItem(py_items, i);

      // Extract key/value
      PyObject *key  = PySequence_GetItem(py_item, 0);
      PyObject *val  = PySequence_GetItem(py_item, 1);

      // Get key's string representation
      PyW_ObjectToString(key, &key_name);

      // Convert the attribute into an IDC value
      idc_value_t v;
      ok = pyvar_to_idcvar(val, &v, gvar_sn) >= CIP_OK;
      if ( ok )
      {
        // Store the attribute
        VarSetAttr(idc_var, key_name.c_str(), &v);
      }
      Py_XDECREF(key);
      Py_XDECREF(val);
      if ( !ok )
        break;
    }
    // Decrement attribute reference
    Py_DECREF(py_items);
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Possible function?
  else if ( PyCallable_Check(py_var) )
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
    switch ( cvt_id )
    {
      //
      // INT64
      //
    case PY_ICID_INT64:
      // Get the value attribute
      attr = PyW_TryGetAttrString(py_var, S_PY_IDCCVT_VALUE_ATTR);
      if ( attr == NULL )
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
        if ( gvar_sn == NULL )
          return CIP_FAILED;

        // Get the value attribute
        attr = PyW_TryGetAttrString(py_var, S_PY_IDCCVT_VALUE_ATTR);
        if ( attr == NULL )
          return CIP_FAILED;

        // Create a global variable
        char buf[MAXSTR];
        qsnprintf(buf, sizeof(buf), S_PY_IDC_GLOBAL_VAR_FMT, *gvar_sn);
        idc_value_t *gvar = add_idc_gvar(buf);
        // Convert the python value into the IDC global variable
        bool ok = pyvar_to_idcvar(attr, gvar, gvar_sn) >= CIP_OK;
        if ( ok )
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
        if ( !create_py_idc_opaque_obj(py_var, idc_var) )
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
      if ( py_dir == NULL || !PyList_Check(py_dir) || size == 0 )
      {
        Py_XDECREF(py_dir);
        return CIP_FAILED;
      }
      // Create the IDC object
      VarObject(idc_var);
      for ( Py_ssize_t i=0; i<size; i++ )
      {
        PyObject *item = PyList_GetItem(py_dir, i);
        const char *field_name = PyString_AsString(item);
        if ( field_name == NULL )
          continue;

        size_t len = strlen(field_name);

        // Skip private attributes
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
  switch ( idc_var.vtype )
  {
  case VT_PVOID:
    if ( *py_var == NULL )
      *py_var = PyCObject_FromVoidPtr(idc_var.pvoid, NULL);
    else
      return CIP_IMMUTABLE;
    break;

  case VT_INT64:
    {
      // Recycle?
      if ( *py_var != NULL )
      {
        // Recycling an int64 object?
        int t = get_pyidc_cvt_type(*py_var);
        if ( t != PY_ICID_INT64 )
          return CIP_IMMUTABLE; // Cannot recycle immutable object
        // Update the attribute
        PyObject_SetAttrString(*py_var, S_PY_IDCCVT_VALUE_ATTR, PyLong_FromLongLong(idc_var.i64));
        return CIP_OK;
      }
      PyObject *py_cls = get_idaapi_attr_by_id(PY_CLSID_CVT_INT64);
      if ( py_cls == NULL )
        return CIP_FAILED;
      PYW_GIL_ENSURE;
      *py_var = PyObject_CallFunctionObjArgs(py_cls, PyLong_FromLongLong(idc_var.i64), NULL);
      PYW_GIL_RELEASE;
      Py_DECREF(py_cls);
      if ( PyW_GetError() || *py_var == NULL )
        return CIP_FAILED;
      break;
    }

#if !defined(NO_OBSOLETE_FUNCS) || defined(__EXPR_SRC)
  case VT_STR:
    *py_var = PyString_FromString(idc_var.str);
    break;

#endif
  case VT_STR2:
    if ( *py_var == NULL )
    {
      const qstring &s = idc_var.qstr();
      *py_var = PyString_FromStringAndSize(s.begin(), s.length());
      break;
    }
    else
      return CIP_IMMUTABLE; // Cannot recycle immutable object
  case VT_LONG:
    // Cannot recycle immutable objects
    if ( *py_var != NULL )
      return CIP_IMMUTABLE;
#ifdef __EA64__
    *py_var = PyLong_FromLongLong(idc_var.num);
#else
    *py_var = PyLong_FromLong(idc_var.num);
#endif
    break;
  case VT_FLOAT:
    if ( *py_var == NULL )
    {
      double x;
      if ( ph.realcvt(&x, (uint16 *)idc_var.e, (sizeof(x)/2-1)|010) != 0 )
        INTERR(30160);

      *py_var = PyFloat_FromDouble(x);
      break;
    }
    else
      return CIP_IMMUTABLE;

  case VT_REF:
    {
      if ( *py_var == NULL )
      {
        PyObject *py_cls = get_idaapi_attr_by_id(PY_CLSID_CVT_BYREF);
        if ( py_cls == NULL )
          return CIP_FAILED;

        // Create a byref object with None value. We populate it later
        PYW_GIL_ENSURE;
        *py_var = PyObject_CallFunctionObjArgs(py_cls, Py_None, NULL);
        PYW_GIL_RELEASE;
        Py_DECREF(py_cls);
        if ( PyW_GetError() || *py_var == NULL )
          return CIP_FAILED;
      }
      int t = *py_var == NULL ? -1 : get_pyidc_cvt_type(*py_var);
      if ( t != PY_ICID_BYREF )
        return CIP_FAILED;

      // Dereference
      // (Since we are not using VREF_COPY flag, we can safely const_cast)
      idc_value_t *dref_v = VarDeref(const_cast<idc_value_t *>(&idc_var), VREF_LOOP);
      if ( dref_v == NULL )
        return CIP_FAILED;

      // Can we recycle the object?
      PyObject *new_py_val = PyW_TryGetAttrString(*py_var, S_PY_IDCCVT_VALUE_ATTR);
      if ( new_py_val != NULL )
      {
        // Recycle
        t = idcvar_to_pyvar(*dref_v, &new_py_val);
        Py_XDECREF(new_py_val); // DECREF because of GetAttrStr

        // Success? Nothing more to be done
        if ( t == CIP_OK )
          return CIP_OK;

        // Clear it so we don't recycle it
        new_py_val = NULL;
      }
      // Try to convert (not recycle)
      if ( idcvar_to_pyvar(*dref_v, &new_py_val) != CIP_OK )
        return CIP_FAILED;

      // Update the attribute
      PyObject_SetAttrString(*py_var, S_PY_IDCCVT_VALUE_ATTR, new_py_val);
      Py_DECREF(new_py_val);
      break;
    }

    // Can convert back into a Python object or Python dictionary
    // (Depending if py_var will be recycled and it was a dictionary)
  case VT_OBJ:
    {
      // Check if this IDC object has __cvt_id__ and the __idc_cvt_value__ fields
      idc_value_t idc_val;
      if (    VarGetAttr(&idc_var, S_PY_IDCCVT_ID_ATTR, &idc_val) == eOk
        && VarGetAttr(&idc_var, S_PY_IDCCVT_VALUE_ATTR, &idc_val) == eOk )
      {
        // Extract the object
        *py_var = (PyObject *) idc_val.pvoid;
        return CIP_OK_NODECREF;
      }
      PyObject *obj;
      bool is_dict = false;

      // Need to create a new object?
      if ( *py_var == NULL )
      {
        // Get skeleton class reference
        PyObject *py_cls = get_idaapi_attr_by_id(PY_CLSID_APPCALL_SKEL_OBJ);
        if ( py_cls == NULL )
          return CIP_FAILED;

        // Call constructor
        PYW_GIL_ENSURE;
        obj = PyObject_CallFunctionObjArgs(py_cls, NULL);
        PYW_GIL_RELEASE;
        Py_DECREF(py_cls);
        if ( PyW_GetError() || obj == NULL )
          return CIP_FAILED;
      }
      else
      {
        // Recycle existing variable
        obj = *py_var;
        if ( PyDict_Check(obj) )
          is_dict = true;
      }

      // Walk the IDC attributes and store into python
      for (const char *attr_name = VarFirstAttr(&idc_var);
        attr_name != NULL;
        attr_name = VarNextAttr(&idc_var, attr_name) )
      {
        // Get the attribute
        idc_value_t v;
        VarGetAttr(&idc_var, attr_name, &v, true);

        // Convert attribute to a python value (recursively)
        PyObject *py_attr(NULL);
        int cvt = idcvar_to_pyvar(v, &py_attr);
        if ( cvt <= CIP_IMMUTABLE )
        {
          // Delete the object (if we created it)
          if ( *py_var == NULL )
            Py_DECREF(obj);

          return CIP_FAILED;
        }
        if ( is_dict )
          PyDict_SetItemString(obj, attr_name, py_attr);
        else
          PyObject_SetAttrString(obj, attr_name, py_attr);

        if ( cvt == CIP_OK )
          Py_XDECREF(py_attr);
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

//-------------------------------------------------------------------------
// Converts IDC arguments to Python argument list or just one tuple
// If 'decref' is NULL then 'pargs' will contain one element which is the tuple
bool pyw_convert_idc_args(
  const idc_value_t args[],
  int nargs,
  ppyobject_vec_t &pargs,
  boolvec_t *decref,
  char *errbuf,
  size_t errbufsize)
{
  bool as_tupple = decref == NULL;
  PyObject *py_tuple(NULL);

  pargs.qclear();

  if ( as_tupple )
  {
    py_tuple = PyTuple_New(nargs);
    if ( py_tuple == NULL )
    {
      if ( errbuf != 0 && errbufsize > 0 )
        qstrncpy(errbuf, "Failed to create a new tuple to store arguments!", errbufsize);
      return false;
    }
    // Add the tuple
    pargs.push_back(py_tuple);
  }
  else
  {
    decref->qclear();
  }

  for ( int i=0; i<nargs; i++ )
  {
    PyObject *py_obj(NULL);
    int cvt = idcvar_to_pyvar(args[i], &py_obj);
    if ( cvt < CIP_OK )
    {
      if ( errbuf != 0 && errbufsize > 0 )
        qsnprintf(errbuf, errbufsize, "arg#%d has wrong type %d", i, args[i].vtype);
      return false;
    }

    if ( as_tupple )
    {
      // Opaque object?
      if ( cvt == CIP_OK_NODECREF )
      {
        // Increment reference for opaque objects.
        // (A tupple will steal references of its set items,
        // and for an opaque object we want it to still exist
        // even if the tuple is gone)
        Py_INCREF(py_obj);
      }
      // Save argument
      PyTuple_SetItem(py_tuple, i, py_obj);
    }
    else
    {
      pargs.push_back(py_obj);
      // Do not decrement reference of opaque objects
      decref->push_back(cvt == CIP_OK);
    }
  }
  return true;
}

//-------------------------------------------------------------------------
// Frees arguments returned by pyw_convert_idc_args()
void pyw_free_idc_args(
  ppyobject_vec_t &pargs,
  boolvec_t *decref)
{
  if ( decref == NULL )
  {
    if ( !pargs.empty() )
      Py_XDECREF(pargs[0]);
  }
  else
  {
    // free argument objects
    for ( int i=(int)pargs.size()-1; i>=0; i-- )
    {
      if ( decref->at(i) )
        Py_DECREF(pargs[i]);
    }
    decref->clear();
  }
  pargs.clear();
}

//</code(py_idaapi)>

#endif
