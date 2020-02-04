
#include <pro.h>
#include <ieee.h>

#include <Python.h>

#include "pywraps.hpp"

#undef hook_to_notification_point
#undef unhook_from_notification_point

//lint -esym(843,pywraps_initialized) could be declared const
//lint -esym(843,g_nw) could be declared const
//lint -esym(844,g_nw) could be declared const
//lint -esym(843,g_use_local_python) could be declared const

//------------------------------------------------------------------------
// String constants used
static const char S_PY_IDCCVT_VALUE_ATTR[]   = "__idc_cvt_value__";
static const char S_PY_IDCCVT_ID_ATTR[]      = "__idc_cvt_id__";
static const char S_PY_IDC_GLOBAL_VAR_FMT[]  = "__py_cvt_gvar_%d";
#define S_PY_IDC_OPAQUE_T "py_idc_cvt_helper_t"

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

static ref_t get_idaapi_attr_by_id(const int class_id);
static ref_t get_idaapi_attr(const char *attr);

//---------------------------------------------------------------------------
ref_t ida_export PyW_SizeVecToPyList(const sizevec_t &vec)
{
  size_t n = vec.size();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_list(PyList_New(n));
  for ( size_t i = 0; i < n; ++i )
  {
#ifdef PY3
    PyList_SetItem(py_list.o, i, PyLong_FromSize_t(vec[i]));
#else
    PyList_SetItem(py_list.o, i, PyInt_FromSize_t(vec[i]));
#endif
  }
  return ref_t(py_list);
}

//---------------------------------------------------------------------------
ref_t ida_export PyW_UvalVecToPyList(const uvalvec_t &vec)
{
  size_t n = vec.size();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_list(PyList_New(n));
  for ( size_t i = 0; i < n; ++i )
    PyList_SetItem(py_list.o, i, Py_BuildValue(PY_BV_UVAL, bvuval_t(vec[i])));
  return ref_t(py_list);
}

//-------------------------------------------------------------------------
static Py_ssize_t pyvar_walk_list(
        const ref_t &py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud),
        void *ud)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  PyObject *o = py_list.o;
  if ( !PyList_CheckExact(o) && !PyW_IsSequenceType(o) )
  {
    PyErr_SetString(PyExc_ValueError, "Object is not a sequence");
    return CIP_FAILED;
  }

  bool is_seq = !PyList_CheckExact(o);
  Py_ssize_t seqsz = is_seq ? PySequence_Size(o) : PyList_Size(o);
  for ( Py_ssize_t i = 0; i < seqsz; ++i )
  {
    // Get the item
    ref_t py_item;
    if ( is_seq )
      py_item = newref_t(PySequence_GetItem(o, i));
    else
      py_item = borref_t(PyList_GetItem(o, i));
    if ( py_item == NULL || cb(py_item, i, ud) != CIP_OK )
    {
      qstring m;
      m.sprnt("Sequence item #%d cannot be converted", int(i));
      PyErr_SetString(PyExc_ValueError, m.c_str());
      return CIP_FAILED;
    }
  }
  return seqsz;
}

//-------------------------------------------------------------------------
Py_ssize_t ida_export pyvar_walk_list(
        PyObject *py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud),
        void *ud)
{
  borref_t r(py_list);
  return pyvar_walk_list(r, cb, ud);
}

//---------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PyListToSizeVec(sizevec_t *out, PyObject *py_list)
{
  out->clear();
  struct ida_local lambda_t
  {
    static int idaapi cvt(const ref_t &py_item, Py_ssize_t /*i*/, void *ud)
    {
      sizevec_t &vec = *static_cast<sizevec_t *>(ud);
      uint64 num;
      if ( !PyW_GetNumber(py_item.o, &num) )
        return CIP_FAILED;
      vec.push_back(size_t(num));
      return CIP_OK;
    }
  };
  return pyvar_walk_list(py_list, lambda_t::cvt, out);
}

//---------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PyListToEaVec(eavec_t *out, PyObject *py_list)
{
  out->clear();
  struct ida_local lambda_t
  {
    static int idaapi cvt(const ref_t &py_item, Py_ssize_t /*i*/, void *ud)
    {
      eavec_t &eavec = *(eavec_t *) ud;
      ea_t ea = BADADDR;
      {
#ifdef PY3
        if ( PyLong_Check(py_item.o) )
        {
          unsigned long long ull = PyLong_AsUnsignedLongLong(py_item.o);
          if ( ull == -1ULL && PyErr_Occurred() != NULL )
            return CIP_FAILED;
          ea = ea_t(ull);
        }
        else
        {
          return CIP_FAILED;
        }
#else
        if ( IDAPyInt_Check(py_item.o) )
          ea = PyInt_AsUnsignedLongMask(py_item.o);
        else if ( PyLong_Check(py_item.o) )
          ea = ea_t(PyLong_AsUnsignedLongLong(py_item.o));
        else
          return CIP_FAILED;
        if ( PyErr_Occurred() != NULL )
          return CIP_FAILED;
#endif
      }
      eavec.push_back(ea);
      return CIP_OK;
    }
  };
  return pyvar_walk_list(py_list, lambda_t::cvt, out);
}

//---------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PyListToStrVec(qstrvec_t *out, PyObject *py_list)
{
  out->clear();
  struct ida_local lambda_t
  {
    static int idaapi cvt(const ref_t &py_item, Py_ssize_t /*i*/, void *ud)
    {
      qstrvec_t &strvec = *(qstrvec_t *)ud;
      if ( !IDAPyStr_Check(py_item.o) )
        return CIP_FAILED;
      IDAPyStr_AsUTF8(&strvec.push_back(), py_item.o);
      return CIP_OK;
    }
  };
  return pyvar_walk_list(py_list, lambda_t::cvt, out);
}

//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
PyObject *ida_export meminfo_vec_t_to_py(meminfo_vec_t &ranges)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  PyObject *py_list = PyList_New(ranges.size());
  meminfo_vec_t::const_iterator it, it_end(ranges.end());
  Py_ssize_t i = 0;
  for ( it=ranges.begin(); it != it_end; ++it, ++i )
  {
    const memory_info_t &mi = *it;
    // start_ea end_ea name sclass sbase bitness perm
    PyList_SetItem(py_list, i,
      Py_BuildValue("(" PY_BV_EA PY_BV_EA "ss" PY_BV_EA "II)",
        bvea_t(mi.start_ea),
        bvea_t(mi.end_ea),
        mi.name.c_str(),
        mi.sclass.c_str(),
        bvea_t(mi.sbase),
        (unsigned int)(mi.bitness),
        (unsigned int)mi.perm));
  }
  return py_list;
}

//-------------------------------------------------------------------------
static qvector<ref_t> py_compiled_form_vec;

//-------------------------------------------------------------------------
void ida_export PyW_register_compiled_form(PyObject *py_form)
{
  ref_t ref = borref_t(py_form);
  if ( !py_compiled_form_vec.has(ref) )
    py_compiled_form_vec.push_back(ref);
}

//-------------------------------------------------------------------------
void ida_export PyW_unregister_compiled_form(PyObject *py_form)
{
  ref_t ref = borref_t(py_form);
  if ( py_compiled_form_vec.has(ref) )
    py_compiled_form_vec.del(ref);
}

//-------------------------------------------------------------------------
static void free_compiled_form_instances(void)
{
  while ( !py_compiled_form_vec.empty() )
  {
    const ref_t &ref = py_compiled_form_vec[0];
    qstring title;
    if ( !PyW_GetStringAttr(ref.o, "title", &title) )
      title = "<unknown title>";
    msg("WARNING: Form \"%s\" was not Free()d. Force-freeing.\n", title.c_str());
    // Will call 'py_unregister_compiled_form()', and thus trim the vector down.
    newref_t unused(PyObject_CallMethod(ref.o, (char *)"Free", "()"));
  }
}

//-------------------------------------------------------------------------
// Checks if the given py_var is a special PyIdc_cvt_helper object.
// It does that by examining the magic attribute and returns its numeric value.
// It returns -1 if the object is not a recognized helper object.
// Any Python object can be treated as an cvt object if this attribute is created.
static int get_pyidc_cvt_type(PyObject *py_var)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Check if this our special by reference object
  ref_t attr(PyW_TryGetAttrString(py_var, S_PY_IDCCVT_ID_ATTR));
  if ( attr == NULL || !IDAPyIntOrLong_Check(attr.o) )
    return -1;
  return int(IDAPyIntOrLong_AsLong(attr.o));
}

//-------------------------------------------------------------------------
// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
bool ida_export pyvar_to_idcvar_or_error(const ref_t &py_obj, idc_value_t *idc_obj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  int sn = 0;
  bool ok = pyvar_to_idcvar(py_obj, idc_obj, &sn) >= CIP_OK;
  if ( !ok )
    PyErr_SetString(PyExc_ValueError, "Could not convert Python object to IDC object!");
  return ok;
}

//------------------------------------------------------------------------
static idc_class_t *get_py_idc_cvt_opaque()
{
  return find_idc_class(S_PY_IDC_OPAQUE_T);
}

//-------------------------------------------------------------------------
// Utility function to create opaque / convertible Python <-> IDC variables
// The referred Python variable will have its reference increased
static bool wrap_PyObject_ptr(const ref_t &py_var, idc_value_t *idc_var)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Create an IDC object of this special helper class
  if ( idcv_object(idc_var, get_py_idc_cvt_opaque()) != eOk )
    return false;

  // Store the CVT id
  idc_value_t idc_val;
  idc_val.set_long(PY_ICID_OPAQUE);
  set_idcv_attr(idc_var, S_PY_IDCCVT_ID_ATTR, idc_val);

  // Store the value as a PVOID referencing the given Python object
  py_var.incref();
  idc_val.set_pvoid(py_var.o);
  set_idcv_attr(idc_var, S_PY_IDCCVT_VALUE_ATTR, idc_val);

  return true;
}

//------------------------------------------------------------------------
// IDC Opaque object destructor: when the IDC object dies we kill the
// opaque Python object along with it
static error_t idaapi py_idc_opaque_dtor(
        idc_value_t *argv,
        idc_value_t * /*res*/)
{
  // This can be called at plugin registration time, when a
  // 'script_plugin_t' instance is ::free()'d. It is
  // not guaranteed that we have the GIL at that point.
  PYW_GIL_GET;

  // Get the value from the object
  idc_value_t idc_val;
  get_idcv_attr(&idc_val, &argv[0], S_PY_IDCCVT_VALUE_ATTR);

  // Extract the Python object reference
  PyObject *py_obj = (PyObject *)idc_val.pvoid;

  // Decrease its reference (and eventually destroy it)
  {
    uninterruptible_op_t op;
    Py_DECREF(py_obj);
  }
  return eOk;
}
static const char py_idc_cvt_helper_dtor_args[] = { VT_OBJ, 0 };
static const ext_idcfunc_t opaque_dtor_desc =
{
  S_PY_IDC_OPAQUE_T ".dtor_name",
  py_idc_opaque_dtor,
  py_idc_cvt_helper_dtor_args,
  NULL,
  0,
  0
};

//-------------------------------------------------------------------------
// Converts a Python variable into an IDC variable
// This function returns on one CIP_XXXX
int ida_export pyvar_to_idcvar(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // None / NULL
  if ( py_var == NULL || py_var.o == Py_None )
  {
    idc_var->set_long(0);
  }
  // Numbers?
  else if ( PyW_GetNumberAsIDC(py_var.o, idc_var) )
  {
    return CIP_OK;
  }
#ifdef PY3
  else if ( PyBytes_Check(py_var.o) )
  {
    idc_var->_set_string(PyBytes_AsString(py_var.o), PyBytes_Size(py_var.o));
  }
#else
  else if ( IDAPyStr_Check(py_var.o) )
  {
    idc_var->_set_string(IDAPyBytes_AsString(py_var.o), PyString_Size(py_var.o));
  }
#endif
  // Unicode
  else if ( PyUnicode_Check(py_var.o) )
  {
#ifdef PY3
    qstring utf8;
    IDAPyStr_AsUTF8(&utf8, py_var.o);
    idc_var->_set_string(utf8.c_str(), utf8.length());
#else
    newref_t utf8(PyUnicode_AsEncodedString(py_var.o, ENC_UTF8, "strict"));
    return pyvar_to_idcvar1(utf8, idc_var, gvar_sn, visited);
#endif
  }
  // Boolean
  else if ( PyBool_Check(py_var.o) )
  {
    idc_var->set_long(py_var.o == Py_True ? 1 : 0);
  }
  // Float
  else if ( PyFloat_Check(py_var.o) )
  {
    double dresult = PyFloat_AsDouble(py_var.o);
    ieee_realcvt((void *)&dresult, idc_var->e, 3);
    idc_var->vtype = VT_FLOAT;
  }
  // void*
  else if ( PyCapsule_IsValid(py_var.o, VALID_CAPSULE_NAME) )
  {
    idc_var->set_pvoid(PyCapsule_GetPointer(py_var.o, VALID_CAPSULE_NAME));
  }
  // Python list?
  else if ( PyList_CheckExact(py_var.o) || PyW_IsSequenceType(py_var.o) )
  {
    // Create the object
    idcv_object(idc_var);

    // Determine list size and type
    bool is_seq = !PyList_CheckExact(py_var.o);
    Py_ssize_t size = is_seq ? PySequence_Size(py_var.o) : PyList_Size(py_var.o);
    bool ok = true;
    qstring attr_name;

    // Convert each item
    for ( Py_ssize_t i=0; i < size; i++ )
    {
      // Get the item
      ref_t py_item;
      if ( is_seq )
        py_item = newref_t(PySequence_GetItem(py_var.o, i));
      else
        py_item = borref_t(PyList_GetItem(py_var.o, i));

      // Convert the item into an IDC variable
      idc_value_t v;
      ok = pyvar_to_idcvar(py_item, &v, gvar_sn) >= CIP_OK;
      if ( ok )
      {
#ifdef PY3
        newref_t py_int(PyLong_FromSsize_t(i));
#else
        newref_t py_int(PyInt_FromSsize_t(i));
#endif

        // Form the attribute name
        ok = PyW_ObjectToString(py_int.o, &attr_name);
        if ( !ok )
          break;
        // Store the attribute
        set_idcv_attr(idc_var, attr_name.c_str(), v);
      }
      if ( !ok )
        break;
    }
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Dictionary: we convert to an IDC object
  else if ( PyDict_Check(py_var.o) )
  {
    // Create an empty IDC object
    idcv_object(idc_var);

    // Get the dict.items() list
    newref_t py_items(PyDict_Items(py_var.o));

    // Get the size of the list
    qstring key_name;
    bool ok = true;
    Py_ssize_t size = PySequence_Size(py_items.o);
    for ( Py_ssize_t i=0; i < size; i++ )
    {
      // Get item[i] -> (key, value)
      PyObject *py_item = PyList_GetItem(py_items.o, i);

      // Extract key/value
      newref_t key(PySequence_GetItem(py_item, 0));
      newref_t val(PySequence_GetItem(py_item, 1));

      // Get key's string representation
      PyW_ObjectToString(key.o, &key_name);

      // Convert the attribute into an IDC value
      idc_value_t v;
      ok = pyvar_to_idcvar(val, &v, gvar_sn) >= CIP_OK;
      if ( ok )
      {
        // Store the attribute
        set_idcv_attr(idc_var, key_name.c_str(), v);
      }
      if ( !ok )
        break;
    }
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Possible function?
  else if ( PyCallable_Check(py_var.o) )
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
    int cvt_id = get_pyidc_cvt_type(py_var.o);
    switch ( cvt_id )
    {
      //
      // INT64
      //
      case PY_ICID_INT64:
        {
          // Get the value attribute
          ref_t attr(PyW_TryGetAttrString(py_var.o, S_PY_IDCCVT_VALUE_ATTR));
          if ( attr == NULL )
            return false;
          idc_var->set_int64(PyLong_AsLongLong(attr.o));
          return CIP_OK;
        }
      //
      // BYREF
      //
      case PY_ICID_BYREF:
        {
          // BYREF always require this parameter
          if ( gvar_sn == NULL )
            return CIP_FAILED;

          // Get the value attribute
          ref_t attr(PyW_TryGetAttrString(py_var.o, S_PY_IDCCVT_VALUE_ATTR));
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
            create_idcv_ref(idc_var, gvar);
          }
          return ok ? CIP_OK : CIP_FAILED;
        }
      //
      // OPAQUE
      //
      case PY_ICID_OPAQUE:
        if ( !wrap_PyObject_ptr(py_var, idc_var) )
          return CIP_FAILED;
        return CIP_OK_OPAQUE;
      //
      // Other objects
      //
      default:
        // A normal object?
        newref_t py_dir(PyObject_Dir(py_var.o));
        Py_ssize_t size = PyList_Size(py_dir.o);
        if ( py_dir == NULL || !PyList_Check(py_dir.o) || size == 0 )
          return CIP_FAILED;
        // Create the IDC object
        idcv_object(idc_var);
        for ( Py_ssize_t i=0; i < size; i++ )
        {
          borref_t item(PyList_GetItem(py_dir.o, i));
#ifdef PY3
            qstring field_name_buf;
            IDAPyStr_AsUTF8(&field_name_buf, item.o);
            const char *field_name = field_name_buf.begin();
#else
            const char *field_name = IDAPyBytes_AsString(item.o);
#endif
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
          newref_t attr(PyObject_GetAttrString(py_var.o, field_name));
          if ( attr == NULL
            // Convert the attribute into an IDC value
            || pyvar_to_idcvar(attr, &v, gvar_sn) < CIP_OK )
          {
            return CIP_FAILED;
          }

          // Store the attribute
          set_idcv_attr(idc_var, field_name, v);
        }
        break;
    }
  }
  return CIP_OK;
}

//-------------------------------------------------------------------------
inline PyObject *cvt_to_pylong(int32 v)
{
  return PyLong_FromLong(v);
}

inline PyObject *cvt_to_pylong(int64 v)
{
  return PyLong_FromLongLong(v);
}

//-------------------------------------------------------------------------
// Converts an IDC variable to a Python variable
// If py_var points to an existing object then the object will be updated
// If py_var points to an existing immutable object then ZERO is returned
// Returns one of CIP_xxxx. Check pywraps.hpp
int ida_export idcvar_to_pyvar(
        const idc_value_t &idc_var,
        ref_t *py_var,
        uint32 flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  switch ( idc_var.vtype )
  {
    case VT_PVOID:
      if ( *py_var == NULL )
      {
        newref_t nr(PyCapsule_New(idc_var.pvoid, VALID_CAPSULE_NAME, NULL));
        *py_var = nr;
      }
      else
      {
        return CIP_IMMUTABLE;
      }
      break;

    case VT_INT64:
      {
        bool as_pylong = (flags & PYWCVTF_INT64_AS_UNSIGNED_PYLONG) != 0;
        if ( as_pylong )
        {
          QASSERT(30513, *py_var == NULL); // recycling not supported in this case
          *py_var = newref_t(PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG) idc_var.i64));
          return CIP_OK;
        }
        else
        {
          // Recycle?
          if ( *py_var != NULL )
          {
            // Recycling an int64 object?
            int t = get_pyidc_cvt_type(py_var->o);
            if ( t != PY_ICID_INT64 )
              return CIP_IMMUTABLE; // Cannot recycle immutable object
            // Update the attribute
            PyObject_SetAttrString(py_var->o, S_PY_IDCCVT_VALUE_ATTR, PyLong_FromLongLong(idc_var.i64));
            return CIP_OK;
          }
          ref_t py_cls(get_idaapi_attr_by_id(PY_CLSID_CVT_INT64));
          if ( py_cls == NULL )
            return CIP_FAILED;
          *py_var = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, PyLong_FromLongLong(idc_var.i64), NULL));
          if ( PyW_GetError() || *py_var == NULL )
            return CIP_FAILED;
        }
        break;
      }

    case VT_STR:
      if ( *py_var == NULL )
      {
        const qstring &s = idc_var.qstr();
        *py_var = newref_t(IDAPyStr_FromUTF8AndSize(s.begin(), s.length()));
        break;
      }
      else
        return CIP_IMMUTABLE; // Cannot recycle immutable object
    case VT_LONG:
      // Cannot recycle immutable objects
      if ( *py_var != NULL )
        return CIP_IMMUTABLE;
      *py_var = newref_t(cvt_to_pylong(idc_var.num));
      break;
    case VT_FLOAT:
      if ( *py_var == NULL )
      {
        double x;
        if ( ph.realcvt(&x, (uint16 *)idc_var.e, (sizeof(x)/2-1)|010) != 1 )
          INTERR(30160);

        *py_var = newref_t(PyFloat_FromDouble(x));
        break;
      }
      else
        return CIP_IMMUTABLE;

    case VT_REF:
      {
        if ( *py_var == NULL )
        {
          ref_t py_cls(get_idaapi_attr_by_id(PY_CLSID_CVT_BYREF));
          if ( py_cls == NULL )
            return CIP_FAILED;

          // Create a byref object with None value. We populate it later
          *py_var = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, Py_None, NULL));
          if ( PyW_GetError() || *py_var == NULL )
            return CIP_FAILED;
        }
        int t = get_pyidc_cvt_type(py_var->o);
        if ( t != PY_ICID_BYREF )
          return CIP_FAILED;

        // Dereference
        // (Since we are not using VREF_COPY flag, we can safely const_cast)
        idc_value_t *dref_v = deref_idcv(const_cast<idc_value_t *>(&idc_var), VREF_LOOP);
        if ( dref_v == NULL )
          return CIP_FAILED;

        // Can we recycle the object?
        ref_t new_py_val(PyW_TryGetAttrString(py_var->o, S_PY_IDCCVT_VALUE_ATTR));
        if ( new_py_val != NULL )
        {
          // Recycle
          t = idcvar_to_pyvar(*dref_v, &new_py_val);

          // Success? Nothing more to be done
          if ( t == CIP_OK )
            return CIP_OK;

          // Clear it so we don't recycle it
          new_py_val = ref_t();
        }
        // Try to convert (not recycle)
        if ( idcvar_to_pyvar(*dref_v, &new_py_val) != CIP_OK )
          return CIP_FAILED;

        // Update the attribute
        PyObject_SetAttrString(py_var->o, S_PY_IDCCVT_VALUE_ATTR, new_py_val.o);
        break;
      }

      // Can convert back into a Python object or Python dictionary
      // (Depending if py_var will be recycled and it was a dictionary)
    case VT_OBJ:
      {
        // Check if this IDC object has __cvt_id__ and the __idc_cvt_value__ fields
        idc_value_t idc_val;
        if ( get_idcv_attr(&idc_val, &idc_var, S_PY_IDCCVT_ID_ATTR) == eOk
          && get_idcv_attr(&idc_val, &idc_var, S_PY_IDCCVT_VALUE_ATTR) == eOk )
        {
          // Extract the object
          *py_var = borref_t((PyObject *) idc_val.pvoid);
          return CIP_OK_OPAQUE;
        }
        ref_t obj;
        bool is_dict = false;

        // Need to create a new object?
        if ( *py_var == NULL )
        {
          // Get skeleton class reference
          ref_t py_cls(get_idaapi_attr_by_id(PY_CLSID_APPCALL_SKEL_OBJ));
          if ( py_cls == NULL )
            return CIP_FAILED;

          // Call constructor
          obj = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, NULL));
          if ( PyW_GetError() || obj == NULL )
            return CIP_FAILED;
        }
        else
        {
          // Recycle existing variable
          obj = *py_var;
          if ( PyDict_Check(obj.o) )
            is_dict = true;
        }

        // Walk the IDC attributes and store into python
        for ( const char *attr_name = first_idcv_attr(&idc_var);
              attr_name != NULL;
              attr_name = next_idcv_attr(&idc_var, attr_name) )
        {
          // Get the attribute
          idc_value_t v;
          get_idcv_attr(&v, &idc_var, attr_name, true);

          // Convert attribute to a python value (recursively)
          ref_t py_attr;
          int cvt = idcvar_to_pyvar(v, &py_attr);
          if ( cvt <= CIP_IMMUTABLE )
            return CIP_FAILED;
          if ( is_dict )
            PyDict_SetItemString(obj.o, attr_name, py_attr.o);
          else
            PyObject_SetAttrString(obj.o, attr_name, py_attr.o);
        }
        *py_var = obj;
        break;
      }
      // Unhandled type
    default:
      *py_var = ref_t();
      return CIP_FAILED;
  }
  return CIP_OK;
}

//-------------------------------------------------------------------------
// Converts IDC arguments to Python argument list or just one tuple
// If 'decref' is NULL then 'pargs' will contain one element which is the tuple
bool ida_export pyw_convert_idc_args(
        const idc_value_t args[],
        int nargs,
        ref_vec_t &pargs,
        uint32 flags,
        qstring *errbuf)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  ref_t py_tuple;

  pargs.qclear();

  bool as_tuple = (flags & PYWCVTF_AS_TUPLE) != 0;
  if ( as_tuple )
  {
    py_tuple = newref_t(PyTuple_New(nargs));
    if ( py_tuple == NULL )
    {
      if ( errbuf != NULL )
        *errbuf = "Failed to create a new tuple to store arguments!";
      return false;
    }
  }

  for ( int i=0; i < nargs; i++ )
  {
    ref_t py_obj;
    int cvt = idcvar_to_pyvar(args[i], &py_obj, flags);
    if ( cvt < CIP_OK )
    {
      if ( errbuf != NULL )
        errbuf->sprnt("arg#%d has wrong type %d", i, args[i].vtype);
      return false;
    }

    if ( as_tuple )
    {
      // PyTuple_SetItem() steals the reference.
      py_obj.incref();
      QASSERT(30412, PyTuple_SetItem(py_tuple.o, i, py_obj.o) == 0);
    }
    else
    {
      pargs.push_back(py_obj);
    }
  }

  // Add the tuple to the list of args only now. Doing so earlier will
  // cause the py_tuple.o->ob_refcnt to be 2 and not 1, and that will
  // cause 'PyTuple_SetItem()' to fail.
  if ( as_tuple )
    pargs.push_back(py_tuple);

  return true;
}

//------------------------------------------------------------------------
static ref_t ida_idaapi_module;
static ref_t compat_idaapi_module;
static bool pywraps_initialized = false;

#define SWIG_RUNTIME_VERSION "4"

//------------------------------------------------------------------------
// check if we have a file which is known to be executed automatically
// by SWIG or Python runtime
static bool pywraps_check_autoscripts(char *buf, size_t bufsize)
{
  static const char *const exts[] =
  {
    "py",
    "pyc",
    "pyd",
    "pyo",
    "pyw",
  };

  static const char *const fns[] =
  {
    "swig_runtime_data" SWIG_RUNTIME_VERSION,
    "sitecustomize",
    "usercustomize"
  };

  for ( size_t ifn=0; ifn < qnumber(fns); ++ifn )
  {
    // check for a script or module with several possible extensions
    for ( size_t iext=0; iext < qnumber(exts); ++iext )
    {
      qsnprintf(buf, bufsize, "%s.%s", fns[ifn], exts[iext]);
      if ( qfileexist(buf) )
        return true;
    }
    // check for a subdirectory under current directory
    if ( qfileexist(fns[ifn]) )
    {
      qstrncpy(buf, fns[ifn], bufsize);
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------
error_t ida_export PyW_CreateIdcException(idc_value_t *res, const char *msg)
{
  // Create exception object
  idcv_object(res, find_idc_class("exception"));

  // Set the message field
  idc_value_t v;
  v.set_string(msg);
  set_idcv_attr(res, "description", v);

  // Throw exception
  return set_qerrno(eExecThrow);
}

//------------------------------------------------------------------------
// Calls a Python callable encoded in IDC.pvoid member
static error_t idaapi idc_py_invoke0(
        idc_value_t *argv,
        idc_value_t *res)
{
  PYW_GIL_GET;
  PyObject *pyfunc = (PyObject *) argv[0].pvoid;
  newref_t py_result(PyObject_CallFunctionObjArgs(pyfunc, NULL));

  // Report Python error as IDC exception
  qstring err;
  error_t err_code = eOk;
  if ( PyW_GetError(&err) )
    err_code = PyW_CreateIdcException(res, err.c_str());
  return err_code;
}
static const char idc_py_invoke0_args[] = { VT_PVOID, 0 };
static const ext_idcfunc_t idc_py_invoke0_desc =
{
  S_PYINVOKE0, idc_py_invoke0, idc_py_invoke0_args, NULL, 0, 0
};

//------------------------------------------------------------------------
// This function must be called on initialization
static bool init_pywraps()
{
  if ( pywraps_initialized )
    return true;

  // Take a reference to the idaapi python module
  // (We need it to create instances of certain classes)
  if ( ida_idaapi_module == NULL )
  {
    // Take a reference to the module so we can create the needed class instances
    ida_idaapi_module = PyW_TryImportModule(S_PY_IDA_IDAAPI_MODNAME);
    if ( ida_idaapi_module == NULL )
      return false;
  }

  // Register the IDC PyInvoke0 method (helper function for add_idc_hotkey())
  if ( !add_idc_func(idc_py_invoke0_desc) )
    return false;

  // IDC opaque class not registered?
  if ( get_py_idc_cvt_opaque() == NULL )
  {
    // Add the class
    idc_class_t *idc_cvt_opaque = add_idc_class(S_PY_IDC_OPAQUE_T);
    if ( idc_cvt_opaque == NULL )
      return false;

    // Register the dtor function
    if ( !add_idc_func(opaque_dtor_desc) )
      return false;

    // Link the dtor function to the class
    set_idc_dtor(idc_cvt_opaque, opaque_dtor_desc.name);
  }

  pywraps_initialized = true;
  return true;
}

//------------------------------------------------------------------------
// This function must be called on de-initialization
static void deinit_pywraps()
{
  if ( !pywraps_initialized )
    return;

  pywraps_initialized = false;

  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    ida_idaapi_module = ref_t(); // Deref.
  }

  // Unregister the IDC PyInvoke0 method (helper function for add_idc_hotkey())
  del_idc_func(idc_py_invoke0_desc.name);
}

//------------------------------------------------------------------------
// Utility function to create linked class instances
ref_t ida_export create_linked_class_instance(
        const char *modname,
        const char *clsname,
        void *lnk)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_module(PyImport_ImportModule(modname));
  ref_t result;
  if ( py_module != NULL )
  {
    ref_t py_class = PyW_TryGetAttrString(py_module.o, clsname);
    if ( py_class != NULL )
    {
      newref_t py_lnk(PyCapsule_New(lnk, VALID_CAPSULE_NAME, NULL));
      ref_t py_obj = newref_t(PyObject_CallFunctionObjArgs(py_class.o, py_lnk.o, NULL));
      if ( !PyW_GetError() && py_obj != NULL )
        result = py_obj;
    }
  }
  return result;
}

//------------------------------------------------------------------------
// Gets a class type reference in idaapi
// With the class type reference we can create a new instance of that type
// This function takes a reference to the idaapi module and keeps the reference
static ref_t get_idaapi_attr_by_id(const int class_id)
{
  if ( class_id >= PY_CLSID_LAST || ida_idaapi_module == NULL )
    return ref_t();

  // Some class names. The array is parallel with the PY_CLSID_xxx consts
  static const char *class_names[] =
  {
    "PyIdc_cvt_int64__",
    "object_t",
    "PyIdc_cvt_refclass__"
  };
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return newref_t(PyObject_GetAttrString(ida_idaapi_module.o, class_names[class_id]));
}

//------------------------------------------------------------------------
// Gets a class reference by name
static ref_t get_idaapi_attr(const char *attrname)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return ida_idaapi_module == NULL
       ? ref_t()
       : PyW_TryGetAttrString(ida_idaapi_module.o, attrname);
}

//------------------------------------------------------------------------
// Returns a qstring from an object attribute
bool ida_export PyW_GetStringAttr(
        PyObject *py_obj,
        const char *attr_name,
        qstring *str)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_attr(PyW_TryGetAttrString(py_obj, attr_name));
  if ( py_attr == NULL )
    return false;

  bool ok = IDAPyStr_Check(py_attr.o);
  if ( ok )
    *str = IDAPyBytes_AsString(py_attr.o);

  return ok;
}

//------------------------------------------------------------------------
// Returns an attribute or NULL
// No errors will be set if the attribute did not exist
ref_t ida_export PyW_TryGetAttrString(PyObject *py_obj, const char *attr)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t o;
  if ( PyObject_HasAttrString(py_obj, attr) )
    o = newref_t(PyObject_GetAttrString(py_obj, attr));
  return o;
}

//------------------------------------------------------------------------
// Tries to import a module and clears the exception on failure
ref_t ida_export PyW_TryImportModule(const char *name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t result(PyImport_ImportModule(name));
  if ( result == NULL && PyErr_Occurred() )
    PyErr_Clear();
  return result;
}

//-------------------------------------------------------------------------
// Converts a Python number into an IDC value (32 or 64bits)
// The function will try to convert the number into a 32bit value
// If the number does not fit then VT_INT64 will be used
bool ida_export PyW_GetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !(PyLong_CheckExact(py_var)) )
    return false;

  PY_LONG_LONG pyll = PyLong_AsLongLong(py_var);
  if ( PyErr_Occurred() )
    return false;

  bool as_i64 = pyll >= 0
              ? pyll > (PY_LONG_LONG) SVAL_MAX    //-V547 'pyll > (__int64) SVAL_MAX' is always false
              : pyll < (PY_LONG_LONG) SVAL_MIN;   //-V547 is always false
  if ( as_i64 )                                   //-V547 'as_i64' is always false
    idc_var->set_int64(int64(pyll));
  else
    idc_var->set_long(sval_t(pyll));
  return true;
}

//-------------------------------------------------------------------------
// Parses a Python object as a long or long long
bool ida_export PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = true;
#define SETNUM(numexpr, is64_expr)              \
  do                                            \
  {                                             \
    if ( num != NULL )                          \
      *num = numexpr;                           \
    if ( is_64 != NULL )                        \
      *is_64 = is64_expr;                       \
  } while ( false )

  do
  {
    if ( !PyLong_CheckExact(py_var) )
    {
      rc = false;
      break;
    }

    // Can we convert to C long?
    long l = IDAPyInt_AsLong(py_var);
    if ( !PyErr_Occurred() )
    {
      SETNUM(uint64(l), false);
      break;
    }

    // Clear last error
    PyErr_Clear();

    // Can be fit into a C unsigned long?
    unsigned long ul = PyLong_AsUnsignedLong(py_var);
    if ( !PyErr_Occurred() )    //-V547 '!PyErr_Occurred()' is always false
    {
      SETNUM(uint64(ul), false);
      break;
    }
    PyErr_Clear();

    // Try to parse as int64
    PY_LONG_LONG ll = PyLong_AsLongLong(py_var);
    if ( !PyErr_Occurred() )    //-V547 '!PyErr_Occurred()' is always false
    {
      SETNUM(uint64(ll), true);
      break;
    }
    PyErr_Clear();

    // Try to parse as uint64
    unsigned PY_LONG_LONG ull = PyLong_AsUnsignedLongLong(py_var);
    PyObject *err = PyErr_Occurred();
    if ( err == NULL )    //-V547 'err == 0' is always false
    {
      SETNUM(uint64(ull), true);
      break;
    }
    // Negative number? _And_ it with uint64(-1)
    rc = false;
    if ( err == PyExc_TypeError )
    {
      newref_t py_mask(Py_BuildValue("K", 0xFFFFFFFFFFFFFFFFull));
      newref_t py_num(PyNumber_And(py_var, py_mask.o));
      if ( py_num != NULL && py_mask != NULL )
      {
        PyErr_Clear();
        ull = PyLong_AsUnsignedLongLong(py_num.o);
        if ( !PyErr_Occurred() )    //-V547 '!PyErr_Occurred()' is always false
        {
          SETNUM(uint64(ull), true);
          rc = true;
        }
      }
    }
    PyErr_Clear();
  } while ( false );
  return rc;
#undef SETNUM
}

//-------------------------------------------------------------------------
// Checks if a given object is of sequence type
bool ida_export PyW_IsSequenceType(PyObject *obj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = true;
  do
  {
    if ( !PySequence_Check(obj) )
    {
      rc = false;
      break;
    }

    Py_ssize_t sz = PySequence_Size(obj);
    if ( sz == -1 || PyErr_Occurred() != NULL )
    {
      PyErr_Clear();
      rc = false;
      break;
    }
  } while ( false );
  return rc;
}

//-------------------------------------------------------------------------
// Returns the string representation of an object
bool ida_export PyW_ObjectToString(PyObject *obj, qstring *out)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_str(PyObject_Str(obj));
  bool ok = py_str != NULL;
  if ( ok )
    *out = IDAPyBytes_AsString(py_str.o);
  else
    out->qclear();
  return ok;
}

//--------------------------------------------------------------------------
// Checks if a Python error occurred and fills the out parameter with the
// exception string
bool ida_export PyW_GetError(qstring *out, bool clear_err)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( PyErr_Occurred() == NULL )
    return false;

  // Error occurred but details not needed?
  if ( out == NULL )
  {
    // Just clear the error
    if ( clear_err )
      PyErr_Clear();
    return true;
  }

  // Get the exception info
  PyObject *err_type, *err_value, *err_traceback, *py_ret(NULL);
  PyErr_Fetch(&err_type, &err_value, &err_traceback);

  if ( !clear_err )
    PyErr_Restore(err_type, err_value, err_traceback);

  // Resolve FormatExc()
  ref_t py_fmtexc(get_idaapi_attr(S_IDAAPI_FORMATEXC));

  // Helper there?
  if ( py_fmtexc != NULL )
  {
    // Call helper
    py_ret = PyObject_CallFunctionObjArgs(
      py_fmtexc.o,
      err_type,
      err_value,
      err_traceback,
      NULL);
  }

  // Clear the error
  if ( clear_err )
    PyErr_Clear();

  // Helper failed?!
  if ( py_ret == NULL )
  {
    // Just convert the 'value' part of the original error
    py_ret = PyObject_Str(err_value);
  }

  // No exception text?
  if ( py_ret == NULL )
  {
    *out = "IDAPython: unknown error!";
  }
  else
  {
    *out = IDAPyBytes_AsString(py_ret);
    Py_DECREF(py_ret);
  }

  if ( clear_err )
  {
    Py_XDECREF(err_traceback);
    Py_XDECREF(err_value);
    Py_XDECREF(err_type);
  }
  return true;
}

//-------------------------------------------------------------------------
static bool PyW_GetError(char *buf, size_t bufsz, bool clear_err)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstring s;
  if ( !PyW_GetError(&s, clear_err) )
    return false;

  qstrncpy(buf, s.c_str(), bufsz);
  return true;
}

//-------------------------------------------------------------------------
// A loud version of PyGetError() which gets the error and displays it
// This method is used to display errors that occurred in a callback
bool ida_export PyW_ShowCbErr(const char *cb_name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  static qstring err_str;
  if ( !PyW_GetError(&err_str) )
    return false;

  msg("IDAPython: Error while calling Python callback <%s>:\n%s", cb_name, err_str.c_str());
  return true;
}

//---------------------------------------------------------------------------
void *ida_export pyobj_get_clink(PyObject *pyobj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Try to query the link attribute
  ref_t attr(PyW_TryGetAttrString(pyobj, S_CLINK_NAME));
  void *t = attr != NULL && PyCapsule_IsValid(attr.o, VALID_CAPSULE_NAME)
          ? PyCapsule_GetPointer(attr.o, VALID_CAPSULE_NAME)
          : NULL;
  return t;
}

//------------------------------------------------------------------------
ssize_t idaapi pywraps_notify_when_t::idp_callback(void *ud, int event_id, va_list va)
{
  pywraps_notify_when_t *_this = (pywraps_notify_when_t *)ud;
  switch ( event_id )
  {
    case processor_t::ev_newfile:
    case processor_t::ev_oldfile:
      {
        // This hook gets called from the kernel. Ensure we hold the GIL.
        // Note that PYW_GIL_GET appears in each case of the switch, which is to
        // ensure that the GIL is retrieved ONLY when we need it. If PYW_GIL_GET
        // appears outside the switch, it will be executed each time this callback
        // is called, which results in a huge slowdown (at least on mac).
        PYW_GIL_GET;
        int old = event_id == processor_t::ev_oldfile ? 1 : 0;
        char *dbname = va_arg(va, char *);
        _this->notify(NW_OPENIDB_SLOT, old);
      }
      break;
  }
  // event not processed, let other plugins or the processor module handle it
  return 0;
}

//------------------------------------------------------------------------
ssize_t idaapi pywraps_notify_when_t::idb_callback(void *ud, int event_id, va_list va)
{
  pywraps_notify_when_t *_this = (pywraps_notify_when_t *)ud;
  switch ( event_id )
  {
    case idb_event::closebase:
      {
        PYW_GIL_GET;
        _this->notify(NW_CLOSEIDB_SLOT);
      }
      break;
  }
  // event not processed, let other plugins or the processor module handle it
  return 0;
}

//------------------------------------------------------------------------
bool pywraps_notify_when_t::unnotify_when(int when, PyObject *py_callable)
{
  int cnt = 0;
  for ( int slot=0; slot < NW_EVENTSCNT; slot++ )
  {
    // convert index to flag and see
    if ( ((1 << slot) & when) != 0 )
    {
      unregister_callback(slot, py_callable);
      ++cnt;
    }
  }
  return cnt > 0;
}

//------------------------------------------------------------------------
void pywraps_notify_when_t::register_callback(int slot, PyObject *py_callable)
{
  borref_t callable_ref(py_callable);
  ref_vec_t &tbl = table[slot];
  ref_vec_t::iterator it_end = tbl.end(), it = std::find(tbl.begin(), it_end, callable_ref);

  // Already added
  if ( it != it_end )
    return;

  // Insert the element
  tbl.push_back(callable_ref);
}

//------------------------------------------------------------------------
void pywraps_notify_when_t::unregister_callback(int slot, PyObject *py_callable)
{
  borref_t callable_ref(py_callable);
  ref_vec_t &tbl = table[slot];
  ref_vec_t::iterator it_end = tbl.end(), it = std::find(tbl.begin(), it_end, callable_ref);

  // Not found?
  if ( it == it_end )
    return;

  // Delete the element
  tbl.erase(it);
}

//------------------------------------------------------------------------
bool pywraps_notify_when_t::init()
{
  return hook_to_notification_point(HT_IDP, idp_callback, this);
  return hook_to_notification_point(HT_IDB, idb_callback, this);
}

//------------------------------------------------------------------------
bool pywraps_notify_when_t::deinit()
{
  // Uninstall all objects
  ref_vec_t::iterator it, it_end;
  for ( int slot=0; slot < NW_EVENTSCNT; slot++ )
  {
    for ( it = table[slot].begin(), it_end = table[slot].end(); it != it_end; ++it )
      unregister_callback(slot, it->o);
  }
  // ...and remove the notification
  bool ok = unhook_from_notification_point(HT_IDP, idp_callback, this);
  return unhook_from_notification_point(HT_IDB, idb_callback, this) && ok;
}

//------------------------------------------------------------------------
bool pywraps_notify_when_t::notify_when(int when, PyObject *py_callable)
{
  // While in notify() do not allow insertion or deletion to happen on the spot
  // Instead we will queue them so that notify() will carry the action when it finishes
  // dispatching the notification handlers
  if ( in_notify )
  {
    notify_when_args_t &args = delayed_notify_when_list.push_back();
    args.when = when;
    args.py_callable = py_callable;
    return true;
  }
  // Uninstalling the notification?
  if ( (when & NW_REMOVE) != 0 )
    return unnotify_when(when & ~NW_REMOVE, py_callable);

  int cnt = 0;
  for ( int slot=0; slot < NW_EVENTSCNT; slot++ )
  {
    // is this flag set?
    if ( ((1 << slot) & when) != 0 )
    {
      register_callback(slot, py_callable);
      ++cnt;
    }
  }
  return cnt > 0;
}

//------------------------------------------------------------------------
bool pywraps_notify_when_t::notify(int slot, ...)
{
  va_list va;
  va_start(va, slot);
  bool ok = notify_va(slot, va);
  va_end(va);
  return ok;
}

//------------------------------------------------------------------------
bool pywraps_notify_when_t::notify_va(int slot, va_list va)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Sanity bounds check!
  if ( slot < 0 || slot >= NW_EVENTSCNT )
    return false;

  bool ok = true;
  in_notify = true;
  int old = slot == NW_OPENIDB_SLOT ? va_arg(va, int) : 0;

  for ( ref_vec_t::iterator it = table[slot].begin(), it_end = table[slot].end();
        it != it_end;
        ++it )
  {
    // Form the notification code
    newref_t py_code(IDAPyInt_FromLong(1 << slot));
    ref_t py_result;
    switch ( slot )
    {
      case NW_CLOSEIDB_SLOT:
      case NW_INITIDA_SLOT:
      case NW_TERMIDA_SLOT:
        {
          py_result = newref_t(PyObject_CallFunctionObjArgs(it->o, py_code.o, NULL));
          break;
        }
      case NW_OPENIDB_SLOT:
        {
          newref_t py_old(IDAPyInt_FromLong(old));
          py_result = newref_t(PyObject_CallFunctionObjArgs(it->o, py_code.o, py_old.o, NULL));
        }
        break;
    }
    if ( PyW_GetError(&err) || py_result == NULL )
    {
      PyErr_Clear();
      warning("notify_when(): Error occurred while notifying object.\n%s", err.c_str());
      ok = false;
    }
  }
  in_notify = false;

  // Process any delayed notify_when() calls that
  if ( !delayed_notify_when_list.empty() )
  {
    notify_when_args_vec_t::iterator it, it_end;
    for ( it = delayed_notify_when_list.begin(), it_end=delayed_notify_when_list.end();
          it != it_end;
          ++it )
    {
      notify_when(it->when, it->py_callable);
    }
    delayed_notify_when_list.qclear();
  }

  return ok;
}

//-------------------------------------------------------------------------
static pywraps_notify_when_t *g_nw = NULL;

//-------------------------------------------------------------------------
bool ida_export add_notify_when(int when, PyObject *py_callable)
{
  return g_nw != NULL && g_nw->notify_when(when, py_callable);
}

//------------------------------------------------------------------------
// Initializes the notify_when mechanism
// (Normally called by IDAPython plugin.init())
static bool pywraps_nw_init()
{
  if ( g_nw != NULL )
    return true;

  g_nw = new pywraps_notify_when_t();
  if ( g_nw->init() )
    return true;

  // Things went bad, undo!
  delete g_nw;
  g_nw = NULL;
  return false;
}

//------------------------------------------------------------------------
static bool pywraps_nw_notify(int slot, ...)
{
  if ( g_nw == NULL )
    return false;

  // Appears to be called from 'driver_notifywhen.cpp', which
  // itself is called from possibly non-python code.
  // I.e., we must acquire the GIL.
  PYW_GIL_GET;
  va_list va;
  va_start(va, slot);
  bool ok = g_nw->notify_va(slot, va);
  va_end(va);

  return ok;
}

//------------------------------------------------------------------------
// Deinitializes the notify_when mechanism
static bool pywraps_nw_term()
{
  if ( g_nw == NULL )
    return true;

  // If could not deinitialize then return w/o stopping nw
  if ( !g_nw->deinit() )
    return false;

  // Cleanup
  delete g_nw;
  g_nw = NULL;
  return true;
}

//-------------------------------------------------------------------------
//                             lookup_info_t
//-------------------------------------------------------------------------
lookup_entry_t &ida_export lookup_info_t_new_entry(lookup_info_t *_this, py_customidamemo_t *py_view)
{
  QASSERT(30454, py_view != NULL && !_this->find_by_py_view(NULL, py_view));
  lookup_entry_t &e = _this->entries.push_back();
  e.py_view = py_view;
  return e;
}

//-------------------------------------------------------------------------
void ida_export lookup_info_t_commit(lookup_info_t *_this, lookup_entry_t &e, TWidget *view)
{
  QASSERT(30455, &e >= _this->entries.begin() && &e < _this->entries.end());
  QASSERT(30456, view != NULL && e.py_view != NULL
          && !_this->find_by_view(NULL, view)
          && _this->find_by_py_view(NULL, e.py_view));
  e.view = view;
}

//-------------------------------------------------------------------------
#define FIND_BY__BODY(self, crit, res)                                  \
  for ( lookup_entries_t::const_iterator it = self->entries.begin(); it != self->entries.end(); ++it ) \
  {                                                                   \
    const lookup_entry_t &e = *it;                                    \
    if ( e.crit == crit )                                             \
    {                                                                 \
      if ( out_##res != NULL )                                        \
        *out_##res = e.res;                                           \
      return true;                                                    \
    }                                                                 \
  }                                                                   \
  return false;                                                       \

bool ida_export lookup_info_t_find_by_py_view(
        const lookup_info_t *_this,
        TWidget **out_view,
        const py_customidamemo_t *py_view)
{
  FIND_BY__BODY(_this, py_view, view);
}

bool ida_export lookup_info_t_find_by_view(
        const lookup_info_t *_this,
        py_customidamemo_t **out_py_view,
        const TWidget *view)
{
  FIND_BY__BODY(_this, view, py_view);
}
#undef FIND_BY__BODY

//-------------------------------------------------------------------------
bool ida_export lookup_info_t_del_by_py_view(
        lookup_info_t *_this,
        const py_customidamemo_t *py_view)
{
  for ( lookup_entries_t::iterator it = _this->entries.begin(); it != _this->entries.end(); ++it )
  {
    if ( it->py_view == py_view )
    {
      _this->entries.erase(it);
      return true;
    }
  }
  return false;
}

//-------------------------------------------------------------------------
lookup_info_t pycim_lookup_info;

//-------------------------------------------------------------------------
//                         py_customidamemo_t
//-------------------------------------------------------------------------
void py_customidamemo_t::convert_node_info(
        node_info_t *out,
        uint32 *out_flags,
        ref_t py_nodeinfo)
{
  if ( out_flags != NULL )
    *out_flags = 0;
#define COPY_PROP(checker, converter, pname, flag)                      \
  do                                                                    \
  {                                                                     \
    newref_t pname(PyObject_GetAttrString(py_nodeinfo.o, #pname));      \
    if ( pname != NULL && checker(pname.o) )                            \
    {                                                                   \
      out->pname = converter(pname.o);                                  \
      if ( out_flags != NULL )                                          \
        *out_flags |= flag;                                             \
    }                                                                   \
  } while ( false )
#define COPY_ULONG_PROP(pname, flag) COPY_PROP(PyNumber_Check, PyLong_AsUnsignedLong, pname, flag)
#define COPY_STRING_PROP(pname, flag) COPY_PROP(IDAPyStr_Check, IDAPyBytes_AsString, pname, flag)
  COPY_ULONG_PROP(bg_color, NIF_BG_COLOR);
  COPY_ULONG_PROP(frame_color, NIF_FRAME_COLOR);
  COPY_ULONG_PROP(flags, NIF_FLAGS);
  COPY_ULONG_PROP(ea, NIF_EA);
  COPY_STRING_PROP(text, NIF_TEXT);
#undef COPY_STRING_PROP
#undef COPY_ULONG_PROP
#undef COPY_PROP
}

//-------------------------------------------------------------------------
void ida_export py_customidamemo_t_set_node_info(
        py_customidamemo_t *_this,
        PyObject *py_node_idx,
        PyObject *py_node_info,
        PyObject *py_flags)
{
  if ( !PyNumber_Check(py_node_idx) || !PyNumber_Check(py_flags) )
    return;
  borref_t py_idx(py_node_idx);
  borref_t py_ni(py_node_info);
  borref_t py_fl(py_flags);
  node_info_t ni;
  _this->convert_node_info(&ni, NULL, py_ni);
  int idx = IDAPyInt_AsLong(py_idx.o);
  uint32 flgs = PyLong_AsLong(py_fl.o);
  viewer_set_node_info(_this->view, idx, ni, flgs);
}

//-------------------------------------------------------------------------
void ida_export py_customidamemo_t_set_nodes_infos(
        py_customidamemo_t *_this,
        PyObject *dict)
{
  if ( !PyDict_Check(dict) )
    return;
  Py_ssize_t pos = 0;
  PyObject *o_key, *o_value;
  while ( PyDict_Next(dict, &pos, &o_key, &o_value) )
  {
    borref_t key(o_key);
    borref_t value(o_value);
    if ( !PyNumber_Check(key.o) )
      continue;
    uint32 flags;
    node_info_t ni;
    _this->convert_node_info(&ni, &flags, value);
    int idx = IDAPyInt_AsLong(key.o);
    viewer_set_node_info(_this->view, idx, ni, flags);
  }
}

//-------------------------------------------------------------------------
PyObject *ida_export py_customidamemo_t_get_node_info(
        py_customidamemo_t *_this,
        PyObject *py_node_idx)
{
  if ( !PyNumber_Check(py_node_idx) )
    Py_RETURN_NONE;
  node_info_t ni;
  if ( !viewer_get_node_info(_this->view, &ni, IDAPyInt_AsLong(py_node_idx)) )
    Py_RETURN_NONE;
  return Py_BuildValue("(kkks)", ni.bg_color, ni.frame_color, ni.ea, ni.text.c_str());
}

//-------------------------------------------------------------------------
void ida_export py_customidamemo_t_del_nodes_infos(
        py_customidamemo_t *_this,
        PyObject *py_nodes)
{
  if ( !PySequence_Check(py_nodes) )
    return;
  Py_ssize_t sz = PySequence_Size(py_nodes);
  for ( Py_ssize_t i = 0; i < sz; ++i )
  {
    newref_t item(PySequence_GetItem(py_nodes, i));
    if ( !PyNumber_Check(item.o) )
      continue;
    int idx = IDAPyInt_AsLong(item.o);
    viewer_del_node_info(_this->view, idx);
  }
}

//-------------------------------------------------------------------------
PyObject *ida_export py_customidamemo_t_get_current_renderer_type(
        py_customidamemo_t *_this)
{
  tcc_renderer_type_t rt = get_view_renderer_type(_this->view);
  return PyLong_FromLong(long(rt));
}

//-------------------------------------------------------------------------
void ida_export py_customidamemo_t_set_current_renderer_type(
        py_customidamemo_t *_this,
        PyObject *py_rto)
{
  tcc_renderer_type_t rt = TCCRT_INVALID;
  borref_t py_rt(py_rto);
  if ( PyNumber_Check(py_rt.o) )
  {
    rt = tcc_renderer_type_t(PyLong_AsLong(py_rt.o));
    set_view_renderer_type(_this->view, rt);
  }
}

//-------------------------------------------------------------------------
PyObject *ida_export py_customidamemo_t_create_groups(
        py_customidamemo_t *_this,
        PyObject *_groups_infos)
{
  if ( !PySequence_Check(_groups_infos) )
    Py_RETURN_NONE;
  borref_t groups_infos(_groups_infos);
  groups_crinfos_t gis;
  Py_ssize_t sz = PySequence_Size(groups_infos.o);
  for ( Py_ssize_t i = 0; i < sz; ++i )
  {
    newref_t item(PySequence_GetItem(groups_infos.o, i));
    if ( !PyDict_Check(item.o) )
      continue;
    borref_t nodes(PyDict_GetItemString(item.o, "nodes"));
    if ( nodes.o == NULL || !PySequence_Check(nodes.o) )
      continue;
    borref_t text(PyDict_GetItemString(item.o, "text"));
    if ( text.o == NULL || !IDAPyStr_Check(text.o) )
      continue;
    group_crinfo_t gi;
    Py_ssize_t nodes_cnt = PySequence_Size(nodes.o);
    for ( Py_ssize_t k = 0; k < nodes_cnt; ++k )
    {
      newref_t node(PySequence_GetItem(nodes.o, k));
      if ( IDAPyInt_Check(node.o) )
        gi.nodes.add_unique(IDAPyInt_AsLong(node.o));
    }
    if ( !gi.nodes.empty() )
    {
      gi.text = IDAPyBytes_AsString(text.o);
      gis.push_back(gi);
    }
  }
  intvec_t groups;
  if ( gis.empty() || !viewer_create_groups(_this->view, &groups, gis) || groups.empty() )
    Py_RETURN_NONE;

  PyObject *py_groups = PyList_New(0);
  for ( intvec_t::const_iterator it = groups.begin(); it != groups.end(); ++it )
    PyList_Append(py_groups, IDAPyInt_FromLong(long(*it)));
  return py_groups;
}

//-------------------------------------------------------------------------
static void pynodes_to_idanodes(intvec_t *idanodes, ref_t pynodes)
{
  Py_ssize_t sz = PySequence_Size(pynodes.o);
  for ( Py_ssize_t i = 0; i < sz; ++i )
  {
    newref_t item(PySequence_GetItem(pynodes.o, i));
    if ( !IDAPyInt_Check(item.o) )
      continue;
    idanodes->add_unique(IDAPyInt_AsLong(item.o));
  }
}

//-------------------------------------------------------------------------
PyObject *ida_export py_customidamemo_t_delete_groups(
        py_customidamemo_t *_this,
        PyObject *_groups,
        PyObject *_new_current)
{
  if ( !PySequence_Check(_groups) || !PyNumber_Check(_new_current) )
    Py_RETURN_NONE;
  borref_t groups(_groups);
  borref_t new_current(_new_current);
  intvec_t ida_groups;
  pynodes_to_idanodes(&ida_groups, groups);
  if ( ida_groups.empty() )
    Py_RETURN_NONE;
  if ( viewer_delete_groups(_this->view, ida_groups, int(IDAPyInt_AsLong(new_current.o))) )
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

//-------------------------------------------------------------------------
PyObject *ida_export py_customidamemo_t_set_groups_visibility(
        py_customidamemo_t *_this,
        PyObject *_groups,
        PyObject *_expand,
        PyObject *_new_current)
{
  if ( !PySequence_Check(_groups)
    || !PyBool_Check(_expand)
    || !PyNumber_Check(_new_current) )
    Py_RETURN_NONE;
  borref_t groups(_groups);
  borref_t expand(_expand);
  borref_t new_current(_new_current);
  intvec_t ida_groups;
  pynodes_to_idanodes(&ida_groups, groups);
  if ( ida_groups.empty() )
    Py_RETURN_NONE;
  if ( viewer_set_groups_visibility(_this->view, ida_groups, expand.o == Py_True, int(IDAPyInt_AsLong(new_current.o))) )
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

//-------------------------------------------------------------------------
bool ida_export py_customidamemo_t_bind(py_customidamemo_t *_this, PyObject *self, TWidget *view)
{
  if ( _this->self != NULL || _this->view != NULL )
    return false;
  PYGLOG("%p: py_customidamemo_t::bind(self=%p, view=%p)\n", _this, _this->self.o, _this->view);
  PYW_GIL_CHECK_LOCKED_SCOPE();

  newref_t py_cobj(PyCapsule_New(_this, VALID_CAPSULE_NAME, NULL));
  PyObject_SetAttrString(self, S_M_THIS, py_cobj.o);

  _this->self = borref_t(self);
  _this->view = view;
  return true;
}

//-------------------------------------------------------------------------
void ida_export py_customidamemo_t_unbind(py_customidamemo_t *_this, bool clear_view)
{
  if ( _this->self == NULL )
    return;
  PYGLOG("%p: py_customidamemo_t::unbind(); self.o=%p, view=%p\n", _this, _this->self.o, _this->view);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_cobj(PyCapsule_New(NULL,VALID_CAPSULE_NAME, NULL));
  PyObject_SetAttrString(_this->self.o, S_M_THIS, py_cobj.o);
  _this->self = newref_t(NULL);
  if ( clear_view )
    _this->view = NULL;
}

//-------------------------------------------------------------------------
void ida_export py_customidamemo_t_collect_class_callbacks_ids(
        py_customidamemo_t *_this,
        pycim_callbacks_ids_t *out)
{
  out->add(S_ON_VIEW_MOUSE_MOVED, _this->GRBASE_HAVE_VIEW_MOUSE_MOVED);
}

//-------------------------------------------------------------------------
bool ida_export py_customidamemo_t_collect_pyobject_callbacks(
        py_customidamemo_t *_this,
        PyObject *o)
{
  pycim_callbacks_ids_t cbids;
  _this->collect_class_callbacks_ids(&cbids);
  _this->cb_flags = 0;
  for ( pycim_callbacks_ids_t::const_iterator it = cbids.begin(); it != cbids.end(); ++it )
  {
    const pycim_callback_id_t &cbid = *it;
    ref_t attr(PyW_TryGetAttrString(o, cbid.name.c_str()));
    int have = cbid.have;
    // Mandatory fields not present?
    if ( (attr == NULL && have <= 0)
         // Mandatory callback fields present but not callable?
      || (attr != NULL && have >= 0 && PyCallable_Check(attr.o) == 0) )
    {
      return false;
    }
    if ( have > 0 && attr != NULL )
      _this->cb_flags |= have;
  }

  return true;
}

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
// A set of tinfo_t & details objects that were created from IDAPython.
// This is necessary in order to clear all the "type details" that are
// associated, in the kernel, with the tinfo_t instances.
//
// Unfortunately the IDAPython plugin has to terminate _after_ the IDB is
// closed, but the "type details" must be cleared _before_ the IDB is closed.
static qvector<tinfo_t*> py_tinfo_t_vec;
static qvector<ptr_type_data_t*> py_ptr_type_data_t_vec;
static qvector<array_type_data_t*> py_array_type_data_t_vec;
static qvector<func_type_data_t*> py_func_type_data_t_vec;
static qvector<udt_type_data_t*> py_udt_type_data_t_vec;

static void __clear(tinfo_t *inst) { inst->clear(); }
static void __clear(ptr_type_data_t *inst) { inst->obj_type.clear(); inst->closure.clear(); }
static void __clear(array_type_data_t *inst) { inst->elem_type.clear(); }
static void __clear(func_type_data_t *inst) { inst->clear(); inst->rettype.clear(); }
static void __clear(udt_type_data_t *inst) { inst->clear(); }

static void til_clear_python_tinfo_t_instances(void)
{
  // Pre-emptive strike: clear all the python-exposed tinfo_t
  // (& related types) instances: if that were not done here,
  // ~tinfo_t() calls happening as part of the python shutdown
  // process will try and clear() their details. ..but the kernel's
  // til-related functions will already have deleted those details
  // at that point.
  //
  // NOTE: Don't clear() the arrays of pointers. All the python-exposed
  // instances will be deleted through the python shutdown/ref-decrementing
  // process anyway (which will cause til_deregister_..() calls), and the
  // entries will be properly pulled out of the vector when that happens.
#define BATCH_CLEAR(Type)                                               \
  do                                                                    \
  {                                                                     \
    for ( size_t i = 0, n = py_##Type##_vec.size(); i < n; ++i )        \
      __clear(py_##Type##_vec[i]);                                      \
  } while ( false )

  BATCH_CLEAR(tinfo_t);
  BATCH_CLEAR(ptr_type_data_t);
  BATCH_CLEAR(array_type_data_t);
  BATCH_CLEAR(func_type_data_t);
  BATCH_CLEAR(udt_type_data_t);
#undef BATCH_CLEAR
}

#define DEF_REG_UNREG_REFCOUNTED(Type)                                  \
  void ida_export til_register_python_##Type##_instance(Type *inst) \
  {                                                                     \
    /* Let's add_unique() it, because in the case of tinfo_t, every reference*/ \
    /* to an object's tinfo_t property will end up trying to register it. */ \
    py_##Type##_vec.add_unique(inst);                                   \
  }                                                                     \
                                                                        \
  void ida_export til_deregister_python_##Type##_instance(Type *inst) \
  {                                                                     \
    qvector<Type*>::iterator found = py_##Type##_vec.find(inst);        \
    if ( found != py_##Type##_vec.end() )                               \
    {                                                                   \
      __clear(inst);                                                    \
      /* tif->clear();*/                                                \
      py_##Type##_vec.erase(found);                                     \
    }                                                                   \
  }

DEF_REG_UNREG_REFCOUNTED(tinfo_t);
DEF_REG_UNREG_REFCOUNTED(ptr_type_data_t);
DEF_REG_UNREG_REFCOUNTED(array_type_data_t);
DEF_REG_UNREG_REFCOUNTED(func_type_data_t);
DEF_REG_UNREG_REFCOUNTED(udt_type_data_t);


//-------------------------------------------------------------------------
//
//---------------------------------------------------------------------------
static qvector<py_timer_ctx_t*> live_timers;
py_timer_ctx_t *ida_export python_timer_new(PyObject *py_callback)
{
  py_timer_ctx_t *t = new py_timer_ctx_t();
  t->pycallback = py_callback;
  Py_INCREF(t->pycallback);
  live_timers.push_back(t);
  return t;
}

//-------------------------------------------------------------------------
void ida_export python_timer_del(py_timer_ctx_t *t)
{
  QASSERT(30491, live_timers.del(t));
  Py_DECREF(t->pycallback);
  delete t;
}

//-------------------------------------------------------------------------
static void clear_python_timer_instances(void)
{
  // Pre-emptive strike: clear all the existing python-exposed
  // timers, or there's a chance IDA will try and execute some
  // python code after IDAPython is removed from memory.
  while ( !live_timers.empty() )
  {
    py_timer_ctx_t *t = live_timers[0];
    unregister_timer(t->timer_id);
    python_timer_del(t);
  }
}

//-------------------------------------------------------------------------
ref_t ida_export try_create_swig_wrapper(ref_t mod, const char *clsname, void *cobj)
{
  qstring wname;
  wname.sprnt("%s__from_ptrval__", clsname);
  ref_t res;
  ref_t py_cls_wrapper_inst(PyW_TryGetAttrString(mod.o, wname.c_str()));
  if ( py_cls_wrapper_inst != NULL )
  {
    uninterruptible_op_t op;
    res = newref_t(PyObject_CallFunction(py_cls_wrapper_inst.o, "(K)", uint64(cobj)));
  }
  return res;
}

//-------------------------------------------------------------------------
ssize_t ida_export get_callable_arg_count(ref_t callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_module(PyImport_ImportModule("inspect"));
  ssize_t cnt = -1;
  if ( py_module != NULL )
  {
    ref_t py_fun = PyW_TryGetAttrString(py_module.o, "getargspec");
    if ( py_fun != NULL )
    {
      newref_t py_tuple(PyObject_CallFunctionObjArgs(py_fun.o, callable.o, NULL));
      if ( PyTuple_Check(py_tuple.o) )
      {
        borref_t py_args(PyTuple_GetItem(py_tuple.o, 0));
        if ( py_args != NULL && PySequence_Check(py_args.o) )
          cnt = PySequence_Length(py_args.o);
      }
    }
  }
  return cnt;
}

//-------------------------------------------------------------------------
typedef qvector<module_callbacks_t> modules_callbacks_t;
static modules_callbacks_t modules_callbacks;
void register_module_lifecycle_callbacks(
        const module_callbacks_t &cbs)
{
  modules_callbacks.push_back(cbs);
}

//-------------------------------------------------------------------------
//                                    hooks
//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
struct hook_data_t
{
  hook_type_t type;
  hook_cb_t *cb;
  void *ud;
};
DECLARE_TYPE_AS_MOVABLE(hook_data_t);
typedef qvector<hook_data_t> hook_data_vec_t;
static hook_data_vec_t hook_data_vec;
#endif // TESTABLE_BUILD

//-------------------------------------------------------------------------
bool ida_export idapython_hook_to_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data)
{
  bool ok = hook_to_notification_point(hook_type, cb, user_data);
#ifdef TESTABLE_BUILD
  if ( ok )
  {
    hook_data_t &hd = hook_data_vec.push_back();
    hd.type = hook_type;
    hd.cb = cb;
    hd.ud = user_data;
  }
#endif // TESTABLE_BUILD
  return ok;
}

//-------------------------------------------------------------------------
bool ida_export idapython_unhook_from_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data)
{
  bool ok = unhook_from_notification_point(hook_type, cb, user_data);
#ifdef TESTABLE_BUILD
  if ( ok )
  {
    bool found = false;
    for ( size_t i = 0, n = hook_data_vec.size(); i < n; ++i )
    {
      const hook_data_t &hd = hook_data_vec[i];
      if ( hd.type == hook_type && hd.cb == cb && hd.ud == user_data )
      {
        hook_data_vec.erase(hook_data_vec.begin() + i);
        found = true;
        break;
      }
    }
    QASSERT(30510, found);
  }
#endif // TESTABLE_BUILD
  return ok;
}

//-------------------------------------------------------------------------
bool ida_export idapython_convert_cli_completions(
        qstrvec_t *out_completions,
        int *out_match_start,
        int *out_match_end,
        ref_t py_res)
{
  bool ok = py_res != NULL
         && PyTuple_Check(py_res.o)
         && PyTuple_Size(py_res.o) == 3;
  if ( ok )
  {
    borref_t i0(PyTuple_GetItem(py_res.o, 0));
    borref_t i1(PyTuple_GetItem(py_res.o, 1));
    borref_t i2(PyTuple_GetItem(py_res.o, 2));
    ok = PyList_Check(i0.o) && IDAPyInt_Check(i1.o) && IDAPyInt_Check(i2.o);
    if ( ok )
    {
      ok = PyW_PyListToStrVec(out_completions, i0.o) > 0;
      if ( ok )
      {
        *out_match_start = IDAPyInt_AsLong(i1.o);
        *out_match_end = IDAPyInt_AsLong(i2.o);
        ok = PyErr_Occurred() == NULL;
      }
      else
      {
        // Clear the error that was set by PyW_PyListToStrVec()
        PyErr_Clear();
      }
    }
  }
  return ok;
}

#undef DEF_REG_UNREG_REFCOUNTED
