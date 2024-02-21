
#include <pro.h>
#include <ieee.h>
#include <parsejson.hpp>

#include <Python.h>

#include "pywraps.hpp"
#include "extapi.hpp"

#undef hook_to_notification_point
#undef unhook_from_notification_point
#undef show_wait_box
#undef hide_wait_box

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
    PyList_SetItem(py_list.o, i, PyLong_FromSize_t(vec[i]));
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
ref_t ida_export PyW_StrVecToPyList(const qstrvec_t &vec)
{
  size_t n = vec.size();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_list(PyList_New(n));
  for ( size_t i = 0; i < n; ++i )
    PyList_SetItem(py_list.o, i, PyUnicode_from_qstring(vec[i]));
  return ref_t(py_list);

}

//-------------------------------------------------------------------------
static Py_ssize_t pyvar_walk_seq(
        const ref_t &py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud),
        void *ud,
        size_t maxsize)
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
  if ( maxsize < seqsz )
    seqsz = maxsize;
  for ( Py_ssize_t i = 0; i < seqsz; ++i )
  {
    // Get the item
    ref_t py_item;
    if ( is_seq )
      py_item = newref_t(PySequence_GetItem(o, i));
    else
      py_item = borref_t(PyList_GetItem(o, i));
    bool ok = py_item && cb(py_item, i, ud) == CIP_OK;
    if ( ok )
    {
      // We cannot have, at the same time, a 'successful conversion', and
      // the Python runtime raising an exception. It's up to the callback
      // implementation to ensure that whatever it did, didn't cause an
      // error to be set.
      QASSERT(30604, PyErr_Occurred() == nullptr);
    }
    else
    {
      if ( PyErr_Occurred() == nullptr )
      {
        qstring m;
        m.sprnt("Sequence item #%d cannot be converted", int(i));
        PyErr_SetString(PyExc_ValueError, m.c_str());
      }
      return CIP_FAILED;
    }
  }
  return seqsz;
}

//-------------------------------------------------------------------------
Py_ssize_t ida_export pyvar_walk_seq(
        PyObject *py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud),
        void *ud,
        size_t maxsize)
{
  borref_t r(py_list);
  return pyvar_walk_seq(r, cb, ud, maxsize);
}

//---------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PySeqToSizeVec(sizevec_t *out, PyObject *py_list, size_t maxsize)
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
  return pyvar_walk_seq(py_list, lambda_t::cvt, out, maxsize);
}

//---------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PySeqToEaVec(
        eavec_t *out,
        PyObject *py_list,
        size_t maxsize)
{
  out->clear();
  struct ida_local lambda_t
  {
    static int idaapi cvt(const ref_t &py_item, Py_ssize_t /*i*/, void *ud)
    {
      eavec_t &eavec = *(eavec_t *) ud;
      ea_t ea = BADADDR;
      {
        if ( PyLong_Check(py_item.o) )
        {
          unsigned long long ull = PyLong_AsUnsignedLongLong(py_item.o);
          if ( ull == -1ULL && PyErr_Occurred() != nullptr )
            return CIP_FAILED;
          ea = ea_t(ull);
        }
        else
        {
          return CIP_FAILED;
        }
      }
      eavec.push_back(ea);
      return CIP_OK;
    }
  };
  return pyvar_walk_seq(py_list, lambda_t::cvt, out, maxsize);
}

//-------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PySeqToTidVec(
        qvector<tid_t> *out,
        PyObject *py_list,
        size_t maxsize)
{
  return PyW_PySeqToEaVec((eavec_t *) out, py_list, maxsize);
}

//-------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PySeqToEa64Vec(ea64vec_t *out, PyObject *py_list, size_t maxsize)
{
  out->clear();
  struct ida_local lambda_t
  {
    static int idaapi cvt(const ref_t &py_item, Py_ssize_t /*i*/, void *ud)
    {
      ea64vec_t &ea64vec = *(ea64vec_t *) ud;
      ea64_t v = 0;
      {
        if ( PyLong_Check(py_item.o) )
        {
          unsigned long long ull = PyLong_AsUnsignedLongLong(py_item.o);
          if ( ull == -1ULL && PyErr_Occurred() != nullptr )
            return CIP_FAILED;
          v = uint64(ull);
        }
        else
        {
          return CIP_FAILED;
        }
      }
      ea64vec.push_back(v);
      return CIP_OK;
    }
  };
  return pyvar_walk_seq(py_list, lambda_t::cvt, out, maxsize);
}

//---------------------------------------------------------------------------
Py_ssize_t ida_export PyW_PySeqToStrVec(qstrvec_t *out, PyObject *py_list, size_t maxsize)
{
  out->clear();
  struct ida_local lambda_t
  {
    static int idaapi cvt(const ref_t &py_item, Py_ssize_t /*i*/, void *ud)
    {
      qstrvec_t &strvec = *(qstrvec_t *)ud;
      if ( !PyUnicode_Check(py_item.o) )
        return CIP_FAILED;
      PyUnicode_as_qstring(&strvec.push_back(), py_item.o);
      return CIP_OK;
    }
  };
  return pyvar_walk_seq(py_list, lambda_t::cvt, out, maxsize);
}

//-------------------------------------------------------------------------
PyObject *ida_export PyW_from_jvalue_t(const jvalue_t &v)
{
  do
  {
    if ( v.type() == JT_UNKNOWN )
      break;
    newref_t json_module(PyImport_ImportModule("json"));
    if ( !json_module )
      break;
    borref_t json_globals(PyModule_GetDict(json_module.o));
    if ( !json_globals )
      break;
    borref_t json_loads(PyDict_GetItemString(json_globals.o, "loads"));
    if ( !json_loads )
      break;
    qstring clob;
    if ( !serialize_json(&clob, v) )
      break;
    ref_t dict = newref_t(PyObject_CallFunction(json_loads.o, "s", clob.c_str()));
    if ( !dict )
      break;
    dict.incref();
    return dict.o;
  } while ( false );

  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
bool ida_export PyW_to_jvalue_t(jvalue_t *out, PyObject *py)
{
  do
  {
    newref_t json_module(PyImport_ImportModule("json"));
    if ( !json_module )
      break;
    borref_t json_globals(PyModule_GetDict(json_module.o));
    if ( !json_globals )
      break;
    borref_t json_dumps(PyDict_GetItemString(json_globals.o, "dumps"));
    if ( !json_dumps )
      break;
    newref_t str(PyObject_CallFunction(json_dumps.o, "O", py));
    qstring buf;
    if ( !PyUnicode_as_qstring(&buf, str.o) )
      break;
    if ( parse_json_string(out, buf.c_str()) != eOk )
      break;
    return true;
  } while ( false );

  return false;
}

//-------------------------------------------------------------------------
PyObject *ida_export PyW_from_jobj_t(const jobj_t &o)
{
  jvalue_t v;
  v.set_obj((jobj_t *) &o);
  PyObject *rc = PyW_from_jvalue_t(v);
  v.extract_obj();
  return rc;
}

//-------------------------------------------------------------------------
bool ida_export PyW_to_jobj_t(jobj_t *out, PyObject *py)
{
  if ( !PyDict_Check(py) )
    return false;
  jvalue_t v;
  bool rc = PyW_to_jvalue_t(&v, py) && v.type() == JT_OBJ;
  if ( rc )
    out->swap(v.obj());
  return rc;
}

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
  int max_nloop = py_compiled_form_vec.size();
  max_nloop *= 10; // i'm feeling generous today
  int cnt = 0;
  while ( !py_compiled_form_vec.empty() )
  {
    const ref_t &ref = py_compiled_form_vec.back();
    qstring title;
    if ( !PyW_GetStringAttr(ref.o, "title", &title) )
      title = "<unknown title>";
    msg("WARNING: Form \"%s\" was not Free()d. Force-freeing.\n", title.c_str());
    // Will call 'py_unregister_compiled_form()', and thus trim the vector down.
    newref_t result(PyObject_CallMethod(ref.o, (char *)"Free", "()"));
    if ( !result && PyErr_Occurred() != nullptr )
    {
      msg("WARNING: Couldn't free form object at %p:\n", ref.o);
      PyErr_Print();
      py_compiled_form_vec.del(ref);
    }
    if ( ++cnt >= max_nloop )
    {
#ifdef TESTABLE_BUILD
      INTERR(30640); // too many iterations, probably we are looping endlessly
#endif
      break;
    }
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
  if ( attr == nullptr || !PyLong_Check(attr.o) )
    return -1;
  return int(PyLong_AsLong(attr.o));
}

//-------------------------------------------------------------------------
static inline bool is_pyidc_cvt_type_int64(PyObject *py_var)
{
  return get_pyidc_cvt_type(py_var) == PY_ICID_INT64;
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
  nullptr,
  0,
  0
};

//-------------------------------------------------------------------------
// Converts a Python variable into an IDC variable
// This function returns on one CIP_XXXX
static int pyvar_to_idcvar1(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn,
        qvector<const PyObject *> &_visited);
static int pyvar_to_idcvar2(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn,
        qvector<const PyObject *> &visited)
{
  if ( !visited.add_unique(py_var.o) )
  {
    qstring buf;
    buf.sprnt("<PyObject-%p-snipped-to-prevent-infinite-recursion>", py_var.o);
    idc_var->_set_string(buf.c_str());
    return CIP_OK;
  }

  // None / nullptr
  if ( py_var == nullptr || py_var.o == Py_None )
  {
    idc_var->set_long(0);
  }
  // Numbers?
  else if ( PyW_GetNumberAsIDC(py_var.o, idc_var) )
  {
    return CIP_OK;
  }
  // String
  else if ( PyBytes_Check(py_var.o) )
  {
    idc_var->_set_string(PyBytes_AsString(py_var.o), PyBytes_Size(py_var.o));
  }
  // Unicode
  else if ( PyUnicode_Check(py_var.o) )
  {
    qstring utf8;
    PyUnicode_as_qstring(&utf8, py_var.o);
    idc_var->_set_string(utf8.c_str(), utf8.length());
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
    ieee_realcvt((void *)&dresult, &idc_var->e, 3);
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
      ok = pyvar_to_idcvar1(py_item, &v, gvar_sn, visited) >= CIP_OK;
      if ( ok )
      {
        // Form the attribute name
        newref_t py_int(PyLong_FromSsize_t(i));
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
      ok = pyvar_to_idcvar1(val, &v, gvar_sn, visited) >= CIP_OK;
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
          if ( attr == nullptr )
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
          if ( gvar_sn == nullptr )
            return CIP_FAILED;

          // Get the value attribute
          ref_t attr(PyW_TryGetAttrString(py_var.o, S_PY_IDCCVT_VALUE_ATTR));
          if ( attr == nullptr )
            return CIP_FAILED;

          // Create a global variable
          char buf[MAXSTR];
          qsnprintf(buf, sizeof(buf), S_PY_IDC_GLOBAL_VAR_FMT, *gvar_sn);
          idc_value_t *gvar = add_idc_gvar(buf);
          // Convert the python value into the IDC global variable
          bool ok = pyvar_to_idcvar1(attr, gvar, gvar_sn, visited) >= CIP_OK;
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
        {
          newref_t py_dir(PyObject_Dir(py_var.o));
          Py_ssize_t size = PyList_Size(py_dir.o);
          if ( !py_dir || !PyList_Check(py_dir.o) || size == 0 )
            return CIP_FAILED;
          // Create the IDC object
          idcv_object(idc_var);
          for ( Py_ssize_t i=0; i < size; i++ )
          {
            borref_t item(PyList_GetItem(py_dir.o, i));
            qstring field_name_buf;
            PyUnicode_as_qstring(&field_name_buf, item.o);
            const char *field_name = field_name_buf.begin();
            if ( field_name == nullptr )
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
            newref_t attr(PyObject_GetAttrString(py_var.o, field_name));
            if ( !attr )
              return CIP_FAILED;
            else if ( pyvar_to_idcvar1(attr, &v, gvar_sn, visited) < CIP_OK )
              return CIP_FAILED;

            // Store the attribute
            set_idcv_attr(idc_var, field_name, v);
          }
        }
        break;
    }
  }
  return CIP_OK;
}

//-------------------------------------------------------------------------
// Converts a Python variable into an IDC variable
// This function returns on one CIP_XXXX
static int pyvar_to_idcvar1(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn,
        qvector<const PyObject *> &_visited)
{
  qvector<const PyObject *> visited = _visited;
  return pyvar_to_idcvar2(py_var, idc_var, gvar_sn, visited);
}

//-------------------------------------------------------------------------
// Converts a Python variable into an IDC variable
// This function returns on one CIP_XXXX
int ida_export pyvar_to_idcvar(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qvector<const PyObject *> visited;
  return pyvar_to_idcvar1(py_var, idc_var, gvar_sn, visited);
}

//-------------------------------------------------------------------------
// helpers to use with idc_value_t::num (which can be 32-, or 64-bit.)
inline PyObject *cvt_to_pylong(int32 v) { return PyLong_FromLong(v); }
inline PyObject *cvt_to_pylong(int64 v) { return PyLong_FromLongLong(v); }

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
      if ( *py_var == nullptr )
      {
        newref_t nr(PyCapsule_New(idc_var.pvoid, VALID_CAPSULE_NAME, nullptr));
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
          QASSERT(30513, *py_var == nullptr); // recycling not supported in this case
          *py_var = newref_t(PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG) idc_var.i64));
          return CIP_OK;
        }
        else
        {
          // Recycle?
          if ( *py_var )
          {
            // Recycling an int64 object?
            if ( !is_pyidc_cvt_type_int64(py_var->o) )
              return CIP_IMMUTABLE; // Cannot recycle immutable object
            // Update the attribute
            PyObject_SetAttrString(py_var->o, S_PY_IDCCVT_VALUE_ATTR, PyLong_FromLongLong(idc_var.i64));
            return CIP_OK;
          }
          ref_t py_cls(get_idaapi_attr_by_id(PY_CLSID_CVT_INT64));
          if ( py_cls == nullptr )
            return CIP_FAILED;
          *py_var = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, PyLong_FromLongLong(idc_var.i64), nullptr));
          if ( PyW_GetError() || !*py_var )
            return CIP_FAILED;
        }
        break;
      }

    case VT_STR:
      if ( *py_var == nullptr )
      {
        const qstring &s = idc_var.qstr();
        if ( (flags & PYWCVTF_STR_AS_BYTES) != 0 )
          *py_var = newref_t(PyBytes_FromStringAndSize(s.begin(), s.length()));
        else
          *py_var = newref_t(PyUnicode_FromStringAndSize(s.begin(), s.length()));
        break;
      }
      else
        return CIP_IMMUTABLE; // Cannot recycle immutable object
    case VT_LONG:
      // Cannot recycle immutable objects
      if ( *py_var )
      {
        // Recycling an int64 object?
        if ( !is_pyidc_cvt_type_int64(py_var->o) )
          return CIP_IMMUTABLE;
        // Update the attribute
        PyObject_SetAttrString(py_var->o, S_PY_IDCCVT_VALUE_ATTR, cvt_to_pylong(idc_var.num));
        return CIP_OK;
      }
      *py_var = newref_t(cvt_to_pylong(idc_var.num));
      break;
    case VT_FLOAT:
      if ( !*py_var )
      {
        double x;
        if ( processor_t::realcvt(&x, (fpvalue_t*)&idc_var.e, (sizeof(x)/2-1)|010) != 1 )
          INTERR(30160);

        *py_var = newref_t(PyFloat_FromDouble(x));
        break;
      }
      else
        return CIP_IMMUTABLE;

    case VT_REF:
      {
        if ( !*py_var )
        {
          ref_t py_cls(get_idaapi_attr_by_id(PY_CLSID_CVT_BYREF));
          if ( py_cls == nullptr )
            return CIP_FAILED;

          // Create a byref object with None value. We populate it later
          *py_var = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, Py_None, nullptr));
          if ( PyW_GetError() || !*py_var )
            return CIP_FAILED;
        }
        int t = get_pyidc_cvt_type(py_var->o);
        if ( t != PY_ICID_BYREF )
          return CIP_FAILED;

        // Dereference
        // (Since we are not using VREF_COPY flag, we can safely const_cast)
        idc_value_t *dref_v = deref_idcv(const_cast<idc_value_t *>(&idc_var), VREF_LOOP);
        if ( dref_v == nullptr )
          return CIP_FAILED;

        // Can we recycle the object?
        ref_t new_py_val(PyW_TryGetAttrString(py_var->o, S_PY_IDCCVT_VALUE_ATTR));
        if ( new_py_val != nullptr )
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
        if ( *py_var == nullptr )
        {
          // Get skeleton class reference
          ref_t py_cls(get_idaapi_attr_by_id(PY_CLSID_APPCALL_SKEL_OBJ));
          if ( py_cls == nullptr )
            return CIP_FAILED;

          // Call constructor
          obj = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, nullptr));
          if ( PyW_GetError() || !obj )
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
              attr_name != nullptr;
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
// If 'decref' is nullptr then 'pargs' will contain one element which is the tuple
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
    if ( py_tuple == nullptr )
    {
      if ( errbuf != nullptr )
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
      if ( errbuf != nullptr )
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
#define SWIG_RUNTIME_DATA "swig_runtime_data" SWIG_RUNTIME_VERSION

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
    SWIG_RUNTIME_DATA,
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
  newref_t py_result(PyObject_CallFunctionObjArgs(pyfunc, nullptr));

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
  S_PYINVOKE0, idc_py_invoke0, idc_py_invoke0_args, nullptr, 0, 0
};

//------------------------------------------------------------------------
// This function must be called on initialization
static bool init_pywraps()
{
  if ( pywraps_initialized )
    return true;

  // Take a reference to the idaapi python module
  // (We need it to create instances of certain classes)
  if ( ida_idaapi_module == nullptr )
  {
    // Take a reference to the module so we can create the needed class instances
    ida_idaapi_module = PyW_TryImportModule(S_PY_IDA_IDAAPI_MODNAME);
    if ( ida_idaapi_module == nullptr )
      return false;
  }

  // Register the IDC PyInvoke0 method (helper function for add_idc_hotkey())
  if ( !add_idc_func(idc_py_invoke0_desc) )
    return false;

  // IDC opaque class not registered?
  if ( get_py_idc_cvt_opaque() == nullptr )
  {
    // Add the class
    idc_class_t *idc_cvt_opaque = add_idc_class(S_PY_IDC_OPAQUE_T);
    if ( idc_cvt_opaque == nullptr )
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
  ref_t result;
  if ( ref_t py_module = newref_t(PyImport_ImportModule(modname)) )
  {
    if ( ref_t py_class = ref_t(PyW_TryGetAttrString(py_module.o, clsname)) )
    {
      newref_t py_lnk(PyCapsule_New(lnk, VALID_CAPSULE_NAME, nullptr));
      ref_t py_obj = newref_t(PyObject_CallFunctionObjArgs(py_class.o, py_lnk.o, nullptr));
      if ( !PyW_GetError() && py_obj )
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
  if ( class_id >= PY_CLSID_LAST || ida_idaapi_module == nullptr )
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
  return ida_idaapi_module == nullptr
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
  if ( py_attr == nullptr )
    return false;
  return PyUnicode_Check(py_attr.o) && PyUnicode_as_qstring(str, py_attr.o);
}

//------------------------------------------------------------------------
// Returns an attribute or nullptr
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
  if ( !result && PyErr_Occurred() != nullptr )
    PyErr_Clear();
  return result;
}

//-------------------------------------------------------------------------
// Converts a Python number into an IDC value (32 or 64bits)
// The function will try to convert the number into a 32bit value
// If the number does not fit then VT_INT64 will be used
bool ida_export PyW_GetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var)
{
  uint64 num;
  bool is_64;
  if ( !PyW_GetNumber(py_var, &num, &is_64) )
    return false;
  if ( is_64 )
    idc_var->set_int64(int64(num));
  else
    idc_var->set_long(sval_t(num));
  return true;
}

//-------------------------------------------------------------------------
// Parses a Python object as a long or long long
CASSERT(sizeof(PY_LONG_LONG) == 8);
bool ida_export PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  uint64 _num = 0;
  bool _is_64 = false;
  if ( num == nullptr )
    num = &_num;
  if ( is_64 == nullptr )
    is_64 = &_is_64;

  *is_64 = false;

  if ( !PyLong_CheckExact(py_var) )
    return false;

  // Try to convert to a signed long long
  PY_LONG_LONG ll = PyLong_AsLongLong(py_var);
  if ( PyErr_Occurred() == nullptr )
  {
    if ( ll < int64(INT_MIN) || ll > int64(INT_MAX) )
      *is_64 = true;
    *num = uint64(ll);
    return true;
  }

  // Not a signed long long. Try unsigned long long
  PyErr_Clear();
  unsigned PY_LONG_LONG ull = PyLong_AsUnsignedLongLong(py_var);
  if ( PyErr_Occurred() == nullptr )
  {
    *is_64 = true;
    *num = uint64(ull);
    return true;
  }

  // Binary AND it with uint64(-1)
  if ( PyErr_Occurred() == PyExc_TypeError )
  {
    PyErr_Clear();
    newref_t py_mask(Py_BuildValue("K", 0xFFFFFFFFFFFFFFFFull));
    newref_t py_num(PyNumber_And(py_var, py_mask.o));
    if ( py_num && py_mask )
    {
      ull = PyLong_AsUnsignedLongLong(py_num.o);
      if ( PyErr_Occurred() == nullptr )    //-V547 'PyErr_Occurred() == nullptr' is always false
      {
        *is_64 = true;
        *num = uint64(ull);
        return true;
      }
    }
  }

  PyErr_Clear();
  return false;
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
    if ( sz == -1 || PyErr_Occurred() != nullptr )
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
  bool ok = py_str;
  if ( ok )
    PyUnicode_as_qstring(out, py_str.o);
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

  if ( PyErr_Occurred() == nullptr )
    return false;

  if ( out != nullptr )
  {
    // Get the exception info (this also clears the exception)
    PyObject *err_type, *err_value, *err_traceback;
    PyErr_Fetch(&err_type, &err_value, &err_traceback);

    // Try helper first
    ref_t py_ret;
    ref_t py_fmtexc(get_idaapi_attr(S_IDAAPI_FORMATEXC));
    if ( py_fmtexc != nullptr )
    {
      py_ret = newref_t(PyObject_CallFunctionObjArgs(
                                py_fmtexc.o,
                                err_type,
                                err_value,
                                err_traceback,
                                nullptr));
    }

    // and fallback to simple stringification if needed
    if ( !py_ret )
      py_ret = newref_t(PyObject_Str(err_value));

    if ( py_ret )
      PyUnicode_as_qstring(out, py_ret.o);
    else
      *out = "IDAPython: unknown error";

    if ( clear_err )
    {
      Py_XDECREF(err_traceback);
      Py_XDECREF(err_value);
      Py_XDECREF(err_type);
    }
    else
    {
      PyErr_Restore(err_type, err_value, err_traceback);
    }
  }
  else
  {
    if ( clear_err )
      PyErr_Clear();
  }

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
  void *t = attr != nullptr && PyCapsule_IsValid(attr.o, VALID_CAPSULE_NAME)
          ? PyCapsule_GetPointer(attr.o, VALID_CAPSULE_NAME)
          : nullptr;
  return t;
}

//-------------------------------------------------------------------------
//                             lookup_info_t
//-------------------------------------------------------------------------
lookup_entry_t &ida_export lookup_info_t_new_entry(lookup_info_t *_this, py_customidamemo_t *py_view)
{
  QASSERT(30454, py_view != nullptr && !_this->find_by_py_view(nullptr, py_view));
  lookup_entry_t &e = _this->entries.push_back();
  e.py_view = py_view;
  return e;
}

//-------------------------------------------------------------------------
void ida_export lookup_info_t_commit(lookup_info_t *_this, lookup_entry_t &e, TWidget *view)
{
  QASSERT(30455, &e >= _this->entries.begin() && &e < _this->entries.end());
  QASSERT(30456, view != nullptr && e.py_view != nullptr
          && !_this->find_by_view(nullptr, view)
          && _this->find_by_py_view(nullptr, e.py_view));
  e.view = view;
}

//-------------------------------------------------------------------------
#define FIND_BY__BODY(self, crit, res)                                \
  for ( lookup_entries_t::const_iterator it = self->entries.begin();  \
        it != self->entries.end();                                    \
        ++it )                                                        \
  {                                                                   \
    const lookup_entry_t &e = *it;                                    \
    if ( e.crit == crit )                                             \
    {                                                                 \
      if ( out_##res != nullptr )                                     \
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
//                         py_customidamemo_t
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
    if ( !nodes || !PySequence_Check(nodes.o) )
      continue;
    borref_t text(PyDict_GetItemString(item.o, "text"));
    if ( !text || !PyUnicode_Check(text.o) )
      continue;
    group_crinfo_t gi;
    Py_ssize_t nodes_cnt = PySequence_Size(nodes.o);
    for ( Py_ssize_t k = 0; k < nodes_cnt; ++k )
    {
      newref_t node(PySequence_GetItem(nodes.o, k));
      if ( PyLong_Check(node.o) )
        gi.nodes.add_unique(PyLong_AsLong(node.o));
    }
    if ( !gi.nodes.empty() )
    {
      PyUnicode_as_qstring(&gi.text, text.o);
      gis.push_back(gi);
    }
  }
  intvec_t groups;
  if ( gis.empty() || !viewer_create_groups(_this->view, &groups, gis) || groups.empty() )
    Py_RETURN_NONE;

  PyObject *py_groups = PyList_New(0);
  for ( intvec_t::const_iterator it = groups.begin(); it != groups.end(); ++it )
    PyList_Append(py_groups, PyLong_FromLong(long(*it)));
  return py_groups;
}

//-------------------------------------------------------------------------
static void pynodes_to_idanodes(intvec_t *idanodes, ref_t pynodes)
{
  Py_ssize_t sz = PySequence_Size(pynodes.o);
  for ( Py_ssize_t i = 0; i < sz; ++i )
  {
    newref_t item(PySequence_GetItem(pynodes.o, i));
    if ( !PyLong_Check(item.o) )
      continue;
    idanodes->add_unique(PyLong_AsLong(item.o));
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
  if ( viewer_delete_groups(_this->view, ida_groups, int(PyLong_AsLong(new_current.o))) )
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
  {
    Py_RETURN_NONE;
  }
  borref_t groups(_groups);
  borref_t expand(_expand);
  borref_t new_current(_new_current);
  intvec_t ida_groups;
  pynodes_to_idanodes(&ida_groups, groups);
  if ( ida_groups.empty() )
    Py_RETURN_NONE;
  if ( viewer_set_groups_visibility(_this->view, ida_groups, expand.o == Py_True, int(PyLong_AsLong(new_current.o))) )
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

//-------------------------------------------------------------------------
bool ida_export py_customidamemo_t_bind(py_customidamemo_t *_this, PyObject *self, TWidget *view)
{
  if ( _this->self != nullptr || _this->view != nullptr )
    return false;
  PYGLOG("%p: py_customidamemo_t::bind(self=%p, view=%p)\n", _this, _this->self.o, _this->view);
  PYW_GIL_CHECK_LOCKED_SCOPE();

  newref_t py_cobj(PyCapsule_New(_this, VALID_CAPSULE_NAME, nullptr));
  PyObject_SetAttrString(self, S_M_THIS, py_cobj.o);

  _this->self = borref_t(self);
  _this->view = view;
  newref_t result(PyObject_CallMethod(self, (char *)"_OnBind", "O", Py_True));

  if ( !result && PyErr_Occurred() != nullptr )
  {
    msg("WARNING: Couldn't bind form object at %p:\n", self);
    PyErr_Print();
  }
  return true;
}

//-------------------------------------------------------------------------
void ida_export py_customidamemo_t_unbind(py_customidamemo_t *_this)
{
  if ( _this->self == nullptr )
    return;
  PYGLOG("%p: py_customidamemo_t::unbind(); self.o=%p, view=%p\n", _this, _this->self.o, _this->view);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t result(PyObject_CallMethod(_this->self.o, (char *)"_OnBind", "O", Py_False));
  if ( !result && PyErr_Occurred() != nullptr )
  {
    msg("WARNING: Couldn't unbind form object at %p:\n", _this->self.o);
    PyErr_Print();
  }

  PyObject_SetAttrString(_this->self.o, S_M_THIS, Py_None);
  _this->self = newref_t(nullptr);
  _this->view = nullptr;
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
    if ( (attr == nullptr && have <= 0)
         // Mandatory callback fields present but not callable?
      || (attr != nullptr && have >= 0 && PyCallable_Check(attr.o) == 0) )
    {
      return false;
    }
    if ( have > 0 && attr != nullptr )
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
  void ida_export til_register_python_##Type##_instance(Type *inst)     \
  {                                                                     \
    /* Let's add_unique() it, because in the case of tinfo_t, every reference*/ \
    /* to an object's tinfo_t property will end up trying to register it. */ \
    py_##Type##_vec.add_unique(inst);                                   \
  }                                                                     \
                                                                        \
  void ida_export til_deregister_python_##Type##_instance(Type *inst)   \
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
  t->pyfunc = borref_t(py_callback);
  live_timers.push_back(t);
  return t;
}

//-------------------------------------------------------------------------
void ida_export python_timer_del(py_timer_ctx_t *t)
{
  QASSERT(30491, live_timers.del(t));
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
  if ( py_cls_wrapper_inst != nullptr )
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
  ssize_t cnt = -1;
  if ( ref_t py_module = newref_t(PyImport_ImportModule("inspect")) )
  {
    if ( ref_t py_fun = ref_t(PyW_TryGetAttrString(py_module.o, "getfullargspec")) )
    {
      newref_t py_tuple(PyObject_CallFunctionObjArgs(py_fun.o, callable.o, nullptr));
      if ( py_tuple && PyTuple_Check(py_tuple.o) )
      {
        borref_t py_args(PyTuple_GetItem(py_tuple.o, 0));
        if ( py_args && PySequence_Check(py_args.o) )
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
struct hook_data_t
{
  hook_type_t type;
  hook_cb_t *cb;
  void *ud;
  bool is_hooks_base;   // FIXME: what is the meaning of this field and where it is used?
};
DECLARE_TYPE_AS_MOVABLE(hook_data_t);
typedef qvector<hook_data_t> hook_data_vec_t;
static hook_data_vec_t hook_data_vec;

//-------------------------------------------------------------------------
void ida_export idapython_register_hook(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data,
        bool is_hooks_base)
{
  hook_data_t &hd = hook_data_vec.push_back();
  hd.type = hook_type;
  hd.cb = cb;
  hd.ud = user_data;
  hd.is_hooks_base = is_hooks_base;
}

//-------------------------------------------------------------------------
void ida_export idapython_unregister_hook(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data)
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
#ifdef TESTABLE_BUILD
  QASSERT(30510, found);
#endif // TESTABLE_BUILD
}

//-------------------------------------------------------------------------
bool ida_export idapython_hook_to_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data,
        bool is_hooks_base)
{
  bool ok = hook_to_notification_point(hook_type, cb, user_data);
  if ( ok )
    idapython_register_hook(hook_type, cb, user_data, is_hooks_base);
  return ok;
}

//-------------------------------------------------------------------------
bool ida_export idapython_unhook_from_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data)
{
  bool ok = unhook_from_notification_point(hook_type, cb, user_data) > 0;
  if ( ok )
    idapython_unregister_hook(hook_type, cb, user_data);
  return ok;
}

//-------------------------------------------------------------------------
bool ida_export idapython_convert_cli_completions(
        qstrvec_t *out_completions,
        int *out_match_start,
        int *out_match_end,
        ref_t py_res)
{
  bool ok = py_res != nullptr
         && PyTuple_Check(py_res.o)
         && PyTuple_Size(py_res.o) == 3;
  if ( ok )
  {
    borref_t i0(PyTuple_GetItem(py_res.o, 0));
    borref_t i1(PyTuple_GetItem(py_res.o, 1));
    borref_t i2(PyTuple_GetItem(py_res.o, 2));
    ok = PyList_Check(i0.o) && PyLong_Check(i1.o) && PyLong_Check(i2.o);
    if ( ok )
    {
      ok = PyW_PySeqToStrVec(out_completions, i0.o) > 0;
      if ( ok )
      {
        *out_match_start = PyLong_AsLong(i1.o);
        *out_match_end = PyLong_AsLong(i2.o);
        ok = PyErr_Occurred() == nullptr;
      }
      else
      {
        // Clear the error that was set by PyW_PySeqToStrVec()
        PyErr_Clear();
      }
    }
  }
  return ok;
}

//-------------------------------------------------------------------------
int ida_export pylong_to_byte_array(
        bytevec_t *out_allocated_buffer,
        PyObject *in,
        bool little_endian,
        bool is_signed)
{
  if ( !PyLong_Check(in) )
    return -1;
  return extapi._PyLong_AsByteArray_ptr(
          in,
          out_allocated_buffer->begin(),
          out_allocated_buffer->size(),
          little_endian,
          is_signed);
}


#undef DEF_REG_UNREG_REFCOUNTED
