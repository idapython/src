%module(docstring="IDA Plugin SDK API wrapper",directors="1",threads="1") idaapi
// * http://swig.10945.n7.nabble.com/How-to-release-Python-GIL-td5027.html
// * http://stackoverflow.com/questions/1576737/releasing-python-gil-in-c-code
// * http://matt.eifelle.com/2007/11/23/enabling-thread-support-in-swig-and-python/
%nothread; // We don't want SWIG to release the GIL for *every* IDA API call.
// Suppress 'previous definition of XX' warnings
#pragma SWIG nowarn=302
// and others...
#pragma SWIG nowarn=312
#pragma SWIG nowarn=325
#pragma SWIG nowarn=314
#pragma SWIG nowarn=362
#pragma SWIG nowarn=383
#pragma SWIG nowarn=389
#pragma SWIG nowarn=401
#pragma SWIG nowarn=451
#pragma SWIG nowarn=454 // Setting a pointer/reference variable may leak memory

%constant size_t SIZE_MAX = size_t(-1);

// Enable automatic docstring generation
%feature(autodoc,0);

%define SWIG_DECLARE_PY_CLINKED_OBJECT(type)
%inline %{
static PyObject *type##_create()
{
  return PyCObject_FromVoidPtr(new type(), NULL);
}
static bool type##_destroy(PyObject *py_obj)
{
  if ( !PyCObject_Check(py_obj) )
    return false;
  delete (type *)PyCObject_AsVoidPtr(py_obj);
  return true;
}
static type *type##_get_clink(PyObject *self)
{
  return (type *)pyobj_get_clink(self);
}
static PyObject *type##_get_clink_ptr(PyObject *self)
{
  return PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG)pyobj_get_clink(self));
}
%}
%enddef

// We use those special maps because SWIG wraps passed PyObject* with 'SwigPtr_PyObject' and 'SwigVar_PyObject'
// They act like autoptr and decrement the reference of the object when the scope ends
// We need to keep a reference outside SWIG and let the caller manage its references
%typemap(directorin)  PyObject * "/*%din%*/Py_XINCREF($1_name);$input = $1_name;"
%typemap(directorout) PyObject * "/*%dout%*/$result = result;Py_XINCREF($result);"

%{
#include <Python.h>

#ifndef USE_DANGEROUS_FUNCTIONS
  #define USE_DANGEROUS_FUNCTIONS 1
#endif

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
#include "graph.hpp"
#ifdef WITH_HEXRAYS
#include "hexrays.hpp"
#endif
#include "pywraps.hpp"

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

// //-----------------------------------------------------------------------
// class pycvt_t
// {
//   struct attr_t
//   {
//     qstring str;
//     uint64 u64;
//     // User is responsible to release this attribute when done
//     PyObject *py_obj;
//   };

//   //-----------------------------------------------------------------------
//   static int get_attr(
//     PyObject *py_obj,
//     const char *attrname,
//     int ft,
//     attr_t &val)
//   {
//     ref_t py_attr(PyW_TryGetAttrString(py_obj, attrname));
//     if ( py_attr == NULL )
//       return FT_NOT_FOUND;

//     int cvt = FT_OK;
//     if ( ft == FT_STR || ft == FT_CHAR && PyString_Check(py_attr.o) )
//       val.str = PyString_AsString(py_attr.o);
//     else if ( (ft > FT_FIRST_NUM && ft < FT_LAST_NUM) && PyW_GetNumber(py_attr.o, &val.u64) )
//       ; // nothing to be done
//     // A string array?
//     else if ( (ft == FT_STRARR || ft == FT_NUM16ARR || ft == FT_CHRARR_STATIC )
//       && (PyList_CheckExact(py_attr.o) || PyW_IsSequenceType(py_attr.o)) )
//     {
//       // Return a reference to the attribute
//       val.py_obj = py_attr.o;
//       // Do not decrement the reference to this attribute
//       py_attr = NULL;
//     }
//     else
//       cvt = FT_BAD_TYPE;
//     return cvt;
//   }

//   //-----------------------------------------------------------------------
//   static int idaapi make_str_list_cb(
//     PyObject *py_item,
//     Py_ssize_t index,
//     void *ud)
//   {
//     if ( !PyString_Check(py_item) )
//       return CIP_FAILED;
//     char **a = (char **)ud;
//     a[index] = qstrdup(PyString_AsString(py_item));
//     return CIP_OK;
//   }

//   //-----------------------------------------------------------------------
//   // Converts an IDC list of strings to a C string list
//   static Py_ssize_t str_list_to_str_arr(
//     PyObject *py_list,
//     char ***arr)
//   {
//     // Take the size
//     Py_ssize_t size = pyvar_walk_list(py_list);

//     // Allocate a buffer
//     char **a = (char **)qalloc((size + 1) * sizeof(char *));

//     // Walk and populate
//     size = pyvar_walk_list(py_list, make_str_list_cb, a);

//     // Make the list NULL terminated
//     a[size] = NULL;

//     // Return the list to the user
//     *arr = a;

//     // Return the size of items processed
//     return size;
//   }

//   //-----------------------------------------------------------------------
//   typedef qvector<uint64> uint64vec_t;
//   static int idaapi make_int_list(
//     PyObject *py_item,
//     Py_ssize_t /*index*/,
//     void *ud)
//   {
//     uint64 val;
//     if ( !PyW_GetNumber(py_item, &val) )
//       return CIP_FAILED;
//     uint64vec_t *vec = (uint64vec_t *)ud;
//     vec->push_back(val);
//     return CIP_OK;
//   }

// public:
//   //-----------------------------------------------------------------------
//   // Frees a NULL terminated list of fields
//   static void free_fields(
//     const scfld_t *fields,
//     void *store_area)
//   {
//     for ( int i=0; ; i++ )
//     {
//       // End of list?
//       const scfld_t &fd = fields[i];
//       if ( fd.field_name == NULL )
//         break;

//       void *store = (void *)((char *)store_area + fd.field_offs);
//       int ft = fd.field_type & ~FT_VALUE_MASK;
//       switch ( ft )
//       {
//       case FT_STR:      // Simple string
//         {
//           char **s = (char **)store;
//           if ( *s != NULL )
//           {
//             qfree(*s);
//             *s = NULL;
//           }
//         }
//         break;

//       case FT_STRARR:   // Array of strings
//         {
//           char ***op = (char ***)store, **p = *op;
//           while ( *p != NULL )
//             qfree((void *)*p++);
//           qfree(*op);
//           *op = NULL;
//         }
//         break;

//       case FT_NUM16ARR:
//         {
//           uint16 **arr = (uint16 **)store;
//           if ( *arr != NULL )
//           {
//             qfree(*arr);
//             *arr = NULL;
//           }
//         }
//         break;
//       }
//     }
//   }

//   //-----------------------------------------------------------------------
//   // Converts from a C structure to Python
//   static int from_c(
//     const scfld_t *fields,
//     void *read_area,
//     PyObject *py_obj)
//   {
//     PyObject *py_attr;
//     int i;
//     bool ok = false;
//     for ( i=0; ; i++ )
//     {
//       // End of list?
//       const scfld_t &fd = fields[i];
//       if ( fd.field_name == NULL )
//       {
//         ok = true;
//         break;
//       }

//       // Point to structure member
//       int ft = fd.field_type & ~FT_VALUE_MASK;
//       void *read = (void *)((char *)read_area + fd.field_offs);
//       // Create the python attribute properly
//       if ( ft > FT_FIRST_NUM && ft < FT_LAST_NUM )
//       {
//         if ( ft == FT_NUM16 )
//           py_attr = Py_BuildValue("H", *(uint16 *)read);
//         else if ( ft == FT_NUM32 )
//           py_attr = Py_BuildValue("I", *(uint32 *)read);
//         else if ( ft == FT_INT )
//           py_attr = Py_BuildValue("i", *(int *)read);
//         else if ( ft == FT_SIZET )
//           py_attr = Py_BuildValue(PY_FMT64,*(size_t *)read);
//         else if ( ft == FT_SSIZET )
//           py_attr = Py_BuildValue(PY_SFMT64,*(ssize_t *)read);
//       }
//       else if ( ft == FT_STR || ft == FT_CHAR )
//       {
//         if ( ft == FT_STR )
//           py_attr = PyString_FromString(*(char **)read);
//         else
//           py_attr = Py_BuildValue("c", *(char *)read);
//       }
//       else if ( ft == FT_STRARR )
//       {
//         char **arr = *(char ***)read;
//         py_attr = PyList_New(0);
//         while ( *arr != NULL )
//           PyList_Append(py_attr, PyString_FromString(*arr++));
//       }
//       else
//         continue;
//       PyObject_SetAttrString(py_obj, fd.field_name, py_attr);
//       Py_XDECREF(py_attr);
//     }
//     return ok ? -1 : i;
//   }

//   //-----------------------------------------------------------------------
//   // Converts fields from IDC and field description into a C structure
//   // If 'use_extlang' is specified, then the passed idc_obj is considered
//   // to be an opaque object and thus can be queried only through extlang
//   static int from_script(
//     const scfld_t *fields,
//     void *store_area,
//     PyObject *py_obj)
//   {
//     int i;
//     bool ok = false;
//     attr_t attr;
//     for ( i=0; ; i++ )
//     {
//       // End of list?
//       const scfld_t &fd = fields[i];
//       if ( fd.field_name == NULL )
//       {
//         ok = true;
//         break;
//       }

//       // Get field type
//       int ft = fd.field_type & ~FT_VALUE_MASK;

//       // Point to structure member
//       void *store = (void *)((char *)store_area + fd.field_offs);

//       // Retrieve attribute and type
//       int cvt = get_attr(py_obj, fd.field_name, ft, attr);

//       // Attribute not found?
//       if ( cvt == FT_NOT_FOUND )
//       {
//         // Skip optional fields
//         if ( fd.is_optional )
//           continue;
//         break;
//       }

//       if ( ft == FT_STR )
//         *(char **)store = qstrdup(attr.str.c_str());
//       else if ( ft == FT_NUM32 )
//         *(uint32 *)store = uint32(attr.u64);
//       else if ( ft == FT_NUM16 )
//         *(uint16 *)store = attr.u64 & 0xffff;
//       else if ( ft == FT_INT )
//         *(int *)store = int(attr.u64);
//       else if ( ft == FT_SIZET )
//         *(size_t *)store = size_t(attr.u64);
//       else if ( ft == FT_SSIZET )
//         *(ssize_t *)store = ssize_t(attr.u64);
//       else if ( ft == FT_CHAR )
//         *(char *)store = *attr.str.c_str();
//       else if ( ft == FT_STRARR )
//       {
//         str_list_to_str_arr(attr.py_obj, (char ***)store);
//         Py_DECREF(attr.py_obj);
//       }
//       else if ( ft == FT_CHRARR_STATIC )
//       {
//         size_t sz = (fd.field_type & FT_VALUE_MASK) >> 16;
//         if ( sz == 0 )
//           break;
//         uint64vec_t w;
//         char *a = (char *) store;
//         if ( pyvar_walk_list(attr.py_obj, make_int_list, &w) )
//         {
//           sz = qmin(w.size(), sz);
//           for ( size_t i=0; i < sz; i++ )
//             a[i] = w[i] & 0xFF;
//         }
//       }
//       else if ( ft == FT_NUM16ARR )
//       {
//         uint64vec_t w;
//         if ( pyvar_walk_list(attr.py_obj, make_int_list, &w) > 0 )
//         {
//           size_t max_sz = (fd.field_type & FT_VALUE_MASK) >> 16;
//           bool zero_term;
//           if ( max_sz == 0 )
//           {
//             zero_term = true;
//             max_sz = w.size();
//           }
//           else
//           {
//             zero_term = false;
//             max_sz = qmin(max_sz, w.size());
//           }
//           // Allocate as much as we parsed elements
//           // Add one more element if list was zero terminated
//           uint16 *a = (uint16 *)qalloc(sizeof(uint16) * (max_sz + (zero_term ? 1 : 0))) ;
//           for ( size_t i=0; i < max_sz; i++ )
//             a[i] = w[i] & 0xFF;

//           if ( zero_term )
//             a[max_sz] = 0;
//           *(uint16 **)store = a;
//         }
//       }
//       else
//       {
//         // Unsupported field type!
//         break;
//       }
//     }
//     return ok ? -1 : i;
//   }
// };

//-------------------------------------------------------------------------
Py_ssize_t pyvar_walk_list(
        const ref_t &py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud),
        void *ud)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  Py_ssize_t size = CIP_FAILED;
  do
  {
    PyObject *o = py_list.o;
    if ( !PyList_CheckExact(o) && !PyW_IsSequenceType(o) )
      break;

    bool is_seq = !PyList_CheckExact(o);
    size = is_seq ? PySequence_Size(o) : PyList_Size(o);
    if ( cb == NULL )
      break;

    Py_ssize_t i;
    for ( i=0; i<size; i++ )
    {
      // Get the item
      ref_t py_item;
      if ( is_seq )
        py_item = newref_t(PySequence_GetItem(o, i));
      else
        py_item = borref_t(PyList_GetItem(o, i));

      if ( py_item == NULL || cb(py_item, i, ud) < CIP_OK )
        break;
    }
    size = i;
  } while ( false );
  return size;
}

//-------------------------------------------------------------------------
Py_ssize_t pyvar_walk_list(
        PyObject *py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud),
        void *ud)
{
  borref_t r(py_list);
  return pyvar_walk_list(r, cb, ud);
}

//---------------------------------------------------------------------------
ref_t PyW_IntVecToPyList(const intvec_t &intvec)
{
  size_t c = intvec.size();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_list(PyList_New(c));
  for ( size_t i=0; i<c; i++ )
    PyList_SetItem(py_list.o, i, PyInt_FromLong(intvec[i]));
  return ref_t(py_list);
}

//---------------------------------------------------------------------------
static int idaapi pylist_to_intvec_cb(
        const ref_t &py_item,
        Py_ssize_t /*index*/,
        void *ud)
{
  intvec_t &intvec = *(intvec_t *)ud;
  uint64 num;
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if (!PyW_GetNumber(py_item.o, &num))
      num = 0;
  }

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
        const ref_t &py_item,
        Py_ssize_t /*index*/,
        void *ud)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t &strvec = *(qstrvec_t *)ud;
  const char *s;
  if ( !PyString_Check(py_item.o) )
    s = "";
  else
    s = PyString_AsString(py_item.o);

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
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Check if this our special by reference object
  ref_t attr(PyW_TryGetAttrString(py_var, S_PY_IDCCVT_ID_ATTR));
  if ( attr == NULL || (!PyInt_Check(attr.o) && !PyLong_Check(attr.o)) )
    return -1;
  return (int)PyInt_AsLong(attr.o);
}

//-------------------------------------------------------------------------
// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
bool pyvar_to_idcvar_or_error(const ref_t &py_obj, idc_value_t *idc_obj)
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
  if ( VarObject(idc_var, get_py_idc_cvt_opaque()) != eOk )
    return false;

  // Store the CVT id
  idc_value_t idc_val;
  idc_val.set_long(PY_ICID_OPAQUE);
  VarSetAttr(idc_var, S_PY_IDCCVT_ID_ATTR, &idc_val);

  // Store the value as a PVOID referencing the given Python object
  py_var.incref();
  idc_val.set_pvoid(py_var.o);
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
  // This can be called at plugin registration time, when a
  // 'script_plugin_t' instance is ::free()'d. It is
  // not guaranteed that we have the GIL at that point.
  PYW_GIL_GET;

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
  // String
  else if ( PyString_Check(py_var.o) )
  {
    idc_var->_set_string(PyString_AsString(py_var.o), PyString_Size(py_var.o));
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
  else if ( PyCObject_Check(py_var.o) )
  {
    idc_var->set_pvoid(PyCObject_AsVoidPtr(py_var.o));
  }
  // Python list?
  else if ( PyList_CheckExact(py_var.o) || PyW_IsSequenceType(py_var.o) )
  {
    // Create the object
    VarObject(idc_var);

    // Determine list size and type
    bool is_seq = !PyList_CheckExact(py_var.o);
    Py_ssize_t size = is_seq ? PySequence_Size(py_var.o) : PyList_Size(py_var.o);
    bool ok = true;
    qstring attr_name;

    // Convert each item
    for ( Py_ssize_t i=0; i<size; i++ )
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
        // Form the attribute name
        newref_t py_int(PyInt_FromSsize_t(i));
        ok = PyW_ObjectToString(py_int.o, &attr_name);
        if ( !ok )
          break;
        // Store the attribute
        VarSetAttr(idc_var, attr_name.c_str(), &v);
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
    VarObject(idc_var);

    // Get the dict.items() list
    newref_t py_items(PyDict_Items(py_var.o));

    // Get the size of the list
    qstring key_name;
    bool ok = true;
    Py_ssize_t size = PySequence_Size(py_items.o);
    for ( Py_ssize_t i=0; i<size; i++ )
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
        VarSetAttr(idc_var, key_name.c_str(), &v);
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
          VarRef(idc_var, gvar);
        }
        return ok ? CIP_OK : CIP_FAILED;
      }
      //
      // OPAQUE
      //
    case PY_ICID_OPAQUE:
      {
        if ( !wrap_PyObject_ptr(py_var, idc_var) )
          return CIP_FAILED;
        return CIP_OK_OPAQUE;
      }
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
      VarObject(idc_var);
      for ( Py_ssize_t i=0; i<size; i++ )
      {
        borref_t item(PyList_GetItem(py_dir.o, i));
        const char *field_name = PyString_AsString(item.o);
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
        if (attr == NULL
          // Convert the attribute into an IDC value
          || pyvar_to_idcvar(attr, &v, gvar_sn) < CIP_OK)
        {
          return CIP_FAILED;
        }

        // Store the attribute
        VarSetAttr(idc_var, field_name, &v);
      }
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
int idcvar_to_pyvar(
  const idc_value_t &idc_var,
  ref_t *py_var)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  switch ( idc_var.vtype )
  {
  case VT_PVOID:
    if ( *py_var == NULL )
    {
      newref_t nr(PyCObject_FromVoidPtr(idc_var.pvoid, NULL));
      *py_var = nr;
    }
    else
    {
      return CIP_IMMUTABLE;
    }
    break;

  case VT_INT64:
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
      break;
    }

#if !defined(NO_OBSOLETE_FUNCS) || defined(__EXPR_SRC)
  case VT_STR:
    *py_var = newref_t(PyString_FromString(idc_var.str));
    break;

#endif
  case VT_STR2:
    if ( *py_var == NULL )
    {
      const qstring &s = idc_var.qstr();
      *py_var = newref_t(PyString_FromStringAndSize(s.begin(), s.length()));
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
      if ( ph.realcvt(&x, (uint16 *)idc_var.e, (sizeof(x)/2-1)|010) != 0 )
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
      idc_value_t *dref_v = VarDeref(const_cast<idc_value_t *>(&idc_var), VREF_LOOP);
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
      if (    VarGetAttr(&idc_var, S_PY_IDCCVT_ID_ATTR, &idc_val) == eOk
        && VarGetAttr(&idc_var, S_PY_IDCCVT_VALUE_ATTR, &idc_val) == eOk )
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
      for (const char *attr_name = VarFirstAttr(&idc_var);
        attr_name != NULL;
        attr_name = VarNextAttr(&idc_var, attr_name) )
      {
        // Get the attribute
        idc_value_t v;
        VarGetAttr(&idc_var, attr_name, &v, true);

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
bool pyw_convert_idc_args(
  const idc_value_t args[],
  int nargs,
  ref_vec_t &pargs,
  bool as_tupple,
  char *errbuf,
  size_t errbufsize)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  ref_t py_tuple;

  pargs.qclear();

  if ( as_tupple )
  {
    py_tuple = newref_t(PyTuple_New(nargs));
    if ( py_tuple == NULL )
    {
      if ( errbuf != 0 && errbufsize > 0 )
        qstrncpy(errbuf, "Failed to create a new tuple to store arguments!", errbufsize);
      return false;
    }
  }

  for ( int i=0; i<nargs; i++ )
  {
    ref_t py_obj;
    int cvt = idcvar_to_pyvar(args[i], &py_obj);
    if ( cvt < CIP_OK )
    {
      if ( errbuf != 0 && errbufsize > 0 )
        qsnprintf(errbuf, errbufsize, "arg#%d has wrong type %d", i, args[i].vtype);
      return false;
    }

    if ( as_tupple )
    {
      // PyTuple_SetItem() steals the reference.
      py_obj.incref();
      if ( cvt == CIP_OK_OPAQUE )
        // We want opaque objects to still exist even when the tuple is gone.
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
  if ( as_tupple )
    pargs.push_back(py_tuple);

  return true;
}




//------------------------------------------------------------------------
// String constants used
static const char S_PYINVOKE0[]              = "_py_invoke0";
static const char S_PY_SWIEX_CLSNAME[]       = "switch_info_ex_t";
static const char S_PY_OP_T_CLSNAME[]        = "op_t";
static const char S_PROPS[]                  = "props";
static const char S_NAME[]                   = "name";
static const char S_TITLE[]                  = "title";
static const char S_ASM_KEYWORD[]            = "asm_keyword";
static const char S_MENU_NAME[]              = "menu_name";
static const char S_HOTKEY[]                 = "hotkey";
static const char S_EMBEDDED[]               = "embedded";
static const char S_POPUP_NAMES[]            = "popup_names";
static const char S_FLAGS[]                  = "flags";
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
static const char S_ON_COMPLETE_LINE[]       = "OnCompleteLine";
static const char S_ON_CREATE[]              = "OnCreate";
static const char S_ON_POPUP[]               = "OnPopup";
static const char S_ON_HINT[]                = "OnHint";
static const char S_ON_POPUP_MENU[]          = "OnPopupMenu";
static const char S_ON_EDIT_LINE[]           = "OnEditLine";
static const char S_ON_INSERT_LINE[]         = "OnInsertLine";
static const char S_ON_GET_LINE[]            = "OnGetLine";
static const char S_ON_DELETE_LINE[]         = "OnDeleteLine";
static const char S_ON_REFRESH[]             = "OnRefresh";
static const char S_ON_REFRESHED[]           = "OnRefreshed";
static const char S_ON_EXECUTE_LINE[]        = "OnExecuteLine";
static const char S_ON_SELECT_LINE[]         = "OnSelectLine";
static const char S_ON_SELECTION_CHANGE[]    = "OnSelectionChange";
static const char S_ON_COMMAND[]             = "OnCommand";
static const char S_ON_GET_ICON[]            = "OnGetIcon";
static const char S_ON_GET_LINE_ATTR[]       = "OnGetLineAttr";
static const char S_ON_GET_SIZE[]            = "OnGetSize";
static const char S_ON_GETTEXT[]             = "OnGetText";
static const char S_ON_ACTIVATE[]            = "OnActivate";
static const char S_ON_DEACTIVATE[]          = "OnDeactivate";
static const char S_ON_SELECT[]              = "OnSelect";
static const char S_ON_CREATING_GROUP[]      = "OnCreatingGroup";
static const char S_ON_DELETING_GROUP[]      = "OnDeletingGroup";
static const char S_ON_GROUP_VISIBILITY[]    = "OnGroupVisibility";
static const char S_M_EDGES[]                = "_edges";
static const char S_M_NODES[]                = "_nodes";
static const char S_M_THIS[]                 = "_this";
static const char S_M_TITLE[]                = "_title";
static const char S_CLINK_NAME[]             = "__clink__";
static const char S_ON_VIEW_ACTIVATED[]      = "OnViewActivated";
static const char S_ON_VIEW_DEACTIVATED[]    = "OnViewDeactivated";
static const char S_ON_VIEW_KEYDOWN[]        = "OnViewKeydown";
static const char S_ON_VIEW_CLICK[]          = "OnViewClick";
static const char S_ON_VIEW_DBLCLICK[]       = "OnViewDblclick";
static const char S_ON_VIEW_CURPOS[]         = "OnViewCurpos";
static const char S_ON_VIEW_SWITCHED[]       = "OnViewSwitched";
static const char S_ON_VIEW_MOUSE_OVER[]     = "OnViewMouseOver";


#ifdef __PYWRAPS__
static const char S_PY_IDAAPI_MODNAME[]      = "__main__";
#else
static const char S_PY_IDAAPI_MODNAME[]      = S_IDAAPI_MODNAME;
#endif

//------------------------------------------------------------------------
static ref_t py_cvt_helper_module;
static bool pywraps_initialized = false;

//---------------------------------------------------------------------------
// Context structure used by add|del_menu_item()
struct py_add_del_menu_item_ctx
{
  qstring menupath;
  PyObject *cb_data;
};

//---------------------------------------------------------------------------
// Context structure used by add|del_idc_hotkey()
struct py_idchotkey_ctx_t
{
  qstring hotkey;
  PyObject *pyfunc;
};

//---------------------------------------------------------------------------
// Context structure used by register/unregister timer
struct py_timer_ctx_t
{
  qtimer_t timer_id;
  PyObject *pycallback;
};

//------------------------------------------------------------------------
// check if we have a file which is known to be executed automatically
// by SWIG or Python runtime
bool pywraps_check_autoscripts(char *buf, size_t bufsize)
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
error_t PyW_CreateIdcException(idc_value_t *res, const char *msg)
{
  // Create exception object
  VarObject(res, find_idc_class("exception"));

  // Set the message field
  idc_value_t v;
  v.set_string(msg);
  VarSetAttr(res, "message", &v);

  // Throw exception
  return set_qerrno(eExecThrow);
}

//------------------------------------------------------------------------
// Calls a Python callable encoded in IDC.pvoid member
static const char idc_py_invoke0_args[] = { VT_PVOID, 0 };
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

//------------------------------------------------------------------------
// This function must be called on initialization
bool init_pywraps()
{
  if ( pywraps_initialized )
    return true;

  // Take a reference to the idaapi python module
  // (We need it to create instances of certain classes)
  if ( py_cvt_helper_module == NULL )
  {
    // Take a reference to the module so we can create the needed class instances
    py_cvt_helper_module = PyW_TryImportModule(S_PY_IDAAPI_MODNAME);
    if ( py_cvt_helper_module == NULL )
      return false;
  }

  // Register the IDC PyInvoke0 method (helper function for add_idc_hotkey())
  if ( !set_idc_func_ex(S_PYINVOKE0, idc_py_invoke0, idc_py_invoke0_args, 0) )
    return false;

  // IDC opaque class not registered?
  if ( get_py_idc_cvt_opaque() == NULL )
  {
    // Add the class
    idc_class_t *idc_cvt_opaque = add_idc_class(S_PY_IDC_OPAQUE_T);
    if ( idc_cvt_opaque == NULL )
      return false;

    // Form the dtor name
    char dtor_name[MAXSTR];
    qsnprintf(dtor_name, sizeof(dtor_name), "%s.dtor", S_PY_IDC_OPAQUE_T);

    // Register the dtor function
    if ( !set_idc_func_ex(dtor_name, py_idc_opaque_dtor, py_idc_cvt_helper_dtor_args, 0) )
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
  if ( !pywraps_initialized )
    return;

  pywraps_initialized = false;

  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    py_cvt_helper_module = ref_t(); // Deref.
  }

  // Unregister the IDC PyInvoke0 method (helper function for add_idc_hotkey())
  set_idc_func_ex(S_PYINVOKE0, NULL, idc_py_invoke0_args, 0);
}

//------------------------------------------------------------------------
// Utility function to create a class instance whose constructor takes zero arguments
ref_t create_idaapi_class_instance0(const char *clsname)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_cls(get_idaapi_attr(clsname));
  if ( py_cls == NULL )
    return ref_t();

  ref_t py_obj = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, NULL));
  if ( PyW_GetError() || py_obj == NULL )
    py_obj = ref_t();
  return py_obj;
}

//------------------------------------------------------------------------
// Utility function to create linked class instances
ref_t create_idaapi_linked_class_instance(
    const char *clsname,
    void *lnk)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_cls(get_idaapi_attr(clsname));
  if ( py_cls == NULL )
    return ref_t();

  newref_t py_lnk(PyCObject_FromVoidPtr(lnk, NULL));
  ref_t py_obj = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, py_lnk.o, NULL));
  if ( PyW_GetError() || py_obj == NULL )
    py_obj = ref_t();
  return py_obj;
}

//------------------------------------------------------------------------
// Gets a class type reference in idaapi
// With the class type reference we can create a new instance of that type
// This function takes a reference to the idaapi module and keeps the reference
ref_t get_idaapi_attr_by_id(const int class_id)
{
  if ( class_id >= PY_CLSID_LAST || py_cvt_helper_module == NULL )
    return ref_t();

  // Some class names. The array is parallel with the PY_CLSID_xxx consts
  static const char *class_names[]=
  {
    "PyIdc_cvt_int64__",
    "object_t",
    "PyIdc_cvt_refclass__"
  };
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return newref_t(PyObject_GetAttrString(py_cvt_helper_module.o, class_names[class_id]));
}

//------------------------------------------------------------------------
// Gets a class reference by name
ref_t get_idaapi_attr(const char *attrname)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return py_cvt_helper_module == NULL
    ? ref_t()
    : PyW_TryGetAttrString(py_cvt_helper_module.o, attrname);
}

//------------------------------------------------------------------------
// Returns a qstring from an object attribute
bool PyW_GetStringAttr(
    PyObject *py_obj,
    const char *attr_name,
    qstring *str)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_attr(PyW_TryGetAttrString(py_obj, attr_name));
  if ( py_attr == NULL )
    return false;

  bool ok = PyString_Check(py_attr.o) != 0;
  if ( ok )
    *str = PyString_AsString(py_attr.o);

  return ok;
}

//------------------------------------------------------------------------
// Returns an attribute or NULL
// No errors will be set if the attribute did not exist
ref_t PyW_TryGetAttrString(PyObject *py_obj, const char *attr)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t o;
  if ( PyObject_HasAttrString(py_obj, attr) )
    o = newref_t(PyObject_GetAttrString(py_obj, attr));
  return o;
}

//------------------------------------------------------------------------
// Tries to import a module and clears the exception on failure
ref_t PyW_TryImportModule(const char *name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t result(PyImport_ImportModule(name));
  if ( result == NULL && PyErr_Occurred() )
      PyErr_Clear();
  return result;
}

//-------------------------------------------------------------------------
// Converts a Python number into an IDC value (32 or 64bits)
// The function will first try to convert the number into a 32bit value
// If the number does not fit then VT_INT64 will be used
// NB: This function cannot properly detect if the Python value should be
// converted to a VT_INT64 or not. For example: 2**32-1 = 0xffffffff which
// can fit in a C long but Python creates a PyLong object for it.
// And because of that we are confused as to whether to convert to 32 or 64
bool PyW_GetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = true;
  do
  {
    if ( !(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)) )
    {
      rc = false;
      break;
    }

    // Can we convert to C long?
    long l = PyInt_AsLong(py_var);
    if ( !PyErr_Occurred() )
    {
      idc_var->set_long(l);
      break;
    }
    // Clear last error
    PyErr_Clear();
    // Can be fit into a C unsigned long?
    l = (long) PyLong_AsUnsignedLong(py_var);
    if ( !PyErr_Occurred() )
    {
      idc_var->set_long(l);
      break;
    }
    PyErr_Clear();
    idc_var->set_int64(PyLong_AsLongLong(py_var));
  } while ( false );
  return rc;
}

//-------------------------------------------------------------------------
// Parses a Python object as a long or long long
bool PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64)
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
    if ( !(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)) )
    {
      rc = false;
      break;
    }

    // Can we convert to C long?
    long l = PyInt_AsLong(py_var);
    if ( !PyErr_Occurred() )
    {
      SETNUM(uint64(l), false);
      break;
    }

    // Clear last error
    PyErr_Clear();

    // Can be fit into a C unsigned long?
    unsigned long ul = PyLong_AsUnsignedLong(py_var);
    if ( !PyErr_Occurred() )
    {
      SETNUM(uint64(ul), false);
      break;
    }
    PyErr_Clear();

    // Try to parse as int64
    PY_LONG_LONG ll = PyLong_AsLongLong(py_var);
    if ( !PyErr_Occurred() )
    {
      SETNUM(uint64(ll), true);
      break;
    }
    PyErr_Clear();

    // Try to parse as uint64
    unsigned PY_LONG_LONG ull = PyLong_AsUnsignedLongLong(py_var);
    PyObject *err = PyErr_Occurred();
    if ( err == NULL )
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
        if ( !PyErr_Occurred() )
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
bool PyW_IsSequenceType(PyObject *obj)
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
bool PyW_ObjectToString(PyObject *obj, qstring *out)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_str(PyObject_Str(obj));
  bool ok = py_str != NULL;
  if ( ok )
    *out = PyString_AsString(py_str.o);
  else
    out->qclear();
  return ok;
}

//--------------------------------------------------------------------------
// Checks if a Python error occured and fills the out parameter with the
// exception string
bool PyW_GetError(qstring *out, bool clear_err)
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
    *out = PyString_AsString(py_ret);
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
bool PyW_GetError(char *buf, size_t bufsz, bool clear_err)
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
bool PyW_ShowCbErr(const char *cb_name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  static qstring err_str;
  if ( !PyW_GetError(&err_str) )
    return false;

  warning("IDAPython: Error while calling Python callback <%s>:\n%s", cb_name, err_str.c_str());
  return true;
}

//---------------------------------------------------------------------------
void *pyobj_get_clink(PyObject *pyobj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Try to query the link attribute
  ref_t attr(PyW_TryGetAttrString(pyobj, S_CLINK_NAME));
  void *t = attr != NULL && PyCObject_Check(attr.o) ? PyCObject_AsVoidPtr(attr.o) : NULL;
  return t;
}



//------------------------------------------------------------------------

//------------------------------------------------------------------------
class pywraps_notify_when_t
{
  ref_vec_t table[NW_EVENTSCNT];
  qstring err;
  bool in_notify;
  struct notify_when_args_t
  {
    int when;
    PyObject *py_callable;
  };
  typedef qvector<notify_when_args_t> notify_when_args_vec_t;
  notify_when_args_vec_t delayed_notify_when_list;

  //------------------------------------------------------------------------
  static int idaapi idp_callback(void *ud, int event_id, va_list va)
  {
    // This hook gets called from the kernel. Ensure we hold the GIL.
    PYW_GIL_GET;
    pywraps_notify_when_t *_this = (pywraps_notify_when_t *)ud;
    switch ( event_id )
    {
    case processor_t::newfile:
    case processor_t::oldfile:
      {
        int old = event_id == processor_t::oldfile ? 1 : 0;
        char *dbname = va_arg(va, char *);
        _this->notify(NW_OPENIDB_SLOT, old);
      }
      break;
    case processor_t::closebase:
      _this->notify(NW_CLOSEIDB_SLOT);
      break;
    }
    // event not processed, let other plugins or the processor module handle it
    return 0;
  }

  //------------------------------------------------------------------------
  bool unnotify_when(int when, PyObject *py_callable)
  {
    int cnt = 0;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
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
  void register_callback(int slot, PyObject *py_callable)
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
  void unregister_callback(int slot, PyObject *py_callable)
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

public:
  //------------------------------------------------------------------------
  bool init()
  {
    return hook_to_notification_point(HT_IDP, idp_callback, this);
  }

  //------------------------------------------------------------------------
  bool deinit()
  {
    // Uninstall all objects
    ref_vec_t::iterator it, it_end;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
    {
      for ( it = table[slot].begin(), it_end = table[slot].end(); it!=it_end; ++it )
        unregister_callback(slot, it->o);
    }
    // ...and remove the notification
    return unhook_from_notification_point(HT_IDP, idp_callback, this);
  }

  //------------------------------------------------------------------------
  bool notify_when(int when, PyObject *py_callable)
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
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
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
  bool notify(int slot, ...)
  {
    va_list va;
    va_start(va, slot);
    bool ok = notify_va(slot, va);
    va_end(va);
    return ok;
  }

  //------------------------------------------------------------------------
  bool notify_va(int slot, va_list va)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    // Sanity bounds check!
    if ( slot < 0 || slot >= NW_EVENTSCNT )
      return false;

    bool ok = true;
    in_notify = true;
    int old = slot == NW_OPENIDB_SLOT ? va_arg(va, int) : 0;

    {
      for (ref_vec_t::iterator it = table[slot].begin(), it_end = table[slot].end();
           it != it_end;
           ++it)
      {
        // Form the notification code
        newref_t py_code(PyInt_FromLong(1 << slot));
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
              newref_t py_old(PyInt_FromLong(old));
              py_result = newref_t(PyObject_CallFunctionObjArgs(it->o, py_code.o, py_old.o, NULL));
            }
            break;
        }
        if ( PyW_GetError(&err) || py_result == NULL )
        {
          PyErr_Clear();
          warning("notify_when(): Error occured while notifying object.\n%s", err.c_str());
          ok = false;
        }
      }
    }
    in_notify = false;

    // Process any delayed notify_when() calls that
    if ( !delayed_notify_when_list.empty() )
    {
      for (notify_when_args_vec_t::iterator it = delayed_notify_when_list.begin(), it_end=delayed_notify_when_list.end();
           it != it_end;
           ++it)
      {
        notify_when(it->when, it->py_callable);
      }
      delayed_notify_when_list.qclear();
    }

    return ok;
  }

  //------------------------------------------------------------------------
  pywraps_notify_when_t()
  {
    in_notify = false;
  }
};

static pywraps_notify_when_t *g_nw = NULL;

//------------------------------------------------------------------------
// Initializes the notify_when mechanism
// (Normally called by IDAPython plugin.init())
bool pywraps_nw_init()
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
bool pywraps_nw_notify(int slot, ...)
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
bool pywraps_nw_term()
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

//</code(py_idaapi)>
%}

// Do not create separate wrappers for default arguments
%feature("compactdefaultargs");

%constant ea_t BADADDR = ea_t(-1);
%constant sel_t BADSEL = sel_t(-1);
%constant nodeidx_t BADNODE = nodeidx_t(-1);

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

%pythoncode %{
#<pycode(py_idaapi)>

import struct
import traceback
import os
import sys
import bisect
import __builtin__
import imp

def require(modulename, package=None):
    """
    Load, or reload a module.

    When under heavy development, a user's tool might consist of multiple
    modules. If those are imported using the standard 'import' mechanism,
    there is no guarantee that the Python implementation will re-read
    and re-evaluate the module's Python code. In fact, it usually doesn't.
    What should be done instead is 'reload()'-ing that module.

    This is a simple helper function that will do just that: In case the
    module doesn't exist, it 'import's it, and if it does exist,
    'reload()'s it.

    For more information, see: <http://www.hexblog.com/?p=749>.
    """
    if modulename in sys.modules.keys():
        reload(sys.modules[modulename])
    else:
        import importlib
        import inspect
        m = importlib.import_module(modulename, package)
        frame_obj, filename, line_number, function_name, lines, index = inspect.stack()[1]
        importer_module = inspect.getmodule(frame_obj)
        if importer_module is None: # No importer module; called from command line
            importer_module = sys.modules['__main__']
        setattr(importer_module, modulename, m)
        sys.modules[modulename] = m

# -----------------------------------------------------------------------

# Seek constants
SEEK_SET = 0 # from the file start
SEEK_CUR = 1 # from the current position
SEEK_END = 2 # from the file end

# Plugin constants
PLUGIN_MOD  = 0x0001
PLUGIN_DRAW = 0x0002
PLUGIN_SEG  = 0x0004
PLUGIN_UNL  = 0x0008
PLUGIN_HIDE = 0x0010
PLUGIN_DBG  = 0x0020
PLUGIN_PROC = 0x0040
PLUGIN_FIX  = 0x0080
PLUGIN_SKIP = 0
PLUGIN_OK   = 1
PLUGIN_KEEP = 2

# PyIdc conversion object IDs
PY_ICID_INT64  = 0
"""int64 object"""
PY_ICID_BYREF  = 1
"""byref object"""
PY_ICID_OPAQUE = 2
"""opaque object"""

# Step trace options (used with set_step_trace_options())
ST_OVER_DEBUG_SEG  = 0x01
"""step tracing will be disabled when IP is in a debugger segment"""

ST_OVER_LIB_FUNC    = 0x02
"""step tracing will be disabled when IP is in a library function"""

# -----------------------------------------------------------------------
class pyidc_opaque_object_t(object):
    """This is the base class for all Python<->IDC opaque objects"""
    __idc_cvt_id__ = PY_ICID_OPAQUE

# -----------------------------------------------------------------------
class py_clinked_object_t(pyidc_opaque_object_t):
    """
    This is a utility and base class for C linked objects
    """
    def __init__(self, lnk = None):
        # static link: if a link was provided
        self.__static_clink__ = True if lnk else False

        # Create link if it was not provided
        self.__clink__ = lnk if lnk else self._create_clink()

    def __del__(self):
        """Delete the link upon object destruction (only if not static)"""
        self._free()

    def _free(self):
        """Explicitly delete the link (only if not static)"""
        if not self.__static_clink__ and self.__clink__ is not None:
            self._del_clink(self.__clink__)
            self.__clink__ = None

    def copy(self):
        """Returns a new copy of this class"""

        # Create an unlinked instance
        inst = self.__class__()

        # Assign self to the new instance
        inst.assign(self)

        return inst

    #
    # Methods to be overwritten
    #
    def _create_clink(self):
        """
        Overwrite me.
        Creates a new clink
        @return: PyCObject representing the C link
        """
        pass

    def _del_clink(self, lnk):
        """
        Overwrite me.
        This method deletes the link
        """
        pass

    def _get_clink_ptr(self):
        """
        Overwrite me.
        Returns the C link pointer as a 64bit number
        """
        pass

    def assign(self, other):
        """
        Overwrite me.
        This method allows you to assign an instance contents to anothers
        @return: Boolean
        """
        pass

    clink = property(lambda self: self.__clink__)
    """Returns the C link as a PyObject"""

    clink_ptr = property(lambda self: self._get_clink_ptr())
    """Returns the C link pointer as a number"""

# -----------------------------------------------------------------------
class object_t(object):
    """Helper class used to initialize empty objects"""
    def __init__(self, **kwds):
        self.__dict__ = kwds

    def __getitem__(self, idx):
        """Allow access to object attributes by index (like dictionaries)"""
        return getattr(self, idx)

# -----------------------------------------------------------------------
class plugin_t(pyidc_opaque_object_t):
    """Base class for all scripted plugins."""
    pass

# -----------------------------------------------------------------------
class pyidc_cvt_helper__(object):
    """
    This is a special helper object that helps detect which kind
    of object is this python object wrapping and how to convert it
    back and from IDC.
    This object is characterized by its special attribute and its value
    """
    def __init__(self, cvt_id, value):
        self.__idc_cvt_id__ = cvt_id
        self.value = value

    def __set_value(self, v):
        self.__idc_cvt_value__ = v
    def __get_value(self):
        return self.__idc_cvt_value__
    value = property(__get_value, __set_value)

# -----------------------------------------------------------------------
class PyIdc_cvt_int64__(pyidc_cvt_helper__):
    """Helper class for explicitly representing VT_INT64 values"""

    def __init__(self, v):
        # id = 0 = int64 object
        super(self.__class__, self).__init__(PY_ICID_INT64, v)

    # operation table
    __op_table = \
    {
        0: lambda a, b: a + b,
        1: lambda a, b: a - b,
        2: lambda a, b: a * b,
        3: lambda a, b: a / b
    }
    # carries the operation given its number
    def __op(self, op_n, other, rev=False):
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
        return self.__class__(self.__op_table[op_n](a, b))

    # overloaded operators
    def __add__(self, other):  return self.__op(0, other)
    def __sub__(self, other):  return self.__op(1, other)
    def __mul__(self, other):  return self.__op(2, other)
    def __div__(self, other):  return self.__op(3, other)
    def __radd__(self, other): return self.__op(0, other, True)
    def __rsub__(self, other): return self.__op(1, other, True)
    def __rmul__(self, other): return self.__op(2, other, True)
    def __rdiv__(self, other): return self.__op(3, other, True)

# -----------------------------------------------------------------------
# qstrvec_t clinked object
# class qstrvec_t(py_clinked_object_t):
#     """Class representing an qstrvec_t"""

#     def __init__(self, items=None):
#         py_clinked_object_t.__init__(self)
#         # Populate the list if needed
#         if items:
#             self.from_list(items)

#     def _create_clink(self):
#         return _idaapi.qstrvec_t_create()

#     def _del_clink(self, lnk):
#         return _idaapi.qstrvec_t_destroy(lnk)

#     def _get_clink_ptr(self):
#         return _idaapi.qstrvec_t_get_clink_ptr(self)

#     def assign(self, other):
#         """Copies the contents of 'other' to 'self'"""
#         return _idaapi.qstrvec_t_assign(self, other)

#     def __setitem__(self, idx, s):
#         """Sets string at the given index"""
#         return _idaapi.qstrvec_t_set(self, idx, s)

#     def __getitem__(self, idx):
#         """Gets the string at the given index"""
#         return _idaapi.qstrvec_t_get(self, idx)

#     def __get_size(self):
#         return _idaapi.qstrvec_t_size(self)

#     size = property(__get_size)
#     """Returns the count of elements"""

#     def addressof(self, idx):
#         """Returns the address (as number) of the qstring at the given index"""
#         return _idaapi.qstrvec_t_addressof(self, idx)

#     def add(self, s):
#         """Add a string to the vector"""
#         return _idaapi.qstrvec_t_add(self, s)


#     def from_list(self, lst):
#         """Populates the vector from a Python string list"""
#         return _idaapi.qstrvec_t_from_list(self, lst)


#     def clear(self, qclear=False):
#         """
#         Clears all strings from the vector.
#         @param qclear: Just reset the size but do not actually free the memory
#         """
#         return _idaapi.qstrvec_t_clear(self, qclear)


#     def insert(self, idx, s):
#         """Insert a string into the vector"""
#         return _idaapi.qstrvec_t_insert(self, idx, s)


#     def remove(self, idx):
#         """Removes a string from the vector"""
#         return _idaapi.qstrvec_t_remove(self, idx)

# -----------------------------------------------------------------------
class PyIdc_cvt_refclass__(pyidc_cvt_helper__):
    """Helper class for representing references to immutable objects"""
    def __init__(self, v):
        # id = one = byref object
        super(self.__class__, self).__init__(PY_ICID_BYREF, v)

    def cstr(self):
        """Returns the string as a C string (up to the zero termination)"""
        return as_cstr(self.value)

# -----------------------------------------------------------------------
def as_cstr(val):
    """
    Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref())
    It scans for the first \x00 and returns the string value up to that point.
    """
    if isinstance(val, PyIdc_cvt_refclass__):
        val = val.value

    n = val.find('\x00')
    return val if n == -1 else val[:n]

# -----------------------------------------------------------------------
def as_unicode(s):
    """Convenience function to convert a string into appropriate unicode format"""
    # use UTF16 big/little endian, depending on the environment?
    return unicode(s).encode("UTF-16" + ("BE" if _idaapi.cvar.inf.mf else "LE"))

# -----------------------------------------------------------------------
def as_uint32(v):
    """Returns a number as an unsigned int32 number"""
    return v & 0xffffffff

# -----------------------------------------------------------------------
def as_int32(v):
    """Returns a number as a signed int32 number"""
    return -((~v & 0xffffffff)+1)

# -----------------------------------------------------------------------
def as_signed(v, nbits = 32):
    """
    Returns a number as signed. The number of bits are specified by the user.
    The MSB holds the sign.
    """
    return -(( ~v & ((1 << nbits)-1) ) + 1) if v & (1 << nbits-1) else v

# ----------------------------------------------------------------------
def copy_bits(v, s, e=-1):
    """
    Copy bits from a value
    @param v: the value
    @param s: starting bit (0-based)
    @param e: ending bit
    """
    # end-bit not specified? use start bit (thus extract one bit)
    if e == -1:
        e = s
    # swap start and end if start > end
    if s > e:
        e, s = s, e

    mask = ~(((1 << (e-s+1))-1) << s)

    return (v & mask) >> s

# ----------------------------------------------------------------------
__struct_unpack_table = {
  1: ('b', 'B'),
  2: ('h', 'H'),
  4: ('l', 'L'),
  8: ('q', 'Q')
}

# ----------------------------------------------------------------------
def struct_unpack(buffer, signed = False, offs = 0):
    """
    Unpack a buffer given its length and offset using struct.unpack_from().
    This function will know how to unpack the given buffer by using the lookup table '__struct_unpack_table'
    If the buffer is of unknown length then None is returned. Otherwise the unpacked value is returned.
    """
    # Supported length?
    n = len(buffer)
    if n not in __struct_unpack_table:
        return None
    # Conver to number
    signed = 1 if signed else 0

    # Unpack
    return struct.unpack_from(__struct_unpack_table[n][signed], buffer, offs)[0]


# ------------------------------------------------------------
def IDAPython_ExecSystem(cmd):
    """
    Executes a command with popen().
    """
    try:
        f = os.popen(cmd, "r")
        s = ''.join(f.readlines())
        f.close()
        return s
    except Exception as e:
        return "%s\n%s" % (str(e), traceback.format_exc())

# ------------------------------------------------------------
def IDAPython_FormatExc(etype, value, tb, limit=None):
    """
    This function is used to format an exception given the
    values returned by a PyErr_Fetch()
    """
    try:
        return ''.join(traceback.format_exception(etype, value, tb, limit))
    except:
        return str(value)


# ------------------------------------------------------------
def IDAPython_ExecScript(script, g):
    """
    Run the specified script.
    It also addresses http://code.google.com/p/idapython/issues/detail?id=42

    This function is used by the low-level plugin code.
    """
    scriptpath = os.path.dirname(script)
    if len(scriptpath) and scriptpath not in sys.path:
        sys.path.append(scriptpath)

    argv = sys.argv
    sys.argv = [ script ]

    # Adjust the __file__ path in the globals we pass to the script
    old__file__ = g['__file__'] if '__file__' in g else ''
    g['__file__'] = script

    try:
        execfile(script, g)
        PY_COMPILE_ERR = None
    except Exception as e:
        PY_COMPILE_ERR = "%s\n%s" % (str(e), traceback.format_exc())
        print(PY_COMPILE_ERR)
    finally:
        # Restore state
        g['__file__'] = old__file__
        sys.argv = argv

    return PY_COMPILE_ERR

# ------------------------------------------------------------
def IDAPython_LoadProcMod(script, g):
    """
    Load processor module.
    """
    pname = g['__name__'] if g and g.has_key("__name__") else '__main__'
    parent = sys.modules[pname]

    scriptpath, scriptname = os.path.split(script)
    if len(scriptpath) and scriptpath not in sys.path:
        sys.path.append(scriptpath)

    procmod_name = os.path.splitext(scriptname)[0]
    procobj = None
    fp = None
    try:
        fp, pathname, description = imp.find_module(procmod_name)
        procmod = imp.load_module(procmod_name, fp, pathname, description)
        if parent:
            setattr(parent, procmod_name, procmod)
            # export attrs from parent to processor module
            parent_attrs = getattr(parent, '__all__',
                                   (attr for attr in dir(parent) if not attr.startswith('_')))
            for pa in parent_attrs:
                setattr(procmod, pa, getattr(parent, pa))
            # instantiate processor object
            if getattr(procmod, 'PROCESSOR_ENTRY', None):
                procobj = procmod.PROCESSOR_ENTRY()
        PY_COMPILE_ERR = None
    except Exception as e:
        PY_COMPILE_ERR = "%s\n%s" % (str(e), traceback.format_exc())
        print(PY_COMPILE_ERR)
    finally:
        if fp: fp.close()

    sys.path.remove(scriptpath)

    return (PY_COMPILE_ERR, procobj)

# ------------------------------------------------------------
def IDAPython_UnLoadProcMod(script, g):
    """
    Unload processor module.
    """
    pname = g['__name__'] if g and g.has_key("__name__") else '__main__'
    parent = sys.modules[pname]

    scriptname = os.path.split(script)[1]
    procmod_name = os.path.splitext(scriptname)[0]
    if getattr(parent, procmod_name, None):
        delattr(parent, procmod_name)
        del sys.modules[procmod_name]
    PY_COMPILE_ERR = None
    return PY_COMPILE_ERR

# ----------------------------------------------------------------------
class __IDAPython_Completion_Util(object):
    """Internal utility class for auto-completion support"""
    def __init__(self):
        self.n = 0
        self.completion = None
        self.lastmodule = None

    @staticmethod
    def parse_identifier(line, prefix, prefix_start):
        """
        Parse a line and extracts identifier
        """
        id_start = prefix_start
        while id_start > 0:
            ch = line[id_start]
            if not ch.isalpha() and ch != '.' and ch != '_':
                id_start += 1
                break
            id_start -= 1

        return line[id_start:prefix_start + len(prefix)]

    @staticmethod
    def dir_of(m, prefix):
        return [x for x in dir(m) if x.startswith(prefix)]

    @classmethod
    def get_completion(cls, id, prefix):
        try:
            m = sys.modules['__main__']

            parts = id.split('.')
            c = len(parts)

            for i in xrange(0, c-1):
                m = getattr(m, parts[i])
        except Exception as e:
            return (None, None)
        else:
            # search in the module
            completion = cls.dir_of(m, prefix)

            # no completion found? looking from the global scope? then try the builtins
            if not completion and c == 1:
                completion = cls.dir_of(__builtin__, prefix)

            return (m, completion) if completion else (None, None)

    def __call__(self, prefix, n, line, prefix_start):
        if n == 0:
            self.n = n
            id = self.parse_identifier(line, prefix, prefix_start)
            self.lastmodule, self.completion = self.get_completion(id, prefix)

        if self.completion is None or n >= len(self.completion):
            return None

        s = self.completion[n]
        try:
            attr = getattr(self.lastmodule, s)
            # Is it callable?
            if callable(attr):
                return s + ("" if line.startswith("?") else "(")
            # Is it iterable?
            elif isinstance(attr, basestring) or getattr(attr, '__iter__', False):
                return s + "["
        except:
            pass

        return s

# Instantiate a completion object
IDAPython_Completion = __IDAPython_Completion_Util()



# The general callback format of notify_when() is:
#    def notify_when_callback(nw_code)
# In the case of NW_OPENIDB, the callback is:
#    def notify_when_callback(nw_code, is_old_database)
NW_OPENIDB    = 0x0001
"""Notify when the database is opened. Its callback is of the form: def notify_when_callback(nw_code, is_old_database)"""
NW_CLOSEIDB   = 0x0002
"""Notify when the database is closed. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_INITIDA    = 0x0004
"""Notify when the IDA starts. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_TERMIDA    = 0x0008
"""Notify when the IDA terminates. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_REMOVE     = 0x0010
"""Use this flag with other flags to uninstall a notifywhen callback"""

#</pycode(py_idaapi)>
%}

%include "pro.i"

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
#ifdef WITH_HEXRAYS
  %include "hexrays.i"
#endif

%inline %{

//<inline(py_idaapi)>
//------------------------------------------------------------------------
/*
#<pydoc>
def parse_command_line(cmdline):
    """
    Parses a space separated string (quotes and escape character are supported)
    @param cmdline: The command line to parse
    @return: A list of strings or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *py_parse_command_line(const char *cmdline)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t args;
  if ( parse_command_line3(cmdline, &args, NULL, LP_PATH_WITH_ARGS) == 0 )
    Py_RETURN_NONE;

  PyObject *py_list = PyList_New(args.size());
  for ( size_t i=0; i<args.size(); i++ )
    PyList_SetItem(py_list, i, PyString_FromString(args[i].c_str()));

  return py_list;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_inf_structure():
    """
    Returns the global variable 'inf' (an instance of idainfo structure, see ida.hpp)
    """
    pass
#</pydoc>
*/
idainfo *get_inf_structure(void)
{
  return &inf;
}

//-------------------------------------------------------------------------
// Declarations from Python.cpp
/*
#<pydoc>
def set_script_timeout(timeout):
    """
    Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses.
    See also L{disable_script_timeout}.

    @param timeout: This value is in seconds.
                    If this value is set to zero then the script will never timeout.
    @return: Returns the old timeout value
    """
    pass
#</pydoc>
*/
int set_script_timeout(int timeout);

/*
#<pydoc>
def disable_script_timeout():
    """
    Disables the script timeout and hides the script wait box.
    Calling L{set_script_timeout} will not have any effects until the script is compiled and executed again

    @return: None
    """
    pass
#</pydoc>
*/
void disable_script_timeout();

/*
#<pydoc>
def enable_extlang_python(enable):
    """
    Enables or disables Python extlang.
    When enabled, all expressions will be evaluated by Python.
    @param enable: Set to True to enable, False otherwise
    """
    pass
#</pydoc>
*/
void enable_extlang_python(bool enable);
void enable_python_cli(bool enable);

/*
#<pydoc>
def RunPythonStatement(stmt):
    """
    This is an IDC function exported from the Python plugin.
    It is used to evaluate Python statements from IDC.
    @param stmt: The statement to evaluate
    @return: 0 - on success otherwise a string containing the error
    """
    pass
#</pydoc>
*/

/*
//---------------------------------------------------------------------------
// qstrvec_t wrapper
//---------------------------------------------------------------------------
DECLARE_PY_CLINKED_OBJECT(qstrvec_t);

static bool qstrvec_t_assign(PyObject *self, PyObject *other)
{
  qstrvec_t *lhs = qstrvec_t_get_clink(self);
  qstrvec_t *rhs = qstrvec_t_get_clink(other);
  if (lhs == NULL || rhs == NULL)
    return false;
  *lhs = *rhs;
  return true;
}

static PyObject *qstrvec_t_addressof(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    Py_RETURN_NONE;
  else
    return PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG)&sv->at(idx));
}


static bool qstrvec_t_set(
    PyObject *self,
    size_t idx,
    const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    return false;
  (*sv)[idx] = s;
  return true;
}

static bool qstrvec_t_from_list(
  PyObject *self,
  PyObject *py_list)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  return sv == NULL ? false : PyW_PyListToStrVec(py_list, *sv);
}

static size_t qstrvec_t_size(PyObject *self)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  return sv == NULL ? 0 : sv->size();
}

static PyObject *qstrvec_t_get(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    Py_RETURN_NONE;
  return PyString_FromString(sv->at(idx).c_str());
}

static bool qstrvec_t_add(PyObject *self, const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL )
    return false;
  sv->push_back(s);
  return true;
}

static bool qstrvec_t_clear(PyObject *self, bool qclear)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL )
    return false;

  if ( qclear )
    sv->qclear();
  else
    sv->clear();

  return true;
}

static bool qstrvec_t_insert(
    PyObject *self,
    size_t idx,
    const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    return false;
  sv->insert(sv->begin() + idx, s);
  return true;
}

static bool qstrvec_t_remove(PyObject *self, size_t idx)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    return false;

  sv->erase(sv->begin()+idx);
  return true;
}
*/
//---------------------------------------------------------------------------



//------------------------------------------------------------------------
/*
#<pydoc>
def notify_when(when, callback):
    """
    Register a callback that will be called when an event happens.
    @param when: one of NW_XXXX constants
    @param callback: This callback prototype varies depending on the 'when' parameter:
                     The general callback format:
                         def notify_when_callback(nw_code)
                     In the case of NW_OPENIDB:
                         def notify_when_callback(nw_code, is_old_database)
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool notify_when(int when, PyObject *py_callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( g_nw == NULL || !PyCallable_Check(py_callable) )
    return false;
  return g_nw->notify_when(when, py_callable);
}

//</inline(py_idaapi)>
%}

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
%include "view.i"
%include "graph.i"
%include "fpro.i"
