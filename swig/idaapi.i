%module(docstring="IDA Plugin SDK API wrapper",directors="1",threads="1") idaapi
// generate directors for all classes that have virtual methods
%feature("director");
// exceptions
%feature("nodirector") const_visitor_t;
%feature("nodirector") const_vloc_visitor_t;
%feature("nodirector") enumplace_t;
%feature("nodirector") generic_linput64_t;
%feature("nodirector") generic_linput_t;
%feature("nodirector") place_t;
%feature("nodirector") idaplace_t;
%feature("nodirector") qrefcnt_obj_t;
%feature("nodirector") qstring_printer_t;
%feature("nodirector") simpleline_place_t;
%feature("nodirector") structplace_t;
%feature("nodirector") type_mapper_t;
%feature("nodirector") type_visitor_t;
%feature("nodirector") vc_printer_t;
%feature("nodirector") vd_printer_t;
%feature("nodirector") vloc_visitor_t;
%feature("nodirector") qflow_chart_t;
%feature("nodirector") lowertype_helper_t;
%feature("nodirector") ida_lowertype_helper_t;
%warnfilter(473) user_lvar_visitor_t::get_info_mapping_for_saving; // Returning a pointer or reference in a director method is not recommended
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
#pragma SWIG nowarn=514 // Director base class 'x' has no virtual destructor.

%constant size_t SIZE_MAX = size_t(-1);
%{

#ifndef USE_DANGEROUS_FUNCTIONS
  #define USE_DANGEROUS_FUNCTIONS 1
#endif

#include <pro.h>

void raise_python_stl_bad_alloc(const std::bad_alloc &ba)
{
  Py_INCREF(PyExc_MemoryError);
  PyErr_SetString(PyExc_MemoryError, "Out of memory (bad_alloc)");
}

void raise_python_unknown_exception()
{
  Py_INCREF(PyExc_RuntimeError);
  PyErr_SetString(PyExc_RuntimeError, "Unknown exception");
}

void raise_python_stl_exception(const std::exception &e)
{
  const char *what = e.what();
  if ( what == NULL || what[0] == '\0' )
  {
    raise_python_unknown_exception();
  }
  else
  {
    Py_INCREF(PyExc_RuntimeError);
    PyErr_SetString(PyExc_RuntimeError, what);
  }
}

void raise_python_swig_director_exception(const Swig::DirectorException &e)
{
  Py_INCREF(PyExc_RuntimeError);
  PyErr_SetString(PyExc_RuntimeError, e.getMessage());
}

void raise_python_out_of_range_exception(const std::out_of_range &e)
{
  Py_INCREF(PyExc_RuntimeError);
  PyErr_SetString(PyExc_IndexError, e.what());
}

%}

%define %exception_set_default_handlers()
%exception {
    try
    {
      $action
    }
    catch ( const std::bad_alloc &ba ) { raise_python_stl_bad_alloc(ba); SWIG_fail; }
    catch ( const std::out_of_range &e ) { raise_python_out_of_range_exception(e); SWIG_fail; }
    catch ( const std::exception &e ) { raise_python_stl_exception(e); SWIG_fail; }
    catch ( const Swig::DirectorException &e ) { raise_python_swig_director_exception(e); SWIG_fail; }
    catch ( ... ) { raise_python_unknown_exception(); SWIG_fail; }
}
%enddef
%exception_set_default_handlers();

// Enable automatic docstring generation
%feature(autodoc,0);

%{
/* strnlen() arrived on OSX at v10.7. Provide it ourselves if needed. */
#ifdef __MAC__
#ifndef MAC_OS_X_VERSION_10_7
#define MAC_OS_X_VERSION_10_7 1070
#endif
#if (MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_7)
inline size_t strnlen(const char *s, size_t maxlen)
{
  const char *found = (const char *) memchr(s, 0, maxlen);
  return found != NULL ? size_t(found - s) : maxlen;
}
#endif
#endif
%}

%define SWIG_DECLARE_PY_CLINKED_OBJECT(type)
%inline %{
static PyObject *type##_create()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyCObject_FromVoidPtr(new type(), NULL);
}
static bool type##_destroy(PyObject *py_obj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCObject_Check(py_obj) )
    return false;
  delete (type *)PyCObject_AsVoidPtr(py_obj);
  return true;
}
static type *type##_get_clink(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return (type *)pyobj_get_clink(self);
}
static PyObject *type##_get_clink_ptr(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyLong_FromUnsignedLongLong(
          PTR2U64(pyobj_get_clink(self)));
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
#include "registry.hpp"
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
%include "idbhooks.i"
%include "netnode.i"
%include "nalt.i"

%include "allins.i"
%include "area.i"
%include "auto.i"
%include "bytes.i"
%include "custdata.i"
%include "dbg.i"
%include "diskio.i"
%include "linput.i"
%include "entry.i"
%include "enum.i"
%include "expr.i"
%include "fixup.i"
%include "frame.i"
%include "funcs.i"
%include "typeinf.i"
#ifdef WITH_HEXRAYS
  %include "hexrays.i"
#endif

SWIG_DECLARE_PY_CLINKED_OBJECT(qstrvec_t)

%{
PyObject *qstrvec2pylist(qstrvec_t &vec)
{
  size_t n = vec.size();
  PyObject *py_list = PyList_New(n);
  for ( size_t i=0; i < n; ++i )
    PyList_SetItem(py_list, i, PyString_FromString(vec[i].c_str()));
  return py_list;
}
%}

%inline %{
//<inline(py_idaapi)>
//</inline(py_idaapi)>
%}

%include "gdl.i"
%include "ints.i"
%include "kernwin.i"
%include "cli.i"
%include "choose.i"
%include "choose2.i"
%include "plgform.i"
%include "custview.i"
%include "askusingform.i"
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
%include "ua.i"
%include "xref.i"
%include "view.i"
%include "graph.i"
%include "fpro.i"
%include "registry.i"
