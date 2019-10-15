#ifndef EXTAPI_HPP
#define EXTAPI_HPP

#include <Python.h>

#ifdef Py_LIMITED_API
typedef void *Py_tracefunc;
struct PyCompilerFlags;
struct PyFrameObject;
#else
#include <frameobject.h>
#endif

typedef void PyEval_SetTrace_t(Py_tracefunc, PyObject *);

typedef int PyRun_SimpleString_t(const char *);
typedef PyObject *PyRun_String_t(const char *, int, PyObject *, PyObject *);

typedef PyObject *PyFunction_New_t(PyObject *, PyObject *);
typedef PyObject *PyFunction_GetCode_t(PyObject *);

typedef int _PyLong_AsByteArray_t(PyObject *, unsigned char *, size_t, int, int);

struct ext_api_t
{
  qstring lib_path;
  void *lib_handle;

  PyEval_SetTrace_t *PyEval_SetTrace_ptr;
  PyRun_SimpleString_t *PyRun_SimpleString_ptr;
  PyRun_String_t *PyRun_String_ptr;
  PyFunction_New_t *PyFunction_New_ptr;
  PyFunction_GetCode_t *PyFunction_GetCode_ptr;
  _PyLong_AsByteArray_t *_PyLong_AsByteArray_ptr;

  ext_api_t() { memset(this, 0, sizeof(*this)); }
  ~ext_api_t() { clear(); }

  bool load(qstring *errbuf);
  void clear();
};

#endif // EXTAPI_HPP
