#ifndef EXTAPI_HPP
#define EXTAPI_HPP

#include <Python.h>

#ifdef Py_LIMITED_API
typedef void *Py_tracefunc;
struct PyCompilerFlags;
#  if PY_MAJOR_VERSION < 3 || PY_MINOR_VERSION < 9
struct PyFrameObject;
#  endif
#else
#  include <frameobject.h>
#endif

typedef void PyEval_SetTrace_t(Py_tracefunc, PyObject *);

typedef int PyRun_SimpleStringFlags_t(const char *, PyCompilerFlags *);
typedef PyObject *PyRun_StringFlags_t(const char *, int, PyObject *, PyObject *, PyCompilerFlags *);

#if PY_MAJOR_VERSION < 3
typedef PyObject *Py_CompileString_t(const char *, const char *, int);
#else
typedef PyObject *Py_CompileStringExFlags_t(const char *, const char *, int, PyCompilerFlags *, int);
#endif

typedef PyObject *PyFunction_New_t(PyObject *, PyObject *);
typedef PyObject *PyFunction_GetCode_t(PyObject *);

typedef int _PyLong_AsByteArray_t(PyObject *, unsigned char *, size_t, int, int);

typedef int  PyEval_ThreadsInitialized_t(void);
typedef void PyEval_InitThreads_t(void);

struct ext_api_t
{
  qstring lib_path;
  void *lib_handle;

  PyEval_SetTrace_t *PyEval_SetTrace_ptr;
  PyRun_SimpleStringFlags_t *PyRun_SimpleStringFlags_ptr;
  PyRun_StringFlags_t *PyRun_StringFlags_ptr;
#if PY_MAJOR_VERSION < 3
  Py_CompileString_t *Py_CompileString_ptr;
#else
  Py_CompileStringExFlags_t *Py_CompileStringExFlags_ptr;
#endif

  PyFunction_New_t *PyFunction_New_ptr;
  PyFunction_GetCode_t *PyFunction_GetCode_ptr;
  _PyLong_AsByteArray_t *_PyLong_AsByteArray_ptr;
  PyEval_ThreadsInitialized_t *PyEval_ThreadsInitialized_ptr;
  PyEval_InitThreads_t *PyEval_InitThreads_ptr;

  ext_api_t() { memset(this, 0, sizeof(*this)); }
  ~ext_api_t() { clear(); }

  bool load(qstring *errbuf);
  void clear();
};

extern ext_api_t extapi;

#endif // EXTAPI_HPP
