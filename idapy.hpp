#ifndef IDAPY_HPP
#define IDAPY_HPP 1

// This set of wrappers lets us keep the typemaps in an acceptable shape.
// Once IDAPython loses support for Python 2.7, these will go.

#ifdef PY3

inline int IDAPyInt_Check(PyObject *obj)
{
  return PyLong_Check(obj);
}

inline long IDAPyInt_AsLong(PyObject *io)
{
  return PyLong_AsLong(io);
}

inline Py_ssize_t IDAPyInt_AsSsize_t(PyObject *pylong)
{
  return PyLong_AsSsize_t(pylong);
}

inline PyObject *IDAPyInt_FromLong(long ival)
{
  return PyLong_FromLong(ival);
}

inline int IDAPyIntOrLong_Check(PyObject *obj)
{
  return PyLong_Check(obj);
}

inline long IDAPyIntOrLong_AsLong(PyObject *obj)
{
  return PyLong_AsLong(obj);
}

inline int IDAPyStr_Check(PyObject *obj)
{
  return PyUnicode_Check(obj);
}

inline bool IDAPyStr_AsUTF8(qstring *out, PyObject *obj)
{
  PyObject *utf8 = PyUnicode_AsUTF8String(obj);
  bool ok = utf8 != NULL;
  if ( ok )
  {
    char *buffer = NULL;
    Py_ssize_t length = 0;
    ok = PyBytes_AsStringAndSize(utf8, &buffer, &length) >= 0;
    if ( ok )
    {
      out->qclear();
      out->append(buffer, length);
    }
  }
  Py_XDECREF(utf8);
  return ok;
}

inline PyObject *IDAPyStr_FromUTF8(const char *v)
{
  return PyUnicode_FromString(v);
}

inline PyObject *IDAPyStr_FromUTF8AndSize(const char *v, Py_ssize_t len)
{
  return PyUnicode_FromStringAndSize(v, len);
}

inline int IDAPyBytes_Check(PyObject *obj)
{
  return PyBytes_Check(obj);
}

inline int IDAPyBytes_Size(PyObject *obj)
{
  return PyBytes_Size(obj);
}

inline PyObject *IDAPyBytes_FromMem(const char *v)
{
  return PyBytes_FromString(v);
}

inline PyObject *IDAPyBytes_FromMemAndSize(const char *v, Py_ssize_t len)
{
  return PyBytes_FromStringAndSize(v, len);
}

inline int IDAPyBytes_AsMemAndSize(PyObject *obj, char **buffer, Py_ssize_t *length)
{
  return PyBytes_AsStringAndSize(obj, buffer, length);
}

inline char *IDAPyBytes_AsString(PyObject *o)
{
  return PyBytes_AsString(o);
}

#else

inline int IDAPyInt_Check(PyObject *obj)
{
  return PyInt_Check(obj);
}

inline long IDAPyInt_AsLong(PyObject *io)
{
  return PyInt_AsLong(io);
}

inline Py_ssize_t IDAPyInt_AsSsize_t(PyObject *pylong)
{
  return PyInt_AsSsize_t(pylong);
}

inline PyObject *IDAPyInt_FromLong(long ival)
{
  return PyInt_FromLong(ival);
}

inline int IDAPyIntOrLong_Check(PyObject *obj)
{
  return PyInt_Check(obj) || PyLong_Check(obj);
}

inline long IDAPyIntOrLong_AsLong(PyObject *obj)
{
  return PyInt_Check(obj) ? PyInt_AsLong(obj) : PyLong_AsLong(obj);
}

inline int IDAPyStr_Check(PyObject *obj)
{
  return PyString_Check(obj);
}

inline bool IDAPyStr_AsUTF8(qstring *out, PyObject *obj)
{
  char *buffer = NULL;
  Py_ssize_t length = 0;
  bool ok = PyString_AsStringAndSize(obj, &buffer, &length) >= 0;
  if ( ok )
  {
    out->qclear();
    out->append(buffer, length);
  }
  return ok;
}

inline PyObject *IDAPyStr_FromUTF8(const char *v)
{
  return PyString_FromString(v);
}

inline int IDAPyBytes_Check(PyObject *obj)
{
  return PyString_Check(obj);
}

inline int IDAPyBytes_Size(PyObject *obj)
{
  return PyString_Size(obj);
}

inline PyObject *IDAPyBytes_FromMem(const char *v)
{
  return PyString_FromString(v);
}

inline PyObject *IDAPyBytes_FromMemAndSize(const char *v, Py_ssize_t len)
{
  return PyString_FromStringAndSize(v, len);
}

inline int IDAPyBytes_AsMemAndSize(PyObject *obj, char **buffer, Py_ssize_t *length)
{
  return PyString_AsStringAndSize(obj, buffer, length);
}

inline char *IDAPyBytes_AsString(PyObject *o)
{
  return PyString_AsString(o);
}

#endif


//-------------------------------------------------------------------------
// common code
//-------------------------------------------------------------------------

inline bool IDAPyBytes_AsBytes(bytevec_t *out, PyObject *obj)
{
  char *buffer = NULL;
  Py_ssize_t length = 0;
  bool ok = IDAPyBytes_AsMemAndSize(obj, &buffer, &length) >= 0;
  if ( ok )
  {
    out->qclear();
    out->append((const uchar *) buffer, length);
  }
  return ok;
}

inline bool IDAPyBytes_as_qtype(qtype *out, PyObject *obj)
{
  bytevec_t bytes;
  bool ok = IDAPyBytes_AsBytes(&bytes, obj);
  if ( ok )
  {
    out->qclear();
    out->append(bytes.begin(), bytes.size());
  }
  return ok;
}

#endif // IDAPY_HPP