#include "py_diskio.hpp"

static PyObject *ex_enumfiles(PyObject * /*self*/, PyObject *args)
{
  PyObject *path, *fname, *callback;
  if ( !PyArg_ParseTuple(args, "OOO", &path, &fname, &callback) )
    return NULL;
  return py_enumerate_files(path, fname, callback);
}

//
//static PyObject *ex_linput_close(PyObject * /*self*/, PyObject *args)
//{
//  PyObject *obj;
//  if ( !PyArg_ParseTuple(args, "O", &obj) )
//    return NULL;
//  pyl_close(obj);
//  Py_RETURN_NONE;
//}
//
//static PyObject *ex_linput_open(PyObject *self, PyObject *args)
//{
//  PyObject *obj, *py_filename, *py_remote;
//  if ( !PyArg_ParseTuple(args, "OOO", &obj, &py_filename, &py_remote) )
//    return NULL;
//  return pyl_open(obj, py_filename, py_remote);
//}
//
//static PyObject *ex_linput_read(PyObject *self, PyObject *args)
//{
//  PyObject *obj, *py_size;
//  if ( !PyArg_ParseTuple(args, "OO", &obj, &py_size) )
//    return NULL;
//  return pyl_read(obj, py_size);
//}

static PyMethodDef py_methods_diskio[] =
{
  {"enumfiles",  ex_enumfiles, METH_VARARGS, ""},
  //{"tell", ex_linput_tell, METH_VARARGS, ""},
  //{"open", ex_linput_open, METH_VARARGS, ""},
  //{"size", ex_linput_tell, METH_VARARGS, ""},
  //{"read", ex_linput_read, METH_VARARGS, ""},
  //{"close", ex_linput_close, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
DRIVER_INIT_METHODS(diskio);