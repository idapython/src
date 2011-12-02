#ifndef __PY_IDA_DISKIO__
#define __PY_IDA_DISKIO__

//<code(py_diskio)>
//--------------------------------------------------------------------------
int idaapi py_enumerate_files_cb(const char *file, void *ud)
{
  PyObject *py_file = PyString_FromString(file);
  PYW_GIL_ENSURE;
  PyObject *py_ret  = PyObject_CallFunctionObjArgs(
    (PyObject *)ud, 
    py_file, 
    NULL);
  PYW_GIL_RELEASE;
  int r = (py_ret == NULL || !PyNumber_Check(py_ret)) ? 1 /* stop enumeration on failure */ : PyInt_AsLong(py_ret);
  Py_XDECREF(py_file);
  Py_XDECREF(py_ret);
  return r;
}
//</code(py_diskio)>

//<inline(py_diskio)>
//--------------------------------------------------------------------------
/*
#<pydoc>
def enumerate_files(path, fname, callback):
    """
    Enumerate files in the specified directory while the callback returns 0.
    @param path: directory to enumerate files in
    @param fname: mask of file names to enumerate
    @param callback: a callable object that takes the filename as
                     its first argument and it returns 0 to continue
                     enumeration or non-zero to stop enumeration.
    @return: 
        None in case of script errors
        tuple(code, fname) : If the callback returns non-zero
    """
    pass
#</pydoc>
*/
PyObject *py_enumerate_files(PyObject *path, PyObject *fname, PyObject *callback)
{
  do
  {
    if ( !PyString_Check(path) || !PyString_Check(fname) || !PyCallable_Check(callback) )
      break;

    const char *_path = PyString_AsString(path);
    const char *_fname = PyString_AsString(fname);
    if ( _path == NULL || _fname == NULL )
      break;

    char answer[MAXSTR];
    answer[0] = '\0';
    int r = enumerate_files(answer, sizeof(answer), _path, _fname, py_enumerate_files_cb, callback);
    return Py_BuildValue("(is)", r, answer);
  } while ( false );
  Py_RETURN_NONE;
}
//</inline(py_diskio)>

#endif
