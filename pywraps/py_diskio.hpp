#ifndef __PY_IDA_DISKIO__
#define __PY_IDA_DISKIO__

//<code(py_diskio)>
//--------------------------------------------------------------------------
int idaapi py_enumerate_files_cb(const char *file, void *ud)
{
  // No need to 'PYW_GIL_GET' here, as this is called synchronously
  // and from the same thread as the one that executes
  // 'py_enumerate_files'.
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_file(PyUnicode_FromString(file));
  newref_t py_ret(
          PyObject_CallFunctionObjArgs(
                  (PyObject *)ud,
                  py_file.o,
                  nullptr));
  return (!py_ret || !PyNumber_Check(py_ret.o)) ? 1 /* stop enum on failure */ : PyInt_AsLong(py_ret.o);
}

//-------------------------------------------------------------------------
struct bytearray_linput_data_t
{
  linput_t *li;
  qstring *bytes;
};
DECLARE_TYPE_AS_MOVABLE(bytearray_linput_data_t);
typedef qvector<bytearray_linput_data_t> bytearray_linput_data_vec_t;
static bytearray_linput_data_vec_t bytearray_linput_data_vec;
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
  PYW_GIL_CHECK_LOCKED_SCOPE();

  do
  {
    if ( !PyUnicode_Check(path) || !PyUnicode_Check(fname) || !PyCallable_Check(callback) )
      break;

    qstring _path;
    qstring _fname;
    if ( !PyUnicode_as_qstring(&_path, path) || !PyUnicode_as_qstring(&_fname, fname) )
      break;

    char answer[MAXSTR];
    answer[0] = '\0';
    int r = enumerate_files(
            answer, sizeof(answer),
            _path.c_str(),
            _fname.c_str(),
            py_enumerate_files_cb, callback);
    return Py_BuildValue("(is)", r, answer);
  } while ( false );
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
linput_t *py_create_bytearray_linput(const qstring &s)
{
  qstring *bytes = new qstring(s);
  linput_t *li = create_bytearray_linput((const uchar *) bytes->c_str(), bytes->length());
  if ( li != nullptr )
  {
    bytearray_linput_data_t &ld = bytearray_linput_data_vec.push_back();
    ld.bytes = bytes;
    ld.li = li;
  }
  else
  {
    delete bytes;
  }
  return li;
}

//-------------------------------------------------------------------------
void py_close_linput(linput_t *li)
{
  bytearray_linput_data_vec_t::iterator it = bytearray_linput_data_vec.begin();
  bytearray_linput_data_vec_t::iterator end = bytearray_linput_data_vec.end();
  for ( ; it != end; ++it )
  {
    if ( it->li == li )
    {
      delete it->bytes;
      bytearray_linput_data_vec.erase(it);
      break;
    }
  }
  close_linput(li);
}

//</inline(py_diskio)>

#endif
