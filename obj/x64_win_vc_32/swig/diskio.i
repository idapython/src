%module(docstring="IDA Plugin SDK API wrapper: diskio",directors="1",threads="1") ida_diskio
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_DISKIO
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_DISKIO
  #define HAS_DEP_ON_INTERFACE_DISKIO
#endif
%include "header.i"
%{
#include <diskio.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include "../../../pywraps.hpp"
%}

// TODO: These could be wrapped
%ignore enumerate_files;
%rename (enumerate_files) py_enumerate_files;
%ignore ioport_bit_t;
%ignore ioport_bits_t;
%ignore ioport_t;
%ignore read_ioports;
%ignore choose_ioport_device;
%ignore find_ioport;
%ignore find_ioport_bit;
%ignore free_ioports;
%ignore lread;
%ignore qlread;
%ignore qlgets;
%ignore qlgetc;
%ignore lreadbytes;
%ignore lread2bytes;
%ignore lread2bytes;
%ignore lread4bytes;
%ignore lread4bytes;
%ignore lread8bytes;
%ignore lread8bytes;
%ignore qlsize;
%ignore qlseek;
%ignore qltell;
%ignore qlfile;
%ignore make_linput;
%ignore unmake_linput;

%ignore eread;
%ignore ewrite;
%ignore eseek;
%ignore ecreate;
%ignore openR;
%ignore openRT;
%ignore openM;
// some of these functions are used in idc.py:
// %ignore eclose;
// %ignore fopenWT;
// %ignore fopenWB;
// %ignore fopenRT;
// %ignore fopenRB;
// %ignore fopenM;
// %ignore fopenA;

%ignore qfsize;
%ignore echsize;
%ignore get_free_disk_space;
%ignore call_system;

// Ignore kernel-only & unexported symbols
%ignore get_thread_priority;
%ignore lowdiskgo;
%ignore ida_argv;
%ignore exename;

%ignore create_bytearray_linput;
%rename (create_bytearray_linput) py_create_bytearray_linput;

%ignore close_linput;
%rename (close_linput) py_close_linput;

%apply qstrvec_t *out { qstrvec_t *dirs };

%cstring_output_buf_and_size_returning_charptr(
        1,
        char *buf,
        size_t bufsize,
        const char *filename,
        const char *subdir); // getsysfile
%cstring_output_buf_and_size_returning_charptr(
        3,
        linput_t *li,
        int64 fpos,
        char *buf,
        size_t bufsize); // qlgetz

%include "diskio.hpp"

%{
//<code(py_diskio)>
//--------------------------------------------------------------------------
int idaapi py_enumerate_files_cb(const char *file, void *ud)
{
  // No need to 'PYW_GIL_GET' here, as this is called synchronously
  // and from the same thread as the one that executes
  // 'py_enumerate_files'.
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_file(IDAPyStr_FromUTF8(file));
  newref_t py_ret(
          PyObject_CallFunctionObjArgs(
                  (PyObject *)ud,
                  py_file.o,
                  NULL));
  return (py_ret == NULL || !PyNumber_Check(py_ret.o)) ? 1 /* stop enum on failure */ : IDAPyInt_AsLong(py_ret.o);
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
%}

%inline %{
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
    if ( !IDAPyStr_Check(path) || !IDAPyStr_Check(fname) || !PyCallable_Check(callback) )
      break;

    const char *_path = IDAPyBytes_AsString(path);
    const char *_fname = IDAPyBytes_AsString(fname);
    if ( _path == NULL || _fname == NULL )
      break;

    char answer[MAXSTR];
    answer[0] = '\0';
    int r = enumerate_files(answer, sizeof(answer), _path, _fname, py_enumerate_files_cb, callback);
    return Py_BuildValue("(is)", r, answer);
  } while ( false );
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
linput_t *py_create_bytearray_linput(const qstring &s)
{
  qstring *bytes = new qstring(s);
  linput_t *li = create_bytearray_linput((const uchar *) bytes->c_str(), bytes->length());
  if ( li != NULL )
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
%}

%pythoncode %{
#<pycode(py_diskio)>
#</pycode(py_diskio)>
%}
%pythoncode %{
if _BC695:
    create_generic_linput64=create_generic_linput
    generic_linput64_t=generic_linput_t

%}