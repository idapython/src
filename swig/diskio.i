// TODO: These could be wrapped
%ignore enumerate_files;
%rename (enumerate_files) py_enumerate_files;
%ignore enumerate_system_files;
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
%ignore efilelength;
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
%ignore create_remote_linput;
%ignore make_filehandle_linput;

// FIXME: These should be wrapped for completeness
%ignore eread;
%ignore ewrite;

// Ignore kernel-only & unexported symbols
%ignore get_thread_priority;
%ignore set_thread_priority;
%ignore checkdspace;
%ignore lowdiskgo;
%ignore ida_argv;
%ignore exename;

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
  newref_t py_file(PyString_FromString(file));
  newref_t py_ret(
          PyObject_CallFunctionObjArgs(
                  (PyObject *)ud,
                  py_file.o,
                  NULL));
  return (py_ret == NULL || !PyNumber_Check(py_ret.o)) ? 1 /* stop enum on failure */ : PyInt_AsLong(py_ret.o);
}
//</code(py_diskio)>
%}

%inline %{
//<inline(py_diskio)>
/*
#<pydoc>
class loader_input_t(pyidc_opaque_object_t):
    """A helper class to work with linput_t related functions.
    This class is also used by file loaders scripts.
    """
    def __init__(self):
        pass

    def close(self):
        """Closes the file"""
        pass

    def open(self, filename, remote = False):
        """Opens a file (or a remote file)
        @return: Boolean
        """
        pass

    def set_linput(self, linput):
        """Links the current loader_input_t instance to a linput_t instance"""
        pass

    @staticmethod
    def from_fp(fp):
        """A static method to construct an instance from a FILE*"""
        pass

    def open_memory(self, start, size):
        """Create a linput for process memory (By internally calling idaapi.create_memory_linput())
        This linput will use dbg->read_memory() to read data
        @param start: starting address of the input
        @param size: size of the memory area to represent as linput
                    if unknown, may be passed as 0
        """
        pass

    def seek(self, pos, whence = SEEK_SET):
        """Set input source position
        @return: the new position (not 0 as fseek!)
        """
        pass

    def tell(self):
        """Returns the current position"""
        pass

    def getz(self, sz, fpos = -1):
        """Returns a zero terminated string at the given position
        @param sz: maximum size of the string
        @param fpos: if != -1 then seek will be performed before reading
        @return: The string or None on failure.
        """
        pass

    def gets(self, len):
        """Reads a line from the input file. Returns the read line or None"""
        pass

    def read(self, size):
        """Reads from the file. Returns the buffer or None"""
        pass

    def readbytes(self, size, big_endian):
        """Similar to read() but it respect the endianness"""
        pass

    def file2base(self, pos, ea1, ea2, patchable):
        """
        Load portion of file into the database
        This function will include (ea1..ea2) into the addressing space of the
        program (make it enabled)
        @param li: pointer ot input source
        @param pos: position in the file
        @param (ea1..ea2): range of destination linear addresses
        @param patchable: should the kernel remember correspondance of
                          file offsets to linear addresses.
        @return: 1-ok,0-read error, a warning is displayed
        """
        pass

    def get_char(self):
        """Reads a single character from the file. Returns None if EOF or the read character"""
        pass

    def opened(self):
        """Checks if the file is opened or not"""
        pass
#</pydoc>
*/
class loader_input_t
{
private:
  linput_t *li;
  int own;
  qstring fn;
  enum
  {
    OWN_NONE    = 0, // li not created yet
    OWN_CREATE  = 1, // Owns li because we created it
    OWN_FROM_LI = 2, // No ownership we borrowed the li from another class
    OWN_FROM_FP = 3, // We got an li instance from an fp instance, we have to unmake_linput() on Close
  };

  //--------------------------------------------------------------------------
  void _from_cobject(PyObject *pycobject)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    this->set_linput((linput_t *)PyCObject_AsVoidPtr(pycobject));
  }

  //--------------------------------------------------------------------------
  void assign(const loader_input_t &rhs)
  {
    fn = rhs.fn;
    li = rhs.li;
    own = OWN_FROM_LI;
  }

  //--------------------------------------------------------------------------
  loader_input_t(const loader_input_t &rhs)
  {
    assign(rhs);
  }
public:
  // Special attribute that tells the pyvar_to_idcvar how to convert this
  // class from and to IDC. The value of this variable must be set to two
  int __idc_cvt_id__;
  //--------------------------------------------------------------------------
  loader_input_t(PyObject *pycobject = NULL): li(NULL), own(OWN_NONE), __idc_cvt_id__(PY_ICID_OPAQUE)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( pycobject != NULL && PyCObject_Check(pycobject) )
      _from_cobject(pycobject);
  }

  //--------------------------------------------------------------------------
  void close()
  {
    if ( li == NULL )
      return;

    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    if ( own == OWN_CREATE )
      close_linput(li);
    else if ( own == OWN_FROM_FP )
      unmake_linput(li);
    Py_END_ALLOW_THREADS;
    li = NULL;
    own = OWN_NONE;
  }

  //--------------------------------------------------------------------------
  ~loader_input_t()
  {
    close();
  }

  //--------------------------------------------------------------------------
  bool open(const char *filename, bool remote = false)
  {
    close();
    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    li = open_linput(filename, remote);
    if ( li != NULL )
    {
      // Save file name
      fn = filename;
      own = OWN_CREATE;
    }
    Py_END_ALLOW_THREADS;
    return li != NULL;
  }

  //--------------------------------------------------------------------------
  void set_linput(linput_t *linput)
  {
    close();
    own = OWN_FROM_LI;
    li = linput;
    fn.sprnt("<linput_t * %p>", linput);
  }

  //--------------------------------------------------------------------------
  static loader_input_t *from_linput(linput_t *linput)
  {
    loader_input_t *l = new loader_input_t();
    l->set_linput(linput);
    return l;
  }

  //--------------------------------------------------------------------------
  // This method can be used to pass a linput_t* from C code
  static loader_input_t *from_cobject(PyObject *pycobject)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( !PyCObject_Check(pycobject) )
      return NULL;
    loader_input_t *l = new loader_input_t();
    l->_from_cobject(pycobject);
    return l;
  }

  //--------------------------------------------------------------------------
  static loader_input_t *from_fp(FILE *fp)
  {
    PYW_GIL_GET;
    loader_input_t *l = NULL;
    Py_BEGIN_ALLOW_THREADS;
    linput_t *fp_li = make_linput(fp);
    if ( fp_li != NULL )
    {
      l = new loader_input_t();
      l->own = OWN_FROM_FP;
      l->fn.sprnt("<FILE * %p>", fp);
      l->li = fp_li;
    }
    Py_END_ALLOW_THREADS;
    return l;
  }

  //--------------------------------------------------------------------------
  linput_t *get_linput()
  {
    return li;
  }

  //--------------------------------------------------------------------------
  bool open_memory(ea_t start, asize_t size = 0)
  {
    PYW_GIL_GET;
    linput_t *l;
    Py_BEGIN_ALLOW_THREADS;
    l = create_memory_linput(start, size);
    if ( l != NULL )
    {
      close();
      li = l;
      fn = "<memory>";
      own = OWN_CREATE;
    }
    Py_END_ALLOW_THREADS;
    return l != NULL;
  }

  //--------------------------------------------------------------------------
  int32 seek(int32 pos, int whence = SEEK_SET)
  {
    int32 r;
    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    r = qlseek(li, pos, whence);
    Py_END_ALLOW_THREADS;
    return r;
  }

  //--------------------------------------------------------------------------
  int32 tell()
  {
    int32 r;
    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    r = qltell(li);
    Py_END_ALLOW_THREADS;
    return r;
  }

  //--------------------------------------------------------------------------
  PyObject *getz(size_t sz, int32 fpos = -1)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(sz + 5);
      if ( buf == NULL )
        break;
      Py_BEGIN_ALLOW_THREADS;
      qlgetz(li, fpos, buf, sz);
      Py_END_ALLOW_THREADS;
      PyObject *ret = PyString_FromString(buf);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *gets(size_t len)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(len + 5);
      if ( buf == NULL )
        break;
      bool ok;
      Py_BEGIN_ALLOW_THREADS;
      ok = qlgets(buf, len, li) != NULL;
      Py_END_ALLOW_THREADS;
      if ( !ok )
      {
        free(buf);
        break;
      }
      PyObject *ret = PyString_FromString(buf);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *read(size_t size)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == NULL )
        break;
      ssize_t r;
      Py_BEGIN_ALLOW_THREADS;
      r = qlread(li, buf, size);
      Py_END_ALLOW_THREADS;
      if ( r == -1 )
      {
        free(buf);
        break;
      }
      PyObject *ret = PyString_FromStringAndSize(buf, r);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  bool opened()
  {
    return li != NULL;
  }

  //--------------------------------------------------------------------------
  PyObject *readbytes(size_t size, bool big_endian)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == NULL )
        break;
      int r;
      Py_BEGIN_ALLOW_THREADS;
      r = lreadbytes(li, buf, size, big_endian);
      Py_END_ALLOW_THREADS;
      if ( r == -1 )
      {
        free(buf);
        break;
      }
      PyObject *ret = PyString_FromStringAndSize(buf, r);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  int file2base(int32 pos, ea_t ea1, ea_t ea2, int patchable)
  {
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = ::file2base(li, pos, ea1, ea2, patchable);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  int32 size()
  {
    int32 rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qlsize(li);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  PyObject *filename()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    return PyString_FromString(fn.c_str());
  }

  //--------------------------------------------------------------------------
  PyObject *get_char()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int ch;
    Py_BEGIN_ALLOW_THREADS;
    ch = qlgetc(li);
    Py_END_ALLOW_THREADS;
    if ( ch == EOF )
      Py_RETURN_NONE;
    return Py_BuildValue("c", ch);
  }
};


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
%}

%pythoncode %{
#<pycode(py_diskio)>
def enumerate_system_files(subdir, fname, callback):
    """Similar to enumerate_files() however it searches inside IDA directory or its subdirectories"""
    return enumerate_files(idadir(subdir), fname, callback)
#</pycode(py_diskio)>
%}
