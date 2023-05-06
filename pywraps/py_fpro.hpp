#ifndef __PY_IDA_FPRO__
#define __PY_IDA_FPRO__

//<inline(py_fpro)>
/*
#<pydoc>
class qfile_t(pyidc_opaque_object_t):
    """A helper class to work with FILE related functions."""
    def __init__(self):
        pass

    def close(self):
        """Closes the file"""
        pass

    def open(self, filename, mode):
        """
        Opens a file

        @param filename: the file name
        @param mode: The mode string, ala fopen() style
        @return: Boolean
        """
        pass

    def set_linput(self, linput):
        """Links the current loader_input_t instance to a linput_t instance"""
        pass

    @staticmethod
    def tmpfile():
        """A static method to construct an instance using a temporary file"""
        pass

    def seek(self, pos, whence = SEEK_SET):
        """
        Set input source position
        @return: the new position (not 0 as fseek!)
        """
        pass

    def tell(self):
        """Returns the current position"""
        pass

    def gets(self, len):
        """Reads a line from the input file. Returns the read line or None"""
        pass

    def read(self, size):
        """Reads from the file. Returns the buffer or None"""
        pass

    def write(self, buf):
        """Writes to the file. Returns 0 or the number of bytes written"""
        pass

    def readbytes(self, size, big_endian):
        """Similar to read() but it respect the endianness"""
        pass

    def writebytes(self, size, big_endian):
        """Similar to write() but it respect the endianness"""
        pass

    def flush(self):
        pass

    def get_byte(self):
        """Reads a single byte from the file. Returns None if EOF or the read byte"""
        pass

    def put_byte(self):
        """Writes a single byte to the file"""
        pass

    def opened(self):
        """Checks if the file is opened or not"""
        pass
#</pydoc>
*/
class qfile_t
{
private:
  FILE *fp;
  bool own;
  qstring fn;

  //--------------------------------------------------------------------------
  void assign(const qfile_t &rhs)
  {
    fn = rhs.fn;
    fp = rhs.fp;
    own = false;
  }
  //--------------------------------------------------------------------------
  bool _from_fp(FILE *fp)
  {
    if ( fp == nullptr )
      return false;
    own = false;
    fn.sprnt("<FILE * %p>", fp);
    this->fp = fp;
    return true;
  }
  inline void _from_capsule(PyObject *pycapsule)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    _from_fp((FILE *) PyCapsule_GetPointer(pycapsule, VALID_CAPSULE_NAME));
  }
public:
  int __idc_cvt_id__;
  //--------------------------------------------------------------------------
  qfile_t(const qfile_t &rhs)
  {
    assign(rhs);
  }

  //--------------------------------------------------------------------------
  qfile_t(PyObject *pycapsule = nullptr)
  {
    fp = nullptr;
    own = true;
    fn.qclear();
    __idc_cvt_id__ = PY_ICID_OPAQUE;
    bool ok;
    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      ok = pycapsule != nullptr && PyCapsule_IsValid(pycapsule, VALID_CAPSULE_NAME);
    }
    if ( ok )
      _from_capsule(pycapsule);
  }

  //--------------------------------------------------------------------------
  bool opened()
  {
    return fp != nullptr;
  }

  //--------------------------------------------------------------------------
  void close()
  {
    if ( fp == nullptr )
      return;
    if ( own )
    {
      SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      qfclose(fp);
      SWIG_PYTHON_THREAD_END_ALLOW;
    }
    fp = nullptr;
    own = true;
  }

  //--------------------------------------------------------------------------
  ~qfile_t()
  {
    close();
  }

  //--------------------------------------------------------------------------
  bool open(const char *filename, const char *mode)
  {
    close();
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    fp = qfopen(filename, mode);
    SWIG_PYTHON_THREAD_END_ALLOW;
    if ( fp == nullptr )
      return false;
    // Save file name
    fn = filename;
    own = true;
    return true;
  }

  //--------------------------------------------------------------------------
  static qfile_t *from_fp(FILE *fp)
  {
    if ( fp == nullptr )
      return nullptr;
    qfile_t *qf = new qfile_t();
    qf->own = false;
    qf->fn.sprnt("<FILE * %p>", fp);
    qf->fp = fp;
    return qf;
  }

  //--------------------------------------------------------------------------
  // This method can be used to pass a FILE* from C code
  static qfile_t *from_capsule(PyObject *pycapsule)
  {
    return PyCapsule_IsValid(pycapsule, VALID_CAPSULE_NAME)
         ? from_fp((FILE *) PyCapsule_GetPointer(pycapsule, VALID_CAPSULE_NAME))
         : nullptr;
  }

  //--------------------------------------------------------------------------
  static qfile_t *tmpfile()
  {
    FILE *fp;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    fp = qtmpfile();
    SWIG_PYTHON_THREAD_END_ALLOW;
    return from_fp(fp);
  }

  //--------------------------------------------------------------------------
  FILE *get_fp()
  {
    return fp;
  }

  //--------------------------------------------------------------------------
  int seek(int64 offset, int whence = SEEK_SET)
  {
    int rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = qfseek(fp, offset, whence);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }

  //--------------------------------------------------------------------------
  int64 tell()
  {
    int64 rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = qftell(fp);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }

  //--------------------------------------------------------------------------
  PyObject *readbytes(int size, bool big_endian)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == nullptr )
        break;
      PYW_GIL_CHECK_LOCKED_SCOPE();
      int r;
      SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      r = freadbytes(fp, buf, size, big_endian);
      SWIG_PYTHON_THREAD_END_ALLOW;
      if ( r != 0 )
      {
        free(buf);
        break;
      }

      PyObject *ret = PyUnicode_FromStringAndSize(buf, r);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *read(int size)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == nullptr )
        break;
      PYW_GIL_CHECK_LOCKED_SCOPE();
      int r;
      SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      r = qfread(fp, buf, size);
      SWIG_PYTHON_THREAD_END_ALLOW;
      if ( r <= 0 )
      {
        free(buf);
        break;
      }
      PyObject *ret = PyUnicode_FromStringAndSize(buf, r);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *gets(int size)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == nullptr )
        break;
      PYW_GIL_CHECK_LOCKED_SCOPE();
      char *p;
      SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      p = qfgets(buf, size, fp);
      SWIG_PYTHON_THREAD_END_ALLOW;
      if ( p == nullptr )
      {
        free(buf);
        break;
      }
      PyObject *ret = PyUnicode_FromString(buf);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  int writebytes(PyObject *py_buf, bool big_endian)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    char *buf;
    Py_ssize_t sz;
    PyBytes_AsStringAndSize(py_buf, &buf, &sz);
    int rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = fwritebytes(fp, buf, int(sz), big_endian);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }

  //--------------------------------------------------------------------------
  int write(PyObject *py_buf)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( !PyUnicode_Check(py_buf) )
      return 0;
    // Just so that there is no risk that the buffer returned by
    borref_t py_buf_ref(py_buf);
    qstring buf;
    PyUnicode_as_qstring(&buf, py_buf);
    int rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = qfwrite(fp, buf.c_str(), buf.length());
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }

  //--------------------------------------------------------------------------
  int puts(const char *str)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = qfputs(str, fp);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }

  //--------------------------------------------------------------------------
  int64 size()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    qoff64_t r;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    int pos = qfseek(fp, 0, SEEK_END);
    r = qftell(fp);
    qfseek(fp, pos, SEEK_SET);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return r;
  }

  //--------------------------------------------------------------------------
  int flush()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = qflush(fp);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }

  //--------------------------------------------------------------------------
  PyObject *filename()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    return PyUnicode_FromString(fn.c_str());
  }

  //--------------------------------------------------------------------------
  PyObject *get_byte()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int ch;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    ch = qfgetc(fp);
    SWIG_PYTHON_THREAD_END_ALLOW;
    if ( ch == EOF )
      Py_RETURN_NONE;
    return Py_BuildValue("i", ch);
  }

  //--------------------------------------------------------------------------
  int put_byte(int chr)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = qfputc(chr, fp);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }
};
//</inline(py_fpro)>

#endif
