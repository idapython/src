#ifndef __PY_IDA_QFILE__
#define __PY_IDA_QFILE__

//<inline(py_qfile)>
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
        """Opens a file
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
        """Set input source position
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

    def get_char(self):
        """Reads a single character from the file. Returns None if EOF or the read character"""
        pass

    def put_char(self):
        """Writes a single character to the file"""
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
    if ( fp == NULL )
      return false;
    own = false;
    fn.sprnt("<FILE * %p>", fp);
    this->fp = fp;
    return true;
  }
  inline void _from_cobject(PyObject *pycobject)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    _from_fp((FILE *)PyCObject_AsVoidPtr(pycobject));
  }
public:
  int __idc_cvt_id__;
  //--------------------------------------------------------------------------
  qfile_t(const qfile_t &rhs)
  {
    assign(rhs);
  }

  //--------------------------------------------------------------------------
  qfile_t(PyObject *pycobject = NULL)
  {
    fp = NULL;
    own = true;
    fn.qclear();
    __idc_cvt_id__ = PY_ICID_OPAQUE;
    bool ok;
    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      ok = pycobject != NULL && PyCObject_Check(pycobject);
    }
    if ( ok )
      _from_cobject(pycobject);
  }

  //--------------------------------------------------------------------------
  bool opened()
  {
    return fp != NULL;
  }

  //--------------------------------------------------------------------------
  void close()
  {
    if ( fp == NULL )
      return;
    if ( own )
    {
      Py_BEGIN_ALLOW_THREADS;
      qfclose(fp);
      Py_END_ALLOW_THREADS;
    }
    fp = NULL;
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
    Py_BEGIN_ALLOW_THREADS;
    fp = qfopen(filename, mode);
    Py_END_ALLOW_THREADS;
    if ( fp == NULL )
      return false;
    // Save file name
    fn = filename;
    own = true;
    return true;
  }

  //--------------------------------------------------------------------------
  static qfile_t *from_fp(FILE *fp)
  {
    if ( fp == NULL )
      return NULL;
    qfile_t *qf = new qfile_t();
    qf->own = false;
    qf->fn.sprnt("<FILE * %p>", fp);
    qf->fp = fp;
    return qf;
  }

  //--------------------------------------------------------------------------
  // This method can be used to pass a FILE* from C code
  static qfile_t *from_cobject(PyObject *pycobject)
  {
    return PyCObject_Check(pycobject) ? from_fp((FILE *)PyCObject_AsVoidPtr(pycobject)) : NULL;
  }

  //--------------------------------------------------------------------------
  static qfile_t *tmpfile()
  {
    FILE *fp;
    Py_BEGIN_ALLOW_THREADS;
    fp = qtmpfile();
    Py_END_ALLOW_THREADS;
    return from_fp(fp);
  }

  //--------------------------------------------------------------------------
  FILE *get_fp()
  {
    return fp;
  }

  //--------------------------------------------------------------------------
  int seek(int32 offset, int whence = SEEK_SET)
  {
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qfseek(fp, offset, whence);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  int32 tell()
  {
    int32 rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qftell(fp);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  PyObject *readbytes(int size, bool big_endian)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == NULL )
        break;
      PYW_GIL_CHECK_LOCKED_SCOPE();
      int r;
      Py_BEGIN_ALLOW_THREADS;
      r = freadbytes(fp, buf, size, big_endian);
      Py_END_ALLOW_THREADS;
      if ( r != 0 )
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
  PyObject *read(int size)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == NULL )
        break;
      PYW_GIL_CHECK_LOCKED_SCOPE();
      int r;
      Py_BEGIN_ALLOW_THREADS;
      r = qfread(fp, buf, size);
      Py_END_ALLOW_THREADS;
      if ( r <= 0 )
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
  PyObject *gets(int size)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == NULL )
        break;
      PYW_GIL_CHECK_LOCKED_SCOPE();
      char *p;
      Py_BEGIN_ALLOW_THREADS;
      p = qfgets(buf, size, fp);
      Py_END_ALLOW_THREADS;
      if ( p == NULL )
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
  int writebytes(PyObject *py_buf, bool big_endian)
  {
    Py_ssize_t sz;
    void *buf;
    PYW_GIL_CHECK_LOCKED_SCOPE();
    sz = PyString_GET_SIZE(py_buf);
    buf = (void *)PyString_AS_STRING(py_buf);
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = fwritebytes(fp, buf, int(sz), big_endian);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  int write(PyObject *py_buf)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( !PyString_Check(py_buf) )
      return 0;
    // Just so that there is no risk that the buffer returned by
    // 'PyString_AS_STRING' gets deallocated within the
    // Py_BEGIN|END_ALLOW_THREADS section.
    borref_t py_buf_ref(py_buf);
    void *p = (void *)PyString_AS_STRING(py_buf);
    Py_ssize_t sz = PyString_GET_SIZE(py_buf);
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qfwrite(fp, p, sz);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  int puts(const char *str)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qfputs(str, fp);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  int32 size()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int32 r;
    Py_BEGIN_ALLOW_THREADS;
    int pos = qfseek(fp, 0, SEEK_END);
    r = qftell(fp);
    qfseek(fp, pos, SEEK_SET);
    Py_END_ALLOW_THREADS;
    return r;
  }

  //--------------------------------------------------------------------------
  int flush()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qflush(fp);
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
    ch = qfgetc(fp);
    Py_END_ALLOW_THREADS;
    if ( ch == EOF )
      Py_RETURN_NONE;
    return Py_BuildValue("c", ch);
  }

  //--------------------------------------------------------------------------
  int put_char(char chr)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qfputc(chr, fp);
    Py_END_ALLOW_THREADS;
    return rc;
  }
};
//</inline(py_qfile)>

#endif
