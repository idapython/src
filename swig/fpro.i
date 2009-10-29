%inline %{
//<inline(py_qfile)>
class qfile_t
{
private:
  FILE *fp;
  bool own;
  qstring fn;

  void assign(const qfile_t &rhs)
  {
    fn = rhs.fn;
    fp = rhs.fp;
    own = false;
  }
public:
  //--------------------------------------------------------------------------
  qfile_t(const qfile_t &rhs)
  {
    assign(rhs);
  }

  //--------------------------------------------------------------------------
  qfile_t()
  {
    fp = NULL;
    own = true;
    fn.qclear();
  }

  //--------------------------------------------------------------------------
  bool opened()
  {
    return fp != NULL;
  }

  //--------------------------------------------------------------------------
  void close()
  {
    if (fp == NULL)
      return;
    if (own)
      qfclose(fp);
    fp = NULL;
  }

  //--------------------------------------------------------------------------
  ~qfile_t()
  {
    close();
  }

  //--------------------------------------------------------------------------
  PyObject *open(const char *filename, const char *mode)
  {
    close();
    fp = qfopen(filename, mode);
    if (fp == NULL)
      Py_RETURN_FALSE;
    // Save file name
    fn = filename;
    own = true;
    Py_RETURN_TRUE;
  }

  //--------------------------------------------------------------------------
  static qfile_t *from_fp(FILE *fp)
  {
    if (fp == NULL)
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
    return from_fp(qtmpfile());
  }

  //--------------------------------------------------------------------------
  FILE *get_fp()
  {
    return fp;
  }

  //--------------------------------------------------------------------------
  int seek(int32 offset, int whence = SEEK_SET)
  {
    return qfseek(fp, offset, whence);
  }

  //--------------------------------------------------------------------------
  int32 tell()
  {
    return qftell(fp);
  }

  //--------------------------------------------------------------------------
  PyObject *readbytes(int size, bool big_endian)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if (buf == NULL)
        break;
      int r = freadbytes(fp, buf, size, big_endian);
      if (r != 0)
      {
        free(buf);
        break;
      }
      PyObject *ret = PyString_FromStringAndSize(buf, r);
      free(buf);
      return ret;
    } while (false);
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *read(int size)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if (buf == NULL)
        break;
      int r = qfread(fp, buf, size);
      if (r <= 0)
      {
        free(buf);
        break;
      }
      PyObject *ret = PyString_FromStringAndSize(buf, r);
      free(buf);
      return ret;
    } while (false);
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *gets(int size)
  {
    do
    {
      char *buf = (char *) malloc(size + 5);
      if (buf == NULL)
        break;
      if (qfgets(buf, size, fp) == NULL)
      {
        free(buf);
        break;
      }
      PyObject *ret = PyString_FromString(buf);
      free(buf);
      return ret;
    } while (false);
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  int writebytes(PyObject *py_buf, bool big_endian)
  {
    int    sz = PyString_GET_SIZE(py_buf);
    void *buf = (void *)PyString_AS_STRING(py_buf);
    return fwritebytes(fp, buf, sz, big_endian);
  }

  //--------------------------------------------------------------------------
  int write(PyObject *py_buf)
  {
    size_t sz = PyString_GET_SIZE(py_buf);
    void *buf = (void *)PyString_AS_STRING(py_buf);
    return qfwrite(fp, buf, sz);
  }

  //--------------------------------------------------------------------------
  int puts(const char *str)
  {
    return qfputs(str, fp);
  }

  //--------------------------------------------------------------------------
  int32 size()
  {
    int pos = qfseek(fp, 0, SEEK_END);
    int32 r = qftell(fp);
    qfseek(fp, pos, SEEK_SET);
    return r;
  }

  //--------------------------------------------------------------------------
  int flush()
  {
    return qflush(fp);
  }

  //--------------------------------------------------------------------------
  PyObject *filename()
  {
    return PyString_FromString(fn.c_str());
  }

  //--------------------------------------------------------------------------
  PyObject *get_char()
  {
    int ch = qfgetc(fp);
    if (ch == EOF)
      Py_RETURN_NONE;
    return Py_BuildValue("c", ch);
  }

  //--------------------------------------------------------------------------
  int put_char(char chr)
  {
    return qfputc(chr, fp);
  }
};
//</inline(py_qfile)>
%}
