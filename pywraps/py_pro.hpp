//<inline(py_pro)>
//---------------------------------------------------------------------------
// qstrvec_t wrapper (INTERNAL! Don't expose. See py_idaapi.py)
//---------------------------------------------------------------------------
static bool qstrvec_t_assign(PyObject *self, PyObject *other)
{
  qstrvec_t *lhs = qstrvec_t_get_clink(self);
  qstrvec_t *rhs = qstrvec_t_get_clink(other);
  if ( lhs == nullptr || rhs == nullptr )
    return false;
  *lhs = *rhs;
  return true;
}

static PyObject *qstrvec_t_addressof(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == nullptr || idx >= sv->size() )
    Py_RETURN_NONE;
  else
    return PyLong_FromUnsignedLongLong(size_t(&sv->at(idx)));
}


static bool qstrvec_t_set(
        PyObject *self,
        size_t idx,
        const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == nullptr || idx >= sv->size() )
    return false;
  (*sv)[idx] = s;
  return true;
}

static bool qstrvec_t_from_list(
        PyObject *self,
        PyObject *py_list)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  return (sv == nullptr || !PySequence_Check(py_list))
       ? false
       : (PyW_PySeqToStrVec(sv, py_list) >= 0);
}

static size_t qstrvec_t_size(PyObject *self)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  return sv == nullptr ? 0 : sv->size();
}

static PyObject *qstrvec_t_get(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == nullptr || idx >= sv->size() )
    Py_RETURN_NONE;
  return PyUnicode_FromString(sv->at(idx).c_str());
}

static bool qstrvec_t_add(PyObject *self, const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == nullptr )
    return false;
  sv->push_back(s);
  return true;
}

static bool qstrvec_t_clear(PyObject *self, bool qclear)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == nullptr )
    return false;

  if ( qclear )
    sv->qclear();
  else
    sv->clear();

  return true;
}

static bool qstrvec_t_insert(
        PyObject *self,
        size_t idx,
        const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == nullptr || idx >= sv->size() )
    return false;
  sv->insert(sv->begin() + idx, s);
  return true;
}

static bool qstrvec_t_remove(PyObject *self, size_t idx)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == nullptr || idx >= sv->size() )
    return false;

  sv->erase(sv->begin()+idx);
  return true;
}


//------------------------------------------------------------------------
/*
#<pydoc>
def str2user(str):
    """
    Insert C-style escape characters to string

    @return: new string with escape characters inserted
    """
    pass
#</pydoc>
*/
PyObject *py_str2user(const char *str)
{
  if ( str == nullptr )
    Py_RETURN_NONE;
  qstring retstr;
  qstr2user(&retstr, str);
  return PyUnicode_FromString(retstr.c_str());
}
//</inline(py_pro)>
