%module(docstring="IDA Plugin SDK API wrapper: pro",directors="1",threads="1") ida_pro
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_PRO
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_PRO
  #define HAS_DEP_ON_INTERFACE_PRO
#endif
%include "header.i"

%ignore user2str;
%ignore back_char;
%ignore qstr2user;
%ignore user2qstr;
%ignore str2user;
%rename (str2user) py_str2user;
%ignore convert_encoding;
%ignore is_valid_utf8;
%ignore qustrlen;
%ignore get_utf8_char;
%ignore put_utf8_char;
%ignore prev_utf8_char;
%ignore idb_utf8;
%ignore scr_utf8;
%ignore utf8_scr;
%ignore change_codepage;
%ignore utf16_utf8;
%ignore utf8_utf16;
%ignore acp_utf8;
%ignore utf8_wchar16;
%ignore utf8_wchar32;
%ignore skip_utf8;
%ignore qustrncpy;
%ignore expand_argv;
%ignore free_argv;
%ignore qwait;
%ignore qwait_for_handles;
%ignore qwait_timed;
%ignore ida_true_type;
%ignore ida_false_type;
%ignore bitcount;
%ignore round_up_power2;
%ignore round_down_power2;

//<typemaps(pro)>
%typemap(check) (char * buf, size_t bufsize, const char * s1, ... )
{
if ( $1 == NULL )
  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$1_type'");
}
%typemap(check) (char * buf, size_t bufsize, const char * base, const char * ext)
{
if ( $1 == NULL )
  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$1_type'");
}
//</typemaps(pro)>

%include "pro.h"

// we must include those manually here
%import "ida.hpp"
%import "xref.hpp"
%import "typeinf.hpp"
%import "enum.hpp"
%import "netnode.hpp"
//

void qvector<int>::grow(const int &x=0);
%ignore qvector<int>::grow;
void qvector<unsigned int>::grow(const unsigned int &x=0);
%ignore qvector<unsigned int>::grow;
void qvector<long long>::grow(const long long &x=0);
%ignore qvector<long long>::grow;
void qvector<unsigned long long>::grow(const unsigned long long &x=0);
%ignore qvector<unsigned long long>::grow;

//---------------------------------------------------------------------
%template(intvec_t)       qvector<int>;
%template(uintvec_t)      qvector<unsigned int>;
%template(longlongvec_t)  qvector<long long>;
%template(ulonglongvec_t) qvector<unsigned long long>;
%template(boolvec_t)      qvector<bool>;

%pythoncode %{
%}


%uncomparable_elements_qvector(simpleline_t, strvec_t);
%template(sizevec_t)  qvector<size_t>;
typedef uvalvec_t eavec_t;// vector of addresses

SWIG_DECLARE_PY_CLINKED_OBJECT(qstrvec_t)

%inline %{
//<inline(py_pro)>
//---------------------------------------------------------------------------
// qstrvec_t wrapper (INTERNAL! Don't expose. See py_idaapi.py)
//---------------------------------------------------------------------------
static bool qstrvec_t_assign(PyObject *self, PyObject *other)
{
  qstrvec_t *lhs = qstrvec_t_get_clink(self);
  qstrvec_t *rhs = qstrvec_t_get_clink(other);
  if ( lhs == NULL || rhs == NULL )
    return false;
  *lhs = *rhs;
  return true;
}

static PyObject *qstrvec_t_addressof(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
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
  if ( sv == NULL || idx >= sv->size() )
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
  return (sv == NULL || !PySequence_Check(py_list))
       ? false
       : (PyW_PyListToStrVec(sv, py_list) >= 0);
}

static size_t qstrvec_t_size(PyObject *self)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  return sv == NULL ? 0 : sv->size();
}

static PyObject *qstrvec_t_get(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    Py_RETURN_NONE;
  return IDAPyStr_FromUTF8(sv->at(idx).c_str());
}

static bool qstrvec_t_add(PyObject *self, const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL )
    return false;
  sv->push_back(s);
  return true;
}

static bool qstrvec_t_clear(PyObject *self, bool qclear)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL )
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
  if ( sv == NULL || idx >= sv->size() )
    return false;
  sv->insert(sv->begin() + idx, s);
  return true;
}

static bool qstrvec_t_remove(PyObject *self, size_t idx)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
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
  qstring retstr;
  qstr2user(&retstr, str);
  return IDAPyStr_FromUTF8(retstr.c_str());
}
//</inline(py_pro)>
%}

%include "carrays.i"
%include "cpointer.i"
%array_class(uchar, uchar_array);
%array_class(tid_t, tid_array);
%array_class(ea_t, ea_array);
%array_class(sel_t, sel_array);
%array_class(uval_t, uval_array);
%pointer_class(int, int_pointer);
%pointer_class(ea_t, ea_pointer);
%pointer_class(sval_t, sval_pointer);
%pointer_class(sel_t, sel_pointer);

%pythoncode %{
#<pycode(py_pro)>
import ida_idaapi

int64vec_t = longlongvec_t
uint64vec_t = ulonglongvec_t
if ida_idaapi.__EA64__:
    svalvec_t = longlongvec_t
    uvalvec_t = ulonglongvec_t
else:
    svalvec_t = intvec_t
    uvalvec_t = uintvec_t

ida_idaapi._listify_types(
        intvec_t,
        uintvec_t,
        longlongvec_t,
        ulonglongvec_t,
        boolvec_t,
        strvec_t)

# -----------------------------------------------------------------------
# qstrvec_t clinked object
class _qstrvec_t(ida_idaapi.py_clinked_object_t):
    """
    WARNING: It is very unlikely an IDAPython user should ever, ever
    have to use this type. It should only be used for IDAPython internals.

    For example, in py_askusingform.py, we ctypes-expose to the IDA
    kernel & UI a qstrvec instance, in case a DropdownListControl is
    constructed.
    That's because that's what ask_form expects, and we have no
    choice but to make a DropdownListControl hold a qstrvec_t.
    This is, afaict, the only situation where a Python
    _qstrvec_t is required.
    """

    def __init__(self, items=None):
        ida_idaapi.py_clinked_object_t.__init__(self)
        # Populate the list if needed
        if items:
            self.from_list(items)

    def _create_clink(self):
        return _ida_pro.qstrvec_t_create()

    def _del_clink(self, lnk):
        return _ida_pro.qstrvec_t_destroy(lnk)

    def _get_clink_ptr(self):
        return _ida_pro.qstrvec_t_get_clink_ptr(self)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _ida_pro.qstrvec_t_assign(self, other)

    def __setitem__(self, idx, s):
        """Sets string at the given index"""
        return _ida_pro.qstrvec_t_set(self, idx, s)

    def __getitem__(self, idx):
        """Gets the string at the given index"""
        return _ida_pro.qstrvec_t_get(self, idx)

    def __get_size(self):
        return _ida_pro.qstrvec_t_size(self)

    size = property(__get_size)
    """Returns the count of elements"""

    def addressof(self, idx):
        """Returns the address (as number) of the qstring at the given index"""
        return _ida_pro.qstrvec_t_addressof(self, idx)

    def add(self, s):
        """Add a string to the vector"""
        return _ida_pro.qstrvec_t_add(self, s)

    def from_list(self, lst):
        """Populates the vector from a Python string list"""
        return _ida_pro.qstrvec_t_from_list(self, lst)

    def clear(self, qclear=False):
        """
        Clears all strings from the vector.
        @param qclear: Just reset the size but do not actually free the memory
        """
        return _ida_pro.qstrvec_t_clear(self, qclear)

    def insert(self, idx, s):
        """Insert a string into the vector"""
        return _ida_pro.qstrvec_t_insert(self, idx, s)

    def remove(self, idx):
        """Removes a string from the vector"""
        return _ida_pro.qstrvec_t_remove(self, idx)

#</pycode(py_pro)>
%}
%pythoncode %{
if _BC695:
    def strlwr(s):
        return str(s).lower()
    def strupr(s):
        return str(s).upper()

%}