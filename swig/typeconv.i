//-------------------------------------------------------------------------
// For some reason, SWIG converts char arrays by computing the size
// from the end of the array, and stops when it encounters a '\0'.
// That doesn't work for us, as our API doesn't guarantee that
// bytes past the length we are interested in will be zeroed-out.
// In other words, the following code should *never* be present
// in idaapi_include.cpp:
// -------------------------
//  while (size && (<name-of-variable>[size - 1] == '\0')) --size;
// -------------------------
//
%typemap(out) char [ANY], const char[ANY]
{
  %set_output(SWIG_FromCharPtrAndSize($1, strnlen($1, $1_dim0)));
}

%typemap(varout) char [ANY], const char[ANY]
{
  %set_output(SWIG_FromCharPtrAndSize($1, strnlen($1, $1_dim0)));
}


%typemap(out) ssize_t
{
  $result = PyLong_FromLongLong($1);
}

//---------------------------------------------------------------------
// Convert an incoming Python list to a tid_t[] array
%typemap(in) tid_t[ANY](tid_t temp[$1_dim0]) {
    int i, len;

    if (!PySequence_Check($input))
    {
        PyErr_SetString(PyExc_TypeError,"Expecting a sequence");
        return NULL;
    }

    /* Cap the number of elements to copy */
    len = PySequence_Length($input) < $1_dim0 ? PySequence_Length($input) : $1_dim0;

    for (i =0; i < len; i++)
    {
        newref_t item(PySequence_GetItem($input,i));
        if (!PyLong_Check(item.o))
        {
            PyErr_SetString(PyExc_ValueError,"Expecting a sequence of long integers");
            return NULL;
        }

        temp[i] = PyLong_AsUnsignedLong(item.o);
    }
    $1 = &temp[0];
}

//-------------------------------------------------------------------------
// Same, but with non-fixed sized arrays.
%typemap(in) (const tid_t *path, int plen) (qvector<tid_t> temp) {
    if (!PySequence_Check($input))
    {
        PyErr_SetString(PyExc_TypeError,"Expecting a sequence");
        return NULL;
    }
    int plen = PySequence_Length($input);
    if ( plen <= 0 )
    {
        PyErr_SetString(PyExc_TypeError, "Sequence must have at least 1 item");
        return NULL;
    }
    temp.resize(plen);
    for ( int i =0; i < plen; ++i )
    {
        newref_t item(PySequence_GetItem($input,i));
        if (!PyLong_Check(item.o))
        {
            PyErr_SetString(PyExc_ValueError,"Expecting a sequence of long integers");
            return NULL;
        }

        temp[i] = PyLong_AsUnsignedLong(item.o);
    }
    $1 = temp.begin();
    $2 = int(temp.size());
}

//---------------------------------------------------------------------
%define %cstring_output_maxstr_none(TYPEMAP, SIZE)

%typemap (default) SIZE {
    $1 = MAXSTR;
 }

%typemap(in,numinputs=0) (TYPEMAP, SIZE) {
    $1 = ($1_ltype) qalloc(MAXSTR+1);
}

%typemap(argout) (TYPEMAP,SIZE) {
    Py_XDECREF(resultobj);
    if (result > 0)
    {
        resultobj = PyString_FromString($1);
    }
    else
    {
        Py_INCREF(Py_None);
        resultobj = Py_None;
    }
    qfree($1);
}
%enddef

//---------------------------------------------------------------------
%define %cstring_bounded_output_none(TYPEMAP,MAX)
%typemap(in, numinputs=0) TYPEMAP(char temp[MAX+1]) {
    $1 = ($1_ltype) temp;
}
%typemap(argout,fragment="t_output_helper") TYPEMAP {
    PyObject *o;
    $1[MAX] = 0;

    if ($1 > 0)
    {
        o = PyString_FromString($1);
    }
    else
    {
        o = Py_None;
        Py_INCREF(Py_None);
    }
    $result = t_output_helper($result,o);
}
%enddef

//---------------------------------------------------------------------
%define %binary_output_or_none(TYPEMAP, SIZE)
%typemap (default) SIZE {
    $1 = MAXSPECSIZE;
}
%typemap(in,numinputs=0) (TYPEMAP, SIZE) {
    $1 = (char *) qalloc(MAXSPECSIZE+1);
}
%typemap(argout) (TYPEMAP,SIZE) {
    Py_XDECREF(resultobj);
    if (result > 0)
    {
        resultobj = PyString_FromStringAndSize((char *)$1, result);
    }
    else
    {
        Py_INCREF(Py_None);
        resultobj = Py_None;
    }
    qfree((void *)$1);
}
%enddef

//---------------------------------------------------------------------
%define %binary_output_with_size(TYPEMAP, SIZE)
%typemap (default) SIZE {
    size_t ressize = MAXSPECSIZE;
    $1 = &ressize;
}
%typemap(in,numinputs=0) (TYPEMAP, SIZE) {
    $1 = (char *) qalloc(MAXSPECSIZE+1);
}
%typemap(argout) (TYPEMAP,SIZE) {
    Py_XDECREF(resultobj);
    if (result)
    {
        resultobj = PyString_FromStringAndSize((char *)$1, *$2);
    }
    else
    {
        Py_INCREF(Py_None);
        resultobj = Py_None;
    }
    qfree((void *)$1);
}
%enddef

//---------------------------------------------------------------------
//                          IN/OUT qstring
//---------------------------------------------------------------------
%typemap(in,numinputs=0) qstring *result (qstring temp) {
    $1 = &temp;
}
%typemap(argout) qstring *result {
    Py_XDECREF(resultobj);
    if (result)
    {
        resultobj = PyString_FromStringAndSize($1->begin(), $1->length());
    }
    else
    {
        Py_INCREF(Py_None);
        resultobj = Py_None;
    }
}
%typemap(freearg) qstring* result
{
  // Nothing. We certainly don't want 'temp' to be deleted.
}

//---------------------------------------------------------------------
// md5/sha256 hash retrieval
%typemap(in, numinputs=0) uchar hash[ANY] (uchar temp[$1_dim0])
{
  $1 = temp;
}

%typemap(argout) uchar hash[ANY]
{
    Py_XDECREF(resultobj);
    if (result)
    {
        char buf[2*$1_dim0 + 1];
        get_hex_string(buf, sizeof(buf), $1, $1_dim0);
        resultobj = PyString_FromString(buf);
    }
    else
    {
        Py_INCREF(Py_None);
        resultobj = Py_None;
    }
}

// Check that the argument is a callable Python object
//---------------------------------------------------------------------
%typemap(in) PyObject *pyfunc {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected a callable object");
        return NULL;
    }
    $1 = $input;
}
// Check that the argument is None or a callable Python object
//---------------------------------------------------------------------
%typemap(in) PyObject *pyfunc_or_none {
    if ($input != Py_None && !PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected None or a callable object");
        return NULL;
    }
    $1 = $input;
}
// Check that the argument is None or a tuple
//---------------------------------------------------------------------
%typemap(in) PyObject *tuple_or_none {
    if ($input != Py_None && !PyTuple_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected None or a tuple");
        return NULL;
    }
    $1 = $input;
}
%typemap(in) ea_t
{
  uint64 $1_temp;
  if ( !PyW_GetNumber($input, &$1_temp) )
  {
    PyErr_SetString(PyExc_TypeError, "Expected an ea_t type");
    return NULL;
  }
  $1 = ea_t($1_temp);
}
// Use PyLong_FromUnsignedLongLong, because 'long' is 4 bytes on
// windows, and thus the ea_t would be truncated at the
// PyLong_FromUnsignedLong(unsigned int) call time.
%typemap(out) ea_t "$result = PyLong_FromUnsignedLongLong($1);"

%typemap(in) qtime64_t "$1 = PyLong_AsUnsignedLongLong($input);"
%typemap(out) qtime64_t "$result = PyLong_FromUnsignedLongLong($1);"

//---------------------------------------------------------------------
//                            IN qstring
//---------------------------------------------------------------------
// This is used to set/retrieve qstring that are structure members.
%typemap(in) qstring*
{
  char *buf;
  Py_ssize_t length;
  int success = PyString_AsStringAndSize($input, &buf, &length);
  if ( success > -1 )
  {
    $1 = new qstring(buf, length);
  }
}
%typemap(freearg) qstring*
{
  delete $1;
}
%typemap(out) qstring*
{
  $result = PyString_FromStringAndSize($1->c_str(), $1->length());
}
%typemap(out) qstring
{
  $result = PyString_FromStringAndSize($1.c_str(), $1.length());
}
%apply qstring { _qstring<char> }
%apply qstring* { _qstring<char>* }

//---------------------------------------------------------------------
//                      varargs (mostly kernwin.hpp)
//---------------------------------------------------------------------
// This is used for functions like warning(), info() and so on
%typemap(in) (const char *format, ...)
{
    $1 = "%s";                                /* Fix format string to %s */
    $2 = (void *) PyString_AsString($input);  /* Get string argument */
};

#ifdef __EA64__
%apply longlong  *INOUT { sval_t  *value };
%apply longlong  *INOUT { adiff_t *disp };
%apply ulonglong *INOUT { ea_t    *addr };
%apply ulonglong *INOUT { sel_t   *sel };
%apply ulonglong *OUTPUT { ea_t *ea1, ea_t *ea2 }; // read_selection()
#else
%apply int          *INOUT { sval_t  *value };
%apply int          *INOUT { adiff_t *disp };
%apply unsigned int *INOUT { ea_t    *addr };
%apply unsigned int *INOUT { sel_t   *sel };
%apply unsigned int *OUTPUT { ea_t *ea1, ea_t *ea2 }; // read_selection()
#endif

%apply qstring *result { qstring *label };
%apply qstring *result { qstring *shortcut };
%apply qstring *result { qstring *tooltip };
%apply qstring *result { qstring *out };
%apply int *OUTPUT { int *icon };
%apply int *OUTPUT { action_state_t *state };
%apply bool *OUTPUT { bool *checkable };
%apply bool *OUTPUT { bool *checked };
%apply bool *OUTPUT { bool *visibility };

//-------------------------------------------------------------------------
// The following is to be used to expose an array of items
// to IDAPython. This will not make a copy (on purpose!).
//-------------------------------------------------------------------------
//
// (Very) heavily inspired by:
// http://stackoverflow.com/questions/7713318/nested-structure-array-access-in-python-using-swig?rq=1
//
%immutable;
%inline %{
template <typename Type, size_t N>
struct wrapped_array_t {
  Type (&data)[N];
  wrapped_array_t(Type (&data)[N]) : data(data) { }
};
%}
%mutable;

%extend wrapped_array_t {
  inline size_t __len__() const { return N; }

  inline const Type& __getitem__(size_t i) const throw(std::out_of_range) {
    if (i >= N || i < 0)
      throw std::out_of_range("out of bounds access");
    return $self->data[i];
  }

  inline void __setitem__(size_t i, const Type& v) throw(std::out_of_range) {
    if (i >= N || i < 0)
      throw std::out_of_range("out of bounds access");
    $self->data[i] = v;
  }

  %pythoncode {
    __iter__ = ida_idaapi._bounded_getitem_iterator
  }
}

//-------------------------------------------------------------------------
#if SWIG_VERSION == 0x20012
%typemap(out) tinfo_t {}
%typemap(ret) tinfo_t
{
  // ret tinfo_t
  tinfo_t *ni = new tinfo_t($1);
  til_register_python_tinfo_t_instance(ni);
  $result = SWIG_NewPointerObj(ni, $&1_descriptor, SWIG_POINTER_OWN | 0);
}


// KLUDGE: We'll let the compiler (or at worse the runtime)
// decide of the flags to use, depending on the method we are currently
// wrapping: at new-time, a SWIG_POINTER_NEW is required.
%typemap(out) tinfo_t* {}
%typemap(ret) tinfo_t*
{
  // ret tinfo_t*
  tinfo_t *ni = new tinfo_t(*($1));
  til_register_python_tinfo_t_instance(ni);
  if ( strcmp("new_tinfo_t", "$symname") == 0 )
  {
    $result = SWIG_NewPointerObj(SWIG_as_voidptr(ni), $1_descriptor, SWIG_POINTER_NEW | 0);
    delete $1;
  }
  else
  {
    $result = SWIG_NewPointerObj(SWIG_as_voidptr(ni), $1_descriptor, SWIG_POINTER_OWN | 0);
  }
}

%typemap(check) tinfo_t*
{
  if ( $1 == NULL )
    SWIG_exception_fail(SWIG_ValueError, "invalid null reference " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}
#else
#error Ensure tinfo_t wrapping is compatible with this version of SWIG
#endif

// Convert all of these
%cstring_output_maxstr_none(char *buf, size_t bufsize);
%binary_output_or_none(void *buf, size_t bufsize);
%binary_output_with_size(void *buf, size_t *bufsize);

// Accept single Python string for const void * + size input arguments
// For example: put_many_bytes() and patch_many_bytes()
%apply (char *STRING, int LENGTH) { (const void *buf, size_t size) };
%apply (char *STRING, int LENGTH) { (const void *buf, size_t len) };
%apply (char *STRING, int LENGTH) { (const void *value, size_t length) };
%apply (char *STRING, int LENGTH) { (const void *dataptr,size_t len) };

// Create wrapper classes for basic type arrays
%array_class(uchar, uchar_array);
%array_class(tid_t, tid_array);
%array_class(ea_t, ea_array);
%array_class(sel_t, sel_array);
%array_class(uval_t, uval_array);
%pointer_class(int, int_pointer);
%pointer_class(ea_t, ea_pointer);
%pointer_class(sval_t, sval_pointer);
%pointer_class(sel_t, sel_pointer);


%{
PyObject *qstrvec2pylist(qstrvec_t &vec)
{
  size_t n = vec.size();
  PyObject *py_list = PyList_New(n);
  for ( size_t i=0; i < n; ++i )
    PyList_SetItem(py_list, i, PyString_FromString(vec[i].c_str()));
  return py_list;
}
%}

//---------------------------------------------------------------------
%typemap(out) uint64 {
$result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
}

//---------------------------------------------------------------------
%typemap(in) uint64
{
  uint64 $1_temp;
  if ( !PyW_GetNumber($input, &$1_temp) )
  {
    PyErr_SetString(PyExc_TypeError, "Expected an uint64 type");
    return NULL;
  }
  $1 = $1_temp;
}
