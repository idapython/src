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
        PyObject *o = PySequence_GetItem($input,i);
        if (!PyLong_Check(o))
        {
            Py_XDECREF(o);
            PyErr_SetString(PyExc_ValueError,"Expecting a sequence of long integers");
            return NULL;
        }

        temp[i] = PyLong_AsUnsignedLong(o);
        Py_DECREF(o);
    }
    $1 = &temp[0];
}

//---------------------------------------------------------------------
%define %cstring_output_maxstr_none(TYPEMAP, SIZE)

%typemap (default) SIZE {
    $1 = MAXSTR;
 }

%typemap(in,numinputs=0) (TYPEMAP, SIZE) {
    $1 = ($1_ltype) qalloc(MAXSTR+1);
}

%typemap(out) ssize_t {
    /* REMOVING ssize_t return value in $symname */
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
%typemap(out) ssize_t {
    /* REMOVING ssize_t return value in $symname */
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
%typemap(out) ssize_t {
    /* REMOVING ssize_t return value in $symname */
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
// Check that the argument is a callable Python object
%typemap(in) PyObject *pyfunc {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected a callable object");
        return NULL;
    }
    $1 = $input;
}

// Convert ea_t
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

//-------------------------------------------------------------------------
// Convert qstring
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

#ifdef __EA64__
%apply longlong  *INOUT { sval_t *value };
%apply ulonglong *INOUT { ea_t   *addr };
%apply ulonglong *INOUT { sel_t  *sel };
#else
%apply int          *INOUT { sval_t *value };
%apply unsigned int *INOUT { ea_t   *addr };
%apply unsigned int *INOUT { sel_t  *sel };
#endif


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
struct wrapped_array {
  Type (&data)[N];
  wrapped_array(Type (&data)[N]) : data(data) { }
};
%}
%mutable;

%extend wrapped_array {
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
}

