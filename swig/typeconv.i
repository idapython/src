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

%define %cstring_output_maxstr_none(TYPEMAP, SIZE)
%typemap (default) SIZE {
	$1 = MAXSTR;
}
%typemap(in,numinputs=0) (TYPEMAP, SIZE) {
#ifdef __cplusplus
   $1 = ($1_ltype) new char[MAXSTR+1];
#else
   $1 = ($1_ltype) malloc(MAXSTR+1);
#endif
}
%typemap(out) ssize_t {
    /* REMOVING ssize_t return value in $symname */
}
%typemap(argout) (TYPEMAP,SIZE) {
   if (result > 0)
   {
     resultobj = PyString_FromString($1);
   }
   else
   {
     Py_INCREF(Py_None);
	 resultobj = Py_None;
   }
#ifdef __cplusplus
   delete [] $1;
#else
   free($1);
#endif
}
%enddef

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

// Check that the argument is a callable Python object
%typemap(in) PyObject *pyfunc {
  if (!PyCallable_Check($input)) {
      PyErr_SetString(PyExc_TypeError, "Expecting a callable object");
      return NULL;
  }
  $1 = $input;
}
