%{
#include <strlist.hpp>
%}

%ignore strwinsetup_t::setup_strings_window;
%ignore strwinsetup_t::save_config;
%ignore strwinsetup_t::restore_config;

%extend strwinsetup_t {

  PyObject *_get_strtypes()
  {
    const bytevec_t &t = $self->strtypes;
    size_t n = t.size();
    PyObject *py_t = PyList_New(n);
    for ( size_t i = 0, n = t.size(); i < n; ++i )
      PyList_SetItem(py_t, i, PyInt_FromLong(t[i]));
    return py_t;
  }

  PyObject *_set_strtypes(PyObject *py_t)
  {
    if ( PySequence_Check(py_t) )
    {
      Py_ssize_t n = PySequence_Size(py_t);
      bytevec_t t;
      t.reserve(n);
      for ( size_t i = 0; i < n; ++i )
      {
        newref_t pyo(PySequence_GetItem(py_t, i));
        if ( PyLong_Check(pyo.o) )
        {
          long stype = PyLong_AsLong(pyo.o);
          if ( stype < 0 || stype >= 0x100 )
          {
            PyErr_SetString(PyExc_ValueError, "values must be between 0 & 0x100");
            return nullptr;
          }
          t.push_back(uchar(stype));
        }
        else
        {
          PyErr_SetString(PyExc_ValueError, "expected an integer");
          return nullptr;
        }
      }
      $self->strtypes.swap(t);
    }
    else
    {
      PyErr_SetString(PyExc_TypeError, "expected a list");
      return nullptr;
    }
    Py_RETURN_TRUE;
  }

  %pythoncode {
     strtypes = property(_get_strtypes, _set_strtypes)
  }
}
%ignore strwinsetup_t::strtypes;

%include "strlist.hpp"
