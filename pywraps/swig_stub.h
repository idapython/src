#ifndef __SWIG_STUB__
#define __SWIG_STUB__

#include <Python.h>

#define SWIG_as_voidptr(a) const_cast< void * >(static_cast< const void * >(a)) 

PyObject *SWIG_NewPointerObj(void *ptr, void *type, int flags);

namespace Swig
{
  class DirectorException
  {
  public:
    const char *getMessage() const
    {
      return "NULL";
    }
  };
}

#define SWIG_RUNTIME_VERSION "4"

// Some fake SWIG types
#define SWIGTYPE_p_member_t NULL

#endif