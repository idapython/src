#include "swig_stub.h"

PyObject *SWIG_NewPointerObj(void *ptr, void *type, int flags) 
{
  return PyCObject_FromVoidPtr(ptr, NULL);
}
