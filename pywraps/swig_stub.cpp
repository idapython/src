#include "swig_stub.h"

PyObject *SWIG_NewPointerObj(void *ptr, void *type, int flags)
{
  return PyCapsule_New(ptr, VALID_CAPSULE_NAME, NULL);
}
