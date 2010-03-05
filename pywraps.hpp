#ifndef __PYWRAPS_HPP__
#define __PYWRAPS_HPP__

//------------------------------------------------------------------------
// Types
#ifndef PYUL_DEFINED
  #define PYUL_DEFINED
  #ifdef __EA64__
    typedef unsigned PY_LONG_LONG pyul_t;
  #else
    typedef unsigned long pyul_t;
  #endif
#endif

#ifdef __EA64__
  #define PY_FMT64 "K"
#else
  #define PY_FMT64 "k"
#endif

// Vector of PyObject*
typedef qvector<PyObject *> ppyobject_vec_t;

//------------------------------------------------------------------------
// PyIdc conversion object IDs
#define PY_ICID_INT64                            0
#define PY_ICID_BYREF                            1
#define PY_ICID_OPAQUE                           2

//------------------------------------------------------------------------
// Constants used by the pyvar_to_idcvar and idcvar_to_pyvar functions
#define CIP_FAILED      -1 // Conversion error
#define CIP_IMMUTABLE    0 // Immutable object passed. Will not update the object but no error occured
#define CIP_OK           1 // Success
#define CIP_OK_NODECREF  2 // Success but do not decrement its reference

//------------------------------------------------------------------------
// All the exported functions from PyWraps are forward declared here

// Tries to import a module and swallows the exception if it fails and returns NULL
PyObject *PyImport_TryImportModule(const char *name);

// Tries to get an attribute and swallows the exception if it fails and returns NULL
PyObject *PyObject_TryGetAttrString(PyObject *py_var, const char *attr);

// Converts a Python number (LONGLONG or normal integer) to an IDC variable (VT_LONG or VT_INT64)
bool PyGetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var);

// Converts a Python number to an uint64 and indicates whether the number was a long number
bool PyGetNumber(PyObject *py_var, uint64 *num, bool *is_64 = NULL);

// Checks if an Python object can be treated like a sequence
bool PyIsSequenceType(PyObject *obj);

// Returns an error string from the last exception (and clears it)
bool PyGetError(qstring *out = NULL);

// If an error occured (it calls PyGetError) it displays it and return TRUE
bool PyShowErr(const char *cb_name);

// [De]Initializes PyWraps
bool init_pywraps();
void deinit_pywraps();

// Returns the string representation of a PyObject
bool PyObjectToString(PyObject *obj, qstring *out);

// Converts Python variable to IDC variable
// gvar_sn is used in case the Python object was a created from a call to idcvar_to_pyvar and the IDC object was a VT_REF
int pyvar_to_idcvar(
  PyObject *py_var,
  idc_value_t *idc_var,
  int *gvar_sn = NULL);

// Converts from IDC to Python
// We support converting VT_REF IDC variable types
int idcvar_to_pyvar(
  const idc_value_t &idc_var,
  PyObject **py_var);


#endif