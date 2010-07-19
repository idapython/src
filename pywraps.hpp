#ifndef __PYWRAPS_HPP__
#define __PYWRAPS_HPP__

//------------------------------------------------------------------------
// Types
#ifndef PYUL_DEFINED
  #define PYUL_DEFINED
  #ifdef __EA64__
    typedef unsigned PY_LONG_LONG pyul_t;
    typedef PY_LONG_LONG pyl_t;
  #else
    typedef unsigned long pyul_t;
    typedef long pyl_t;
  #endif
#endif

#ifdef __EA64__
  #define PY_FMT64  "K"
  #define PY_SFMT64 "L"
#else
  #define PY_FMT64  "k"
  #define PY_SFMT64 "l"
#endif

#define S_IDAAPI_MODNAME                         "idaapi"
#define S_IDC_MODNAME                            "idc"
#define S_IDAAPI_EXECSCRIPT                      "IDAPython_ExecScript"
#define S_IDAAPI_COMPLETION                      "IDAPython_Completion"

// Vector of PyObject*
typedef qvector<PyObject *> ppyobject_vec_t;

//------------------------------------------------------------------------
// PyIdc conversion object IDs
#define PY_ICID_INT64                            0
#define PY_ICID_BYREF                            1
#define PY_ICID_OPAQUE                           2

//------------------------------------------------------------------------
// Constants used with the notify_when()
#define NW_OPENIDB          0x0001
#define NW_OPENIDB_SLOT     0
#define NW_CLOSEIDB         0x0002
#define NW_CLOSEIDB_SLOT    1
#define NW_INITIDA          0x0004
#define NW_INITIDA_SLOT     2
#define NW_TERMIDA          0x0008
#define NW_TERMIDA_SLOT     3
#define NW_REMOVE           0x0010 // Uninstall flag
#define NW_EVENTSCNT        4 // Count of notify_when codes

//------------------------------------------------------------------------
// Constants used by the pyvar_to_idcvar and idcvar_to_pyvar functions
#define CIP_FAILED      -1 // Conversion error
#define CIP_IMMUTABLE    0 // Immutable object passed. Will not update the object but no error occured
#define CIP_OK           1 // Success
#define CIP_OK_NODECREF  2 // Success but do not decrement its reference

//------------------------------------------------------------------------
// All the exported functions from PyWraps are forward declared here
insn_t *insn_t_get_clink(PyObject *self);
op_t *op_t_get_clink(PyObject *self);

// Tries to import a module and swallows the exception if it fails and returns NULL
PyObject *PyW_TryImportModule(const char *name);

// Tries to get an attribute and swallows the exception if it fails and returns NULL
PyObject *PyW_TryGetAttrString(PyObject *py_var, const char *attr);

// Converts a Python number (LONGLONG or normal integer) to an IDC variable (VT_LONG or VT_INT64)
bool PyW_GetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var);

// Returns a qstring from a Python attribute string
bool PyW_GetStringAttr(
    PyObject *py_obj, 
    const char *attr_name, 
    qstring *str);

// Converts a Python number to an uint64 and indicates whether the number was a long number
bool PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64 = NULL);

// Checks if an Python object can be treated like a sequence
bool PyW_IsSequenceType(PyObject *obj);

// Returns an error string from the last exception (and clears it)
bool PyW_GetError(qstring *out = NULL);

// If an error occured (it calls PyGetError) it displays it and return TRUE
bool PyW_ShowErr(const char *cb_name);

// Utility function to create a class instance whose constructor takes zero arguments
PyObject *create_idaapi_class_instance0(const char *clsname);

// Utility function to create linked class instances
PyObject *create_idaapi_linked_class_instance(const char *clsname, void *lnk);

// [De]Initializes PyWraps
bool init_pywraps();
void deinit_pywraps();

// Returns the string representation of a PyObject
bool PyW_ObjectToString(PyObject *obj, qstring *out);

// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
bool convert_pyobj_to_idc_exc(PyObject *py_obj, idc_value_t *idc_obj);

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

// Walks a Python list or Sequence and calls the callback
Py_ssize_t pyvar_walk_list(
  PyObject *py_list, 
  int (idaapi *cb)(PyObject *py_item, Py_ssize_t index, void *ud) = NULL,
  void *ud = NULL);

// Returns a reference to a class
PyObject *get_idaapi_attr(const char *attr);

// notify_when()
bool pywraps_nw_term();
bool pywraps_nw_notify(int slot, ...);
bool pywraps_nw_init();

#endif