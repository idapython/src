#ifndef __PYWRAPS_HPP__
#define __PYWRAPS_HPP__

//------------------------------------------------------------------------
// Types
#ifndef PYUL_DEFINED
  #define PYUL_DEFINED
  typedef unsigned PY_LONG_LONG PY_ULONG_LONG;
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

//------------------------------------------------------------------------
#define S_IDAAPI_MODNAME                         "idaapi"
#define S_IDC_MODNAME                            "idc"
#define S_IDAAPI_EXECSCRIPT                      "IDAPython_ExecScript"
#define S_IDAAPI_COMPLETION                      "IDAPython_Completion"
#define S_IDAAPI_FORMATEXC                       "IDAPython_FormatExc"
#define S_IDAAPI_LOADPROCMOD                     "IDAPython_LoadProcMod"
#define S_IDAAPI_UNLOADPROCMOD                   "IDAPython_UnLoadProcMod"

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
#define CIP_OK_OPAQUE    2 // Success, but the data pointed to by the PyObject* is an opaque object.

//---------------------------------------------------------------------------
// Helper macro to create C counterparts of Python py_clinked_object_t object
#ifdef __PYWRAPS__
#define DECLARE_PY_CLINKED_OBJECT(type)                        \
  static PyObject *type##_create()                             \
  {                                                            \
    PYW_GIL_CHECK_LOCKED_SCOPE();                              \
    return PyCObject_FromVoidPtr(new type(), NULL);            \
  }                                                            \
  static bool type##_destroy(PyObject *py_obj)                 \
  {                                                            \
    PYW_GIL_CHECK_LOCKED_SCOPE();                              \
    if ( !PyCObject_Check(py_obj) )                            \
      return false;                                            \
    delete (type *)PyCObject_AsVoidPtr(py_obj);                \
    return true;                                               \
  }                                                            \
  static type *type##_get_clink(PyObject *self)                \
  {                                                            \
    PYW_GIL_CHECK_LOCKED_SCOPE();                              \
    return (type *)pyobj_get_clink(self);                      \
  }                                                            \
  static PyObject *type##_get_clink_ptr(PyObject *self)        \
  {                                                            \
    PYW_GIL_CHECK_LOCKED_SCOPE();                              \
    return PyLong_FromUnsignedLongLong(                        \
      (unsigned PY_LONG_LONG)pyobj_get_clink(self));           \
  }
#else
// SWIG does not expand macros and thus those definitions won't be wrapped
// Use DECLARE_PY_CLINKED_OBJECT(type) inside the .i file
#define DECLARE_PY_CLINKED_OBJECT(type)
#endif // __PYWRAPS__

//---------------------------------------------------------------------------
class gil_lock_t
{
private:
  PyGILState_STATE state;
public:
  gil_lock_t()
  {
    state = PyGILState_Ensure();
  }

  ~gil_lock_t()
  {
    PyGILState_Release(state);
  }
};
// Declare a variable to acquire/release the GIL
#define PYW_GIL_GET gil_lock_t lock;

#define GIL_CHKCONDFAIL (((debug & IDA_DEBUG_PLUGIN) == IDA_DEBUG_PLUGIN) \
                      && PyGILState_GetThisThreadState() != _PyThreadState_Current)

#define PYW_GIL_CHECK_LOCKED_SCOPE()                                    \
  do                                                                    \
  {                                                                     \
    if ( GIL_CHKCONDFAIL )                                              \
    {                                                                   \
      msg("*** WARNING: Code at %s:%d should have the GIL, but apparently doesn't ***\n", \
          __FILE__, __LINE__);                                          \
      if ( under_debugger )                                             \
        BPT;                                                            \
    }                                                                   \
  } while ( false )


//------------------------------------------------------------------------
// All the exported functions from PyWraps are forward declared here
insn_t *insn_t_get_clink(PyObject *self);
op_t *op_t_get_clink(PyObject *self);

//-------------------------------------------------------------------------
// The base for a reference. Will automatically increase the reference
// counter for the object when it is assigned from another ref_t,
// and decrease the reference counter when destroyed.
// This is meant to be used whenever possible, in order to prevent
// situations where, e.g., a given code path is taken and we return from
// a function without first decreasing the reference counter.
//
// Note: You should never, ever have to Py_[INCREF|DECREF] the 'o' object yourself.
// Note: These simple ref_t cannot be created with a PyObject* directly
//       (that would be the role of 'newref_t'/'borref_t' below.)
//       In other words: simple 'ref_t' instances are never created from the
//       result of calling the CPython API. They are only used when in
//       idapython land.
//       In yet other words: the CPython API only deals in terms of
//       'New references' and 'Borrowed references'. Those are implemented,
//       respectively, by the 'newref_t' and 'borref_t' classes below.
//       This 'ref_t' is only used for internal handling.
struct ref_t
{
  PyObject *o;

  ref_t() : o(NULL) {}
  ref_t(const ref_t &other) : o(other.o) { incref(); }
  ~ref_t() { decref(); }
  ref_t &operator=(const ref_t &other)
  {
    decref();
    o = other.o;
    incref();
    return *this;
  }

  void incref() const { if ( o != NULL ) Py_INCREF(o); }
  void decref() const { if ( o != NULL ) Py_DECREF(o); }

  bool operator==(PyObject *other) const { return o == other; }
  bool operator!=(PyObject *other) const { return ! ((*this) == other); }

  bool operator==(const ref_t &other) const { return o == other.o; }
  bool operator!=(const ref_t &other) const { return ! ((*this) == other); }

  // operator PyObject *() const { return o; }
  // PyObject *operator ->() const { return o; }
  // PyObject &operator *() const { return *o; }
  //protected:
};

//-------------------------------------------------------------------------
// A 'new' reference. Typically used when the CPython implementation returns
// a PyObject* whose refcnt was already increased, and that the caller is
// responsible for releasing.
//
// This implements the 'New reference' idea at http://docs.python.org/2/c-api/intro.html:
// ---
// "When a function passes ownership of a reference on to its caller,
//  the caller is said to receive a new reference"
// ---
// E.g., from "PyObject_GetAttrString"'s doc:
// ---
// "Return value: New reference.
//  Retrieve an attribute named attr_name from object o[...]"
// ---
struct newref_t : public ref_t
{
  newref_t(); // No.
  newref_t(const newref_t &other); // No.
  newref_t &operator=(const newref_t &other); // No.
  newref_t(PyObject *_o)
  {
#ifdef _DEBUG
    QASSERT(30409, _o == NULL || _o->ob_refcnt >= 1);
#endif
    o = _o;
  }
};

//-------------------------------------------------------------------------
// A 'borrowed' reference. Typically used when the CPython implementation returns
// a PyObject* whose ownership is _not_ transferred to the caller.
// Therefore, and since the caller wants to make sure the object is not
// released while it is using it, it must first increase the reference count,
// and then decrease it.
//
// This is similar to the simpler 'ref_t' in that it first increases, and then
// decreases the reference count. The difference is that 'borref_t' instances
// can be created with a PyObject*, while 'ref_t' instances cannot (by design).
//
// This implements the 'Borrowed reference' idea at http://docs.python.org/2/c-api/intro.html:
// ---
// "When no ownership is transferred, the caller is said to borrow the reference.
//  Nothing needs to be done for a borrowed reference."
// ---
struct borref_t : public ref_t
{
  borref_t(); // No.
  borref_t(const newref_t &other); // No.
  borref_t &operator=(const newref_t &other); // No.
  borref_t(PyObject *_o)
  {
    o = _o;
    incref(); // ~ref_t() will decref(), so we need to incref.
  }
};


//------------------------------------------------------------------------
// Vector of ref_t
struct ref_vec_t : public qvector<ref_t>
{
  void to_pyobject_pointers(qvector<PyObject*> *out)
  {
    size_t n = size();
    out->resize(n);
    for ( size_t i = 0; i < n; ++i )
      out->at(i) = at(i).o;
  }
};


// Returns a new reference to a class
// Return value: New reference.
ref_t get_idaapi_attr(const char *attr);

// Returns a new reference to a class by its ID
// Return value: New reference.
ref_t get_idaapi_attr_by_id(const int class_id);

// Tries to import a module and swallows the exception if it fails and returns NULL
// Return value: New reference.
ref_t PyW_TryImportModule(const char *name);

// Tries to get an attribute and swallows the exception if it fails and returns NULL
ref_t PyW_TryGetAttrString(PyObject *py_var, const char *attr);

// Returns the linked object (void *) from a PyObject
void *pyobj_get_clink(PyObject *pyobj);

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
bool PyW_GetError(qstring *out = NULL, bool clear_err = true);
bool PyW_GetError(char *buf, size_t bufsz, bool clear_err = true);

// If an error occured (it calls PyGetError) it displays it and return TRUE
// This function is used when calling callbacks
bool PyW_ShowCbErr(const char *cb_name);

// Utility function to create a class instance whose constructor takes zero arguments
ref_t create_idaapi_class_instance0(const char *clsname);

// Utility function to create linked class instances
ref_t create_idaapi_linked_class_instance(const char *clsname, void *lnk);

// Returns the string representation of a PyObject
bool PyW_ObjectToString(PyObject *obj, qstring *out);

// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
bool pyvar_to_idcvar_or_error(const ref_t &py_obj, idc_value_t *idc_obj);

// Creates and initializes an IDC exception
error_t PyW_CreateIdcException(idc_value_t *res, const char *msg);

//
// Conversion functions
//
bool pyw_convert_idc_args(
        const idc_value_t args[],
        int nargs,
        ref_vec_t &pargs,
        bool as_tupple,
        char *errbuf = NULL,
        size_t errbufsize = 0);

// Converts Python variable to IDC variable
// gvar_sn is used in case the Python object was a created from a call to idcvar_to_pyvar and the IDC object was a VT_REF
int pyvar_to_idcvar(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn = NULL);

// Converts from IDC to Python
// We support converting VT_REF IDC variable types
int idcvar_to_pyvar(
  const idc_value_t &idc_var,
  ref_t *py_var);

// Walks a Python list or Sequence and calls the callback
Py_ssize_t pyvar_walk_list(
        const ref_t &py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud) = NULL,
        void *ud = NULL);
Py_ssize_t pyvar_walk_list(
        PyObject *py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud) = NULL,
        void *ud = NULL);

// Converts an intvec_t to a Python list object
ref_t PyW_IntVecToPyList(const intvec_t &intvec);

// Converts an Python list to an intvec
bool PyW_PyListToIntVec(PyObject *py_list, intvec_t &intvec);

// Converts a Python list to a qstrvec
bool PyW_PyListToStrVec(PyObject *py_list, qstrvec_t &strvec);

//---------------------------------------------------------------------------
//
// notify_when()
//
bool pywraps_nw_term();
bool pywraps_nw_notify(int slot, ...);
bool pywraps_nw_init();

//---------------------------------------------------------------------------
bool pywraps_check_autoscripts(char *buf, size_t bufsize);

// [De]Initializes PyWraps
bool init_pywraps();
void deinit_pywraps();

#endif
