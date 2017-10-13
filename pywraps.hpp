#ifndef __PYWRAPS_HPP__
#define __PYWRAPS_HPP__

#include <Python.h>

//------------------------------------------------------------------------
// The following are to be used whenever Py_BuildValue-style
// format specifiers are needed.
#define PY_BV_EA "K" // Convert a C unsigned long long to a Python long integer object.
#define PY_BV_SZ "n" // Convert a C Py_ssize_t to a Python integer or long integer.
#define PY_BV_UVAL PY_BV_EA
#define PY_BV_ASIZE PY_BV_EA
#define PY_BV_SEL PY_BV_EA
#define PY_BV_SVAL "L" // Convert a C long long to a Python long integer object

typedef unsigned PY_LONG_LONG bvea_t;
typedef Py_ssize_t bvsz_t;
typedef bvea_t bvuval_t;
typedef bvea_t bvasize_t;
typedef bvea_t bvsel_t;
typedef PY_LONG_LONG bvsval_t;

//-------------------------------------------------------------------------
// a few forward decls
class insn_t;
class op_t;
struct switch_info_t;

// "A pointer can be explicitly converted to any integral type large
//  enough to hold it. The mapping function is implementation-defined."
//                                                           — C++03
// => G++ (and probably MSVC) will typically first sign-extend the pointer.
//
// int bar(void *p) { return foo(uint64(p)); }
//
// translates to:
//
// mov    0x8(%ebp),%eax
// mov    %eax,%edx
// sar    $0x1f,%edx     ; <---- boom!
// mov    %eax,(%esp)
// mov    %edx,0x4(%esp)
// call   2d <_Z3barPv+0x16>

#ifdef __X64__
#define PTR2U64(Binding) (uint64(Binding))
#else
#define PTR2U64(Binding) (uint64(uint32(Binding)))
#endif

#if defined(__LINUX__) || defined(__MAC__)
#define exported __attribute__((visibility("default")))
#else
#define exported
#endif

//------------------------------------------------------------------------
#define S_IDA_IDAAPI_MODNAME                     "ida_idaapi"
#define S_IDA_NALT_MODNAME                       "ida_nalt"
#define S_IDA_UA_MODNAME                         "ida_ua"
#define S_IDA_KERNWIN_MODNAME                    "ida_kernwin"
#define S_IDA_MOVES_MODNAME                      "ida_moves"
#define S_IDC_MODNAME                            "idc"
#define S_IDAAPI_EXECSCRIPT                      "IDAPython_ExecScript"
#define S_IDAAPI_COMPLETION                      "IDAPython_Completion"
#define S_IDAAPI_FORMATEXC                       "IDAPython_FormatExc"
#define S_IDAAPI_LOADPROCMOD                     "IDAPython_LoadProcMod"
#define S_IDAAPI_UNLOADPROCMOD                   "IDAPython_UnLoadProcMod"


//------------------------------------------------------------------------
// String constants used
static const char S_PYINVOKE0[]              = "_py_invoke0";
static const char S_PY_SWIEX_CLSNAME[]       = "switch_info_t";
static const char S_PY_OP_T_CLSNAME[]        = "op_t";
static const char S_PROPS[]                  = "props";
static const char S_NAME[]                   = "name";
static const char S_TITLE[]                  = "title";
static const char S_ASM_KEYWORD[]            = "asm_keyword";
static const char S_MENU_NAME[]              = "menu_name";
static const char S_HOTKEY[]                 = "hotkey";
static const char S_EMBEDDED[]               = "embedded";
static const char S_POPUP_NAMES[]            = "popup_names";
static const char S_FLAGS[]                  = "flags";
static const char S_VALUE_SIZE[]             = "value_size";
static const char S_MAY_CREATE_AT[]          = "may_create_at";
static const char S_CALC_ITEM_SIZE[]         = "calc_item_size";
static const char S_ID[]                     = "id";
static const char S_PRINTF[]                 = "printf";
static const char S_TEXT_WIDTH[]             = "text_width";
static const char S_SCAN[]                   = "scan";
static const char S_ANALYZE[]                = "analyze";
static const char S_CBSIZE[]                 = "cbsize";
static const char S_ON_CLICK[]               = "OnClick";
static const char S_ON_CLOSE[]               = "OnClose";
static const char S_ON_DBL_CLICK[]           = "OnDblClick";
static const char S_ON_CURSOR_POS_CHANGED[]  = "OnCursorPosChanged";
static const char S_ON_KEYDOWN[]             = "OnKeydown";
static const char S_ON_COMPLETE_LINE[]       = "OnCompleteLine";
static const char S_ON_CREATE[]              = "OnCreate";
static const char S_ON_POPUP[]               = "OnPopup";
static const char S_ON_HINT[]                = "OnHint";
static const char S_ON_POPUP_MENU[]          = "OnPopupMenu";
static const char S_ON_EDIT_LINE[]           = "OnEditLine";
static const char S_ON_INSERT_LINE[]         = "OnInsertLine";
static const char S_ON_GET_LINE[]            = "OnGetLine";
static const char S_ON_DELETE_LINE[]         = "OnDeleteLine";
static const char S_ON_REFRESH[]             = "OnRefresh";
static const char S_ON_EXECUTE_LINE[]        = "OnExecuteLine";
static const char S_ON_SELECT_LINE[]         = "OnSelectLine";
static const char S_ON_SELECTION_CHANGE[]    = "OnSelectionChange";
static const char S_ON_GET_ICON[]            = "OnGetIcon";
static const char S_ON_GET_LINE_ATTR[]       = "OnGetLineAttr";
static const char S_ON_GET_SIZE[]            = "OnGetSize";
static const char S_ON_GETTEXT[]             = "OnGetText";
static const char S_ON_ACTIVATE[]            = "OnActivate";
static const char S_ON_DEACTIVATE[]          = "OnDeactivate";
static const char S_ON_SELECT[]              = "OnSelect";
static const char S_ON_CREATING_GROUP[]      = "OnCreatingGroup";
static const char S_ON_DELETING_GROUP[]      = "OnDeletingGroup";
static const char S_ON_GROUP_VISIBILITY[]    = "OnGroupVisibility";
static const char S_ON_INIT[]                = "OnInit";
static const char S_M_EDGES[]                = "_edges";
static const char S_M_NODES[]                = "_nodes";
static const char S_M_THIS[]                 = "_this";
static const char S_M_TITLE[]                = "_title";
static const char S_CLINK_NAME[]             = "__clink__";
static const char S_ON_VIEW_MOUSE_MOVED[]    = "OnViewMouseMoved";
static const char S_MAIN[]                   = "__main__";


#ifdef __PYWRAPS__
static const char S_PY_IDA_IDAAPI_MODNAME[] = "__main__";
#else
static const char S_PY_IDA_IDAAPI_MODNAME[] = S_IDA_IDAAPI_MODNAME;
#endif

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

// Let's declare just the relevant bits, in order to not have to force
// including 'kernwin.hpp' in all files
#ifndef __KERNWIN_HPP
idaman uint32 ida_export_data debug;
#define IDA_DEBUG_PLUGIN 0x00000020
THREAD_SAFE AS_PRINTF(1, 2) inline int msg(const char *format, ...);
#endif // __KERNWIN_HPP
#define GIL_CHKCONDFAIL (((debug & IDA_DEBUG_PLUGIN) != 0) \
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


//-------------------------------------------------------------------------
struct exc_report_t
{
  ~exc_report_t()
  {
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
};
#define PYW_GIL_GET_AND_REPORT_ERROR PYW_GIL_GET; exc_report_t exc;


// Returns the linked object (void *) from a PyObject
idaman void * ida_export pyobj_get_clink(PyObject *pyobj);

//------------------------------------------------------------------------
// All the exported functions from PyWraps are forward declared here
inline insn_t *insn_t_get_clink(PyObject *self) { return (insn_t *)pyobj_get_clink(self); }
inline op_t *op_t_get_clink(PyObject *self) { return (op_t *)pyobj_get_clink(self); }
inline switch_info_t *switch_info_t_get_clink(PyObject *self) { return (switch_info_t *)pyobj_get_clink(self); }

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
    // We *must* first (possibly) set & incref the other object,
    // because decref() might call the Python's deallocator, which
    // might have side-effects, that might affect this ref_t
    // instance.
    // If that's too many 'might' to your taste, let me illustrate.
    //
    // py_plgform.hpp's 'plgform_t' holds a 'ref_t' instance, named 'py_obj'.
    // If the actual, Qt widget wrapped by that plgform_t gets destroyed,
    // plgform_t::unhook() will be called, which will assign an
    // empty ref_t instance to its 'py_obj'.
    // That will decrement the refcount, and might call the deallocator:
    // the plgform_t::destroy static function.
    // That function will 'delete' the plgform_t object.
    // But, in the ~plgform_t() destructor, the 'py_obj' object will be
    // destroyed too: decreasing once again the refcnt (which now falls to -1).
    // At this point, all hell breaks loose (or is allowed to).
    PyObject *was = o;
    o = other.o;
    incref();
    if ( was != NULL )
      Py_DECREF(was);
    return *this;
  }

  void incref() const { if ( o != NULL ) Py_INCREF(o); }
  void decref() const { if ( o != NULL ) { QASSERT(30469, o->ob_refcnt > 0); Py_DECREF(o); } }

  bool operator==(PyObject *other) const { return o == other; }
  bool operator!=(PyObject *other) const { return !((*this) == other); }

  bool operator==(const ref_t &other) const { return o == other.o; }
  bool operator!=(const ref_t &other) const { return !((*this) == other); }
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

// Tries to import a module and swallows the exception if it fails and returns NULL
// Return value: New reference.
exported ref_t ida_export PyW_TryImportModule(const char *name);

// Tries to get an attribute and swallows the exception if it fails and returns NULL
exported ref_t ida_export PyW_TryGetAttrString(PyObject *py_var, const char *attr);

// Converts a Python number (LONGLONG or normal integer) to an IDC variable (VT_LONG or VT_INT64)
exported bool ida_export PyW_GetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var);

// Returns a qstring from a Python attribute string
exported bool ida_export PyW_GetStringAttr(
        PyObject *py_obj,
        const char *attr_name,
        qstring *str);

// Converts a Python number to an uint64 and indicates whether the number was a long number
exported bool ida_export PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64 = NULL);

// Checks if an Python object can be treated like a sequence
exported bool ida_export PyW_IsSequenceType(PyObject *obj);

// Returns an error string from the last exception (and clears it)
exported bool ida_export PyW_GetError(qstring *out = NULL, bool clear_err = true);

// If an error occured (it calls PyGetError) it displays it and return TRUE
// This function is used when calling callbacks
exported bool ida_export PyW_ShowCbErr(const char *cb_name);

// Utility function to create linked class instances
exported ref_t ida_export create_linked_class_instance(const char *modname, const char *clsname, void *lnk);

// Returns the string representation of a PyObject
exported bool ida_export PyW_ObjectToString(PyObject *obj, qstring *out);

// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
exported bool ida_export pyvar_to_idcvar_or_error(const ref_t &py_obj, idc_value_t *idc_obj);

// Creates and initializes an IDC exception
exported error_t ida_export PyW_CreateIdcException(idc_value_t *res, const char *msg);

//
// Conversion functions
//
#define PYWCVTF_AS_TUPLE                 0x1
#define PYWCVTF_INT64_AS_UNSIGNED_PYLONG 0x2 // don't wrap int64 into 'PyIdc_cvt_int64__' objects, but make them 'long' instead

// Converts from IDC to Python
exported bool ida_export pyw_convert_idc_args(
        const idc_value_t args[],
        int nargs,
        ref_vec_t &pargs,
        uint32 flags,
        qstring *errbuf = NULL);

// Converts from IDC to Python
// We support converting VT_REF IDC variable types
exported int ida_export idcvar_to_pyvar(
        const idc_value_t &idc_var,
        ref_t *py_var,
        uint32 flags=0);

//-------------------------------------------------------------------------
// Converts Python variable to IDC variable
// gvar_sn is used in case the Python object was a created from a call to idcvar_to_pyvar and the IDC object was a VT_REF
exported int ida_export pyvar_to_idcvar(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn = NULL);

//-------------------------------------------------------------------------
// Walks a Python list or Sequence and calls the callback
exported Py_ssize_t ida_export pyvar_walk_list(
        PyObject *py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud)=NULL,
        void *ud = NULL);

// Converts a sizevec_t to a Python list object
exported ref_t ida_export PyW_SizeVecToPyList(const sizevec_t &vec);

// Converts an Python list to an sizevec
exported bool ida_export PyW_PyListToSizeVec(PyObject *py_list, sizevec_t &vec);

// Converts an Python list to an eavec
exported bool ida_export PyW_PyListToEaVec(PyObject *py_list, eavec_t &eavec);

// Converts a Python list to a qstrvec
exported bool ida_export PyW_PyListToStrVec(PyObject *py_list, qstrvec_t &strvec);

//-------------------------------------------------------------------------
exported bool ida_export PyWStringOrNone_Check(PyObject *tp);

//-------------------------------------------------------------------------
#include <idd.hpp>
exported PyObject *ida_export meminfo_vec_t_to_py(meminfo_vec_t &ranges);

//-------------------------------------------------------------------------
exported void ida_export PyW_register_compiled_form(PyObject *py_form);

//-------------------------------------------------------------------------
exported void ida_export PyW_unregister_compiled_form(PyObject *py_form);

//---------------------------------------------------------------------------
// notify_when()
class pywraps_notify_when_t
{
  ref_vec_t table[NW_EVENTSCNT];
  qstring err;
  bool in_notify;
  struct notify_when_args_t
  {
    int when;
    PyObject *py_callable;
  };
  typedef qvector<notify_when_args_t> notify_when_args_vec_t;
  notify_when_args_vec_t delayed_notify_when_list;

  static ssize_t idaapi idp_callback(void *ud, int event_id, va_list va);
  static ssize_t idaapi idb_callback(void *ud, int event_id, va_list va);
  bool unnotify_when(int when, PyObject *py_callable);
  void register_callback(int slot, PyObject *py_callable);
  void unregister_callback(int slot, PyObject *py_callable);

public:
  bool init();
  bool deinit();
  bool notify_when(int when, PyObject *py_callable);
  bool notify(int slot, ...);
  bool notify_va(int slot, va_list va);
  pywraps_notify_when_t() : in_notify(false) {}
};
exported bool ida_export add_notify_when(int when, PyObject *py_callable);

// void hexrays_clear_python_cfuncptr_t_references(void);

// void free_compiled_form_instances(void);

// #define PYGDBG_ENABLED
#ifdef PYGDBG_ENABLED
#define PYGLOG(...) msg(__VA_ARGS__)
#else
#define PYGLOG(...)
#endif

//-------------------------------------------------------------------------
struct pycall_res_t
{
  pycall_res_t(PyObject *pyo)
    : result(pyo)
  {
    PYGLOG("return code: %p\n", result.o);
  }

  ~pycall_res_t()
  {
    if ( PyErr_Occurred() )
      PyErr_Print();
  }

  inline bool success() const { return result.o != NULL; }

  newref_t result;

private:
  pycall_res_t(); // No.
};

#include <loader.hpp>

//-------------------------------------------------------------------------
//                        CustomIDAMemo wrappers
//-------------------------------------------------------------------------i
class lookup_info_t;
class py_customidamemo_t;
struct lookup_entry_t
{
  lookup_entry_t() : view(NULL), py_view(NULL) {}

  TWidget *view;
  py_customidamemo_t *py_view;
};
DECLARE_TYPE_AS_MOVABLE(lookup_entry_t);
typedef qvector<lookup_entry_t> lookup_entries_t;

#include <graph.hpp>
#define PY_LINFO_HLPPRM_new_entry (lookup_info_t *_this, py_customidamemo_t *py_view)
#define PY_LINFO_PARAMS_new_entry (py_customidamemo_t *py_view)
#define PY_LINFO_TRANSM_new_entry (this, py_view)

#define PY_LINFO_HLPPRM_commit (lookup_info_t *_this, lookup_entry_t &e, TWidget *view)
#define PY_LINFO_PARAMS_commit (lookup_entry_t &e, TWidget *view)
#define PY_LINFO_TRANSM_commit (this, e, view)

#define PY_LINFO_HLPPRM_find_by_view (const lookup_info_t *_this, py_customidamemo_t **out_py_view, const TWidget *view)
#define PY_LINFO_PARAMS_find_by_view (py_customidamemo_t **out_py_view, const TWidget *view) const
#define PY_LINFO_TRANSM_find_by_view (this, out_py_view, view)

#define PY_LINFO_HLPPRM_find_by_py_view (const lookup_info_t *_this, TWidget **out_view, const py_customidamemo_t *py_view)
#define PY_LINFO_PARAMS_find_by_py_view (TWidget **out_view, const py_customidamemo_t *py_view) const
#define PY_LINFO_TRANSM_find_by_py_view (this, out_view, py_view)

#define PY_LINFO_HLPPRM_del_by_py_view (lookup_info_t *_this, const py_customidamemo_t *py_view)
#define PY_LINFO_PARAMS_del_by_py_view (const py_customidamemo_t *py_view)
#define PY_LINFO_TRANSM_del_by_py_view (this, py_view)

#define DECL_LINFO_HELPER(decl, RType, MName, MParams)  \
  decl RType ida_export lookup_info_t_##MName MParams

#define DECL_LINFO_HELPERS(decl)                                          \
  DECL_LINFO_HELPER(decl, lookup_entry_t&, new_entry, PY_LINFO_HLPPRM_new_entry); \
  DECL_LINFO_HELPER(decl, void,            commit, PY_LINFO_HLPPRM_commit); \
  DECL_LINFO_HELPER(decl, bool,            find_by_view, PY_LINFO_HLPPRM_find_by_view);\
  DECL_LINFO_HELPER(decl, bool,            find_by_py_view, PY_LINFO_HLPPRM_find_by_py_view);\
  DECL_LINFO_HELPER(decl, bool,            del_by_py_view, PY_LINFO_HLPPRM_del_by_py_view);


DECL_LINFO_HELPERS(idaman);

class py_customidamemo_t;
class lookup_info_t
{
  DECL_LINFO_HELPERS(friend);

public:
#define PY_LINFO_TRAMPOLINE(RType, MName, MParams, PNames)                \
  RType MName MParams { return lookup_info_t_##MName PNames; }

  PY_LINFO_TRAMPOLINE(lookup_entry_t&, new_entry,       PY_LINFO_PARAMS_new_entry,       PY_LINFO_TRANSM_new_entry);
  PY_LINFO_TRAMPOLINE(void,            commit,          PY_LINFO_PARAMS_commit,          PY_LINFO_TRANSM_commit);
  PY_LINFO_TRAMPOLINE(bool,            find_by_view,    PY_LINFO_PARAMS_find_by_view,    PY_LINFO_TRANSM_find_by_view);
  PY_LINFO_TRAMPOLINE(bool,            find_by_py_view, PY_LINFO_PARAMS_find_by_py_view, PY_LINFO_TRANSM_find_by_py_view);
  PY_LINFO_TRAMPOLINE(bool,            del_by_py_view,  PY_LINFO_PARAMS_del_by_py_view,  PY_LINFO_TRANSM_del_by_py_view);
#undef PY_LINFO_TRAMPOLINE

private:
  lookup_entries_t entries;
};

extern exported lookup_info_t ida_export_data pycim_lookup_info;

//-------------------------------------------------------------------------
struct pycim_callback_id_t
{
  qstring name;
  int have;
};

struct pycim_callbacks_ids_t : public qvector<pycim_callback_id_t>
{
  void add(const char *_n, int _h)
  {
    pycim_callback_id_t &o = push_back();
    o.name = _n;
    o.have = _h;
  }
};

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
#define PY_CIM_HLPPRM_set_node_info (py_customidamemo_t *_this, PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags)
#define PY_CIM_PARAMS_set_node_info (PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags)
#define PY_CIM_TRANSM_set_node_info (this, py_node_idx, py_node_info, py_flags)

#define PY_CIM_HLPPRM_set_nodes_infos (py_customidamemo_t *_this, PyObject *dict)
#define PY_CIM_PARAMS_set_nodes_infos (PyObject *dict)
#define PY_CIM_TRANSM_set_nodes_infos (this, dict)

#define PY_CIM_HLPPRM_get_node_info (py_customidamemo_t *_this, PyObject *py_node_idx)
#define PY_CIM_PARAMS_get_node_info (PyObject *py_node_idx)
#define PY_CIM_TRANSM_get_node_info (this, py_node_idx)

#define PY_CIM_HLPPRM_del_nodes_infos (py_customidamemo_t *_this, PyObject *py_nodes)
#define PY_CIM_PARAMS_del_nodes_infos (PyObject *py_nodes)
#define PY_CIM_TRANSM_del_nodes_infos (this, py_nodes)

#define PY_CIM_HLPPRM_get_current_renderer_type (py_customidamemo_t *_this)
#define PY_CIM_PARAMS_get_current_renderer_type ()
#define PY_CIM_TRANSM_get_current_renderer_type (this)

#define PY_CIM_HLPPRM_set_current_renderer_type (py_customidamemo_t *_this, PyObject *py_rto)
#define PY_CIM_PARAMS_set_current_renderer_type (PyObject *py_rto)
#define PY_CIM_TRANSM_set_current_renderer_type (this, py_rto)

#define PY_CIM_HLPPRM_create_groups (py_customidamemo_t *_this, PyObject *groups_infos)
#define PY_CIM_PARAMS_create_groups (PyObject *groups_infos)
#define PY_CIM_TRANSM_create_groups (this, groups_infos)

#define PY_CIM_HLPPRM_delete_groups (py_customidamemo_t *_this, PyObject *groups, PyObject *new_current)
#define PY_CIM_PARAMS_delete_groups (PyObject *groups, PyObject *new_current)
#define PY_CIM_TRANSM_delete_groups (this, groups, new_current)

#define PY_CIM_HLPPRM_set_groups_visibility (py_customidamemo_t *_this, PyObject *groups, PyObject *expand, PyObject *new_current)
#define PY_CIM_PARAMS_set_groups_visibility (PyObject *groups, PyObject *expand, PyObject *new_current)
#define PY_CIM_TRANSM_set_groups_visibility (this, groups, expand, new_current)

#define PY_CIM_HLPPRM_collect_pyobject_callbacks (py_customidamemo_t *_this, PyObject *self)
#define PY_CIM_PARAMS_collect_pyobject_callbacks (PyObject *in_self)
#define PY_CIM_TRANSM_collect_pyobject_callbacks (this, in_self)

#define PY_CIM_HLPPRM_collect_class_callbacks_ids (py_customidamemo_t *_this, pycim_callbacks_ids_t *out)
#define PY_CIM_PARAMS_collect_class_callbacks_ids (pycim_callbacks_ids_t *out)
#define PY_CIM_TRANSM_collect_class_callbacks_ids (this, out)

#define PY_CIM_HLPPRM_bind (py_customidamemo_t *_this, PyObject *self, TWidget *view)
#define PY_CIM_PARAMS_bind (PyObject *in_self, TWidget *in_view)
#define PY_CIM_TRANSM_bind (this, in_self, in_view)

#define PY_CIM_HLPPRM_unbind (py_customidamemo_t *_this, bool clear_view)
#define PY_CIM_PARAMS_unbind (bool clear_view)
#define PY_CIM_TRANSM_unbind (this, clear_view)

#define DECL_CIM_HELPER(decl, RType, MName, MParams)            \
  decl RType ida_export py_customidamemo_t_##MName MParams

#define DECL_CIM_HELPERS(decl)                                          \
  DECL_CIM_HELPER(decl, void,      set_node_info, PY_CIM_HLPPRM_set_node_info); \
  DECL_CIM_HELPER(decl, void,      set_nodes_infos, PY_CIM_HLPPRM_set_nodes_infos); \
  DECL_CIM_HELPER(decl, PyObject*, get_node_info, PY_CIM_HLPPRM_get_node_info); \
  DECL_CIM_HELPER(decl, void,      del_nodes_infos, PY_CIM_HLPPRM_del_nodes_infos); \
  DECL_CIM_HELPER(decl, PyObject*, get_current_renderer_type, PY_CIM_HLPPRM_get_current_renderer_type); \
  DECL_CIM_HELPER(decl, void,      set_current_renderer_type, PY_CIM_HLPPRM_set_current_renderer_type); \
  DECL_CIM_HELPER(decl, PyObject*, create_groups, PY_CIM_HLPPRM_create_groups); \
  DECL_CIM_HELPER(decl, PyObject*, delete_groups, PY_CIM_HLPPRM_delete_groups); \
  DECL_CIM_HELPER(decl, PyObject*, set_groups_visibility, PY_CIM_HLPPRM_set_groups_visibility);\
  \
  DECL_CIM_HELPER(decl, bool,      collect_pyobject_callbacks, PY_CIM_HLPPRM_collect_pyobject_callbacks); \
  DECL_CIM_HELPER(decl, void,      collect_class_callbacks_ids, PY_CIM_HLPPRM_collect_class_callbacks_ids); \
  DECL_CIM_HELPER(decl, bool,      bind, PY_CIM_HLPPRM_bind); \
  DECL_CIM_HELPER(decl, void,      unbind, PY_CIM_HLPPRM_unbind); \

DECL_CIM_HELPERS(idaman);

//-------------------------------------------------------------------------
#define PY_CIM_TRAMPOLINE(RType, MName, MParams, PNames)                \
  RType MName MParams { return py_customidamemo_t_##MName PNames; }

class py_customidamemo_t
{
  void convert_node_info(
          node_info_t *out,
          uint32 *out_flags,
          ref_t py_nodeinfo);

  // can use up to 16 bits; not more! (GRCODE_HAVE_* uses the rest)
  enum
  {
    GRBASE_HAVE_VIEW_MOUSE_MOVED = 0x0001,
  };

  int cb_flags;

  // View events
  void on_view_mouse_moved(const view_mouse_event_t *event);
  int get_py_method_arg_count(char *method_name);

  // View events that are bound with 'set_custom_viewer_handler()'.
  static void idaapi s_on_view_mouse_moved(
          TWidget *cv,
          int shift,
          view_mouse_event_t *e,
          void *ud);

  DECL_CIM_HELPERS(friend);

protected:
  ref_t self;
  TWidget *view;
  pycim_callbacks_ids_t cbids;

  PY_CIM_TRAMPOLINE(bool, collect_pyobject_callbacks, PY_CIM_PARAMS_collect_pyobject_callbacks, PY_CIM_TRANSM_collect_pyobject_callbacks);
  PY_CIM_TRAMPOLINE(virtual void, collect_class_callbacks_ids, PY_CIM_PARAMS_collect_class_callbacks_ids, PY_CIM_TRANSM_collect_class_callbacks_ids);
  PY_CIM_TRAMPOLINE(bool, bind, PY_CIM_PARAMS_bind, PY_CIM_TRANSM_bind);
  PY_CIM_TRAMPOLINE(void, unbind, PY_CIM_PARAMS_unbind, PY_CIM_TRANSM_unbind);

  friend TWidget *pycim_get_widget(PyObject *self);

public:
  py_customidamemo_t()
    : cb_flags(0),
      self(newref_t(NULL)),
      view(NULL)
  {
    PYGLOG("%p: py_customidamemo_t()\n", this);
  }
  virtual ~py_customidamemo_t()
  {
    PYGLOG("%p: ~py_customidamemo_t()\n", this);
    unbind(true);
    pycim_lookup_info.del_by_py_view(this);
  }

  virtual void refresh()
  {
    refresh_viewer(view);
  }
  inline bool has_callback(int flag) { return (cb_flags & flag) != 0; }

  PY_CIM_TRAMPOLINE(void,      set_node_info,             PY_CIM_PARAMS_set_node_info,             PY_CIM_TRANSM_set_node_info);
  PY_CIM_TRAMPOLINE(void,      set_nodes_infos,           PY_CIM_PARAMS_set_nodes_infos,           PY_CIM_TRANSM_set_nodes_infos);
  PY_CIM_TRAMPOLINE(PyObject*, get_node_info,             PY_CIM_PARAMS_get_node_info,             PY_CIM_TRANSM_get_node_info);
  PY_CIM_TRAMPOLINE(void,      del_nodes_infos,           PY_CIM_PARAMS_del_nodes_infos,           PY_CIM_TRANSM_del_nodes_infos);
  PY_CIM_TRAMPOLINE(PyObject*, get_current_renderer_type, PY_CIM_PARAMS_get_current_renderer_type, PY_CIM_TRANSM_get_current_renderer_type);
  PY_CIM_TRAMPOLINE(void,      set_current_renderer_type, PY_CIM_PARAMS_set_current_renderer_type, PY_CIM_TRANSM_set_current_renderer_type);
  PY_CIM_TRAMPOLINE(PyObject*, create_groups,             PY_CIM_PARAMS_create_groups,             PY_CIM_TRANSM_create_groups);
  PY_CIM_TRAMPOLINE(PyObject*, delete_groups,             PY_CIM_PARAMS_delete_groups,             PY_CIM_TRANSM_delete_groups);
  PY_CIM_TRAMPOLINE(PyObject*, set_groups_visibility,     PY_CIM_PARAMS_set_groups_visibility,     PY_CIM_TRANSM_set_groups_visibility);
};
#undef PY_CIM_TRAMPOLINE

#undef DECL_CIM_HELPERS
#undef DECL_CIM_HELPER


//-------------------------------------------------------------------------
template <typename T>
T *view_extract_this(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_this(PyW_TryGetAttrString(self, S_M_THIS));
  if ( py_this == NULL || !PyCObject_Check(py_this.o) )
    return NULL;
  return (T*) PyCObject_AsVoidPtr(py_this.o);
}

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
#include <typeinf.hpp>
#define DECL_REG_UNREG_REFCOUNTED(Type)                                 \
  exported void ida_export til_register_python_##Type##_instance(Type *inst); \
  exported void ida_export til_deregister_python_##Type##_instance(Type *inst);
DECL_REG_UNREG_REFCOUNTED(tinfo_t);
DECL_REG_UNREG_REFCOUNTED(ptr_type_data_t);
DECL_REG_UNREG_REFCOUNTED(array_type_data_t);
DECL_REG_UNREG_REFCOUNTED(func_type_data_t);
DECL_REG_UNREG_REFCOUNTED(udt_type_data_t);
#undef DECL_REG_UNREG_REFCOUNTED

//-------------------------------------------------------------------------
// Context structure used by register/unregister timer
struct py_timer_ctx_t
{
  py_timer_ctx_t() : timer_id(NULL), pycallback(NULL) {}
  qtimer_t timer_id;
  PyObject *pycallback;
};
exported py_timer_ctx_t *ida_export python_timer_new(PyObject *py_callback);
exported void ida_export python_timer_del(py_timer_ctx_t *t);

//-------------------------------------------------------------------------
exported ref_t ida_export try_create_swig_wrapper(ref_t mod, const char *clsname, void *cobj);

//-------------------------------------------------------------------------
// Useful for small operations that must not be interrupted: e.g., when
// wrapping an insn_t into a SWiG proxy object, or when destroying
// such an instance from the kernel. Use 'uninterruptible_op_t' if you can.
exported void ida_export set_interruptible_state(bool interruptible);
struct uninterruptible_op_t
{
  uninterruptible_op_t() { set_interruptible_state(false); }
  ~uninterruptible_op_t() { set_interruptible_state(true); }
};

// //-------------------------------------------------------------------------
// class py_custom_data_type_t;
// class py_custom_data_format_t;
// typedef void py_custom_data_type_t_unregisterer_t(py_custom_data_type_t *inst);
// typedef void py_custom_data_format_t_unregisterer_t(py_custom_data_format_t *inst);
// exported void ida_export register_py_custom_data_type_and_format_unregisterer(
//         py_custom_data_type_t_unregisterer_t cdt_unregisterer,
//         py_custom_data_format_t_unregisterer_t cdf_unregisterer);
// exported void ida_export register_py_custom_data_type_instance(py_custom_data_type_t *inst);
// exported void ida_export register_py_custom_data_format_instance(py_custom_data_format_t *inst);
// exported void ida_export unregister_py_custom_data_type_instance(py_custom_data_type_t *inst);
// exported void ida_export unregister_py_custom_data_format_instance(py_custom_data_format_t *inst);
// exported py_custom_data_type_t *py_custom_data_type_cast(data_type_t *inst);
// exported py_custom_data_format_t *py_custom_data_format_cast(data_format_t *inst);

exported bool ida_export idapython_hook_to_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data);
exported bool ida_export idapython_unhook_from_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data);
#define hook_to_notification_point USE_IDAPYTHON_HOOK_TO_NOTIFICATION_POINT
#define unhook_from_notification_point USE_IDAPYTHON_UNHOOK_FROM_NOTIFICATION_POINT

//-------------------------------------------------------------------------
struct module_callbacks_t
{
  module_callbacks_t() { memset(this, 0, sizeof(*this)); }
  void (*closebase) (void);
  void (*term) (void);
};
DECLARE_TYPE_AS_MOVABLE(module_callbacks_t);
exported void register_module_lifecycle_callbacks(
        const module_callbacks_t &cbs);

#endif // __PYWRAPS_HPP__
