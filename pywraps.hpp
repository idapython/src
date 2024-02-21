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
#define PY_BV_TYPE "y"
#define PY_BV_FIELDCMTS "y"
#define PY_BV_FIELDS "y"
#define PY_BV_BYTES "y"

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
struct jobj_t;
struct jarr_t;
struct jvalue_t;

// "A pointer can be explicitly converted to any integral type large
//  enough to hold it. The mapping function is implementation-defined."
//                                                           - C++03
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

#define PTR2U64(Binding) (uint64(Binding))

//------------------------------------------------------------------------
#define S_IDA_IDAAPI_MODNAME                     "ida_idaapi"
#define S_IDA_NALT_MODNAME                       "ida_nalt"
#define S_IDA_UA_MODNAME                         "ida_ua"
#define S_IDA_KERNWIN_MODNAME                    "ida_kernwin"
#define S_IDA_MOVES_MODNAME                      "ida_moves"
#define S_IDC_MODNAME                            "idc"
#define S_IDAAPI_EXECSCRIPT                      "IDAPython_ExecScript"
#define S_IDAAPI_FINDCOMPLETIONS                 "IDAPython_Completion"
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
static const char S_COLS[]                   = "cols";
static const char S_ASM_KEYWORD[]            = "asm_keyword";
static const char S_MENU_NAME[]              = "menu_name";
static const char S_HOTKEY[]                 = "hotkey";
static const char S_EMBEDDED[]               = "embedded";
static const char S_POPUP_NAMES[]            = "popup_names";
static const char S_FLAGS[]                  = "flags";
static const char S_FLAGS2[]                 = "flags2";
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
static const char S_ON_FIND_COMPLETIONS[]    = "OnFindCompletions";
static const char S_ON_CREATE[]              = "OnCreate";
static const char S_ON_POPUP[]               = "OnPopup";
static const char S_ON_HINT[]                = "OnHint";
static const char S_ON_EDGE_HINT[]           = "OnEdgeHint";
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
static const char S_ON_GET_EA[]              = "OnGetEA";
static const char S_ON_GET_DIRTREE[]         = "OnGetDirTree";
static const char S_ON_INDEX_TO_INODE[]      = "OnIndexToInode";
static const char S_ON_INDEX_TO_DIFFPOS[]    = "OnIndexToDiffpos";
static const char S_ON_LAZY_LOAD_DIR[]       = "OnLazyLoadDir";
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
static const char S_FILE[]                   = "__file__";

#define VALID_CAPSULE_NAME "$valid$"
#define INVALID_CAPSULE_NAME "$INvalid$"

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
// Constants used by the pyvar_to_idcvar and idcvar_to_pyvar functions
#define CIP_FAILED      -1 // Conversion error
#define CIP_IMMUTABLE    0 // Immutable object passed. Will not update the object but no error occurred
#define CIP_OK           1 // Success
#define CIP_OK_OPAQUE    2 // Success, but the data pointed to by the PyObject* is an opaque object.

//-------------------------------------------------------------------------
inline bool PyUnicode_as_qstring(qstring *out, PyObject *obj)
{
  PyObject *utf8 = PyUnicode_AsUTF8String(obj);
  bool ok = utf8 != nullptr;
  if ( ok )
  {
    char *buffer = nullptr;
    Py_ssize_t length = 0;
    ok = PyBytes_AsStringAndSize(utf8, &buffer, &length) >= 0;
    if ( ok )
    {
      out->qclear();
      out->append(buffer, length);
    }
  }
  Py_XDECREF(utf8);
  return ok;
}

//-------------------------------------------------------------------------
inline PyObject *PyUnicode_from_qstring(const qstring &s)
{
  return PyUnicode_FromStringAndSize(s.c_str(), s.length());
}

//-------------------------------------------------------------------------
inline bool PyBytes_as_bytevec_t(bytevec_t *out, PyObject *obj)
{
  char *buffer = nullptr;
  Py_ssize_t length = 0;
  bool ok = PyBytes_AsStringAndSize(obj, &buffer, &length) >= 0;
  if ( ok )
  {
    out->qclear();
    out->append((const uchar *) buffer, length);
  }
  return ok;
}

//-------------------------------------------------------------------------
inline bool PyBytes_as_qtype(qtype *out, PyObject *obj)
{
  bytevec_t bytes;
  bool ok = PyBytes_as_bytevec_t(&bytes, obj);
  if ( ok )
  {
    out->qclear();
    out->append(bytes.begin(), bytes.size());
  }
  return ok;
}

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

#ifdef Py_LIMITED_API
#  define GIL_CHKCONDFAIL (false)
#else
#  define GIL_CHKCONDFAIL (((debug & IDA_DEBUG_PLUGIN) != 0) && !PyGILState_Check())
#endif

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

  ref_t() : o(nullptr) {}
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
    if ( was != nullptr )
      Py_DECREF(was);
    return *this;
  }

  void incref() const { if ( o != nullptr ) Py_INCREF(o); }
  void decref() const { if ( o != nullptr ) { QASSERT(30469, o->ob_refcnt > 0); Py_DECREF(o); } }

  bool operator==(PyObject *other) const { return o == other; }
  bool operator!=(PyObject *other) const { return !((*this) == other); }

  bool operator==(const ref_t &other) const { return o == other.o; }
  bool operator!=(const ref_t &other) const { return !((*this) == other); }
  operator bool() const { return o != nullptr; }
};

struct borref_t;

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
  newref_t() = delete;
  newref_t(const newref_t &other) = delete;
  newref_t &operator=(const newref_t &other) = delete;
  newref_t(const borref_t &other) = delete;
  newref_t &operator=(const borref_t &other) = delete;
  newref_t(PyObject *_o)
  {
#ifdef _DEBUG
    QASSERT(30409, _o == nullptr || _o->ob_refcnt >= 1);
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
  borref_t() = delete;
  borref_t(const newref_t &other) = delete;
  borref_t &operator=(const newref_t &other) = delete;
  borref_t(const borref_t &other) = delete;
  borref_t &operator=(const borref_t &other) = delete;
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
    size_t _n = size();
    out->resize(_n);
    for ( size_t i = 0; i < _n; ++i )
      out->at(i) = at(i).o;
  }
};

#ifdef _MSC_VER
// warning C4190: 'PyW_TryImportModule' has C-linkage specified, but returns UDT 'ref_t' which is incompatible with C
#pragma warning(disable : 4190)
#elif defined(__MAC__)
GCC_DIAG_OFF(return-type-c-linkage);
#endif


// Tries to import a module and swallows the exception if it fails and returns nullptr
// Return value: New reference.
idaman ref_t ida_export PyW_TryImportModule(const char *name);

// Tries to get an attribute and swallows the exception if it fails and returns nullptr
idaman ref_t ida_export PyW_TryGetAttrString(PyObject *py_var, const char *attr);

// Converts a Python number (LONGLONG or normal integer) to an IDC variable (VT_LONG or VT_INT64)
idaman bool ida_export PyW_GetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var);

// Returns a qstring from a Python attribute string
idaman bool ida_export PyW_GetStringAttr(
        PyObject *py_obj,
        const char *attr_name,
        qstring *str);

// Deprecated. Please use specific functions instead.
idaman bool ida_export PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64 = nullptr);

// Checks if an Python object can be treated like a sequence
idaman bool ida_export PyW_IsSequenceType(PyObject *obj);

// Returns an error string from the last exception (and clears it)
idaman bool ida_export PyW_GetError(qstring *out = nullptr, bool clear_err = true);

// If an error occurred (it calls PyGetError) it displays it and return TRUE
// This function is used when calling callbacks
idaman bool ida_export PyW_ShowCbErr(const char *cb_name);

// Utility function to create linked class instances
idaman ref_t ida_export create_linked_class_instance(const char *modname, const char *clsname, void *lnk);

// Returns the string representation of a PyObject
idaman bool ida_export PyW_ObjectToString(PyObject *obj, qstring *out);

// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
idaman bool ida_export pyvar_to_idcvar_or_error(const ref_t &py_obj, idc_value_t *idc_obj);

// Creates and initializes an IDC exception
idaman error_t ida_export PyW_CreateIdcException(idc_value_t *res, const char *msg);

//
// Conversion functions
//
#define PYWCVTF_AS_TUPLE                 0x1
#define PYWCVTF_INT64_AS_UNSIGNED_PYLONG 0x2 // don't wrap int64 into 'PyIdc_cvt_int64__' objects, but make them 'long' instead
#define PYWCVTF_STR_AS_BYTES             0x4 // VT_STR objects will be converted into 'bytes', not strings coming from UTF-8 data

// Converts from IDC to Python
idaman bool ida_export pyw_convert_idc_args(
        const idc_value_t args[],
        int nargs,
        ref_vec_t &pargs,
        uint32 flags,
        qstring *errbuf = nullptr);

// Converts from IDC to Python
// We support converting VT_REF IDC variable types
idaman int ida_export idcvar_to_pyvar(
        const idc_value_t &idc_var,
        ref_t *py_var,
        uint32 flags=0);

//-------------------------------------------------------------------------
// Converts Python variable to IDC variable
// gvar_sn is used in case the Python object was a created from a call to idcvar_to_pyvar and the IDC object was a VT_REF
idaman int ida_export pyvar_to_idcvar(
        const ref_t &py_var,
        idc_value_t *idc_var,
        int *gvar_sn=nullptr);

//-------------------------------------------------------------------------
// Walks a Python sequence and calls the callback
idaman Py_ssize_t ida_export pyvar_walk_seq(
        PyObject *py_list,
        int (idaapi *cb)(const ref_t &py_item, Py_ssize_t index, void *ud)=nullptr,
        void *ud = nullptr,
        size_t maxsize=size_t(-1));

// Converts a vector to a Python list object
idaman ref_t ida_export PyW_SizeVecToPyList(const sizevec_t &vec);
idaman ref_t ida_export PyW_UvalVecToPyList(const uvalvec_t &vec);
idaman ref_t ida_export PyW_StrVecToPyList(const qstrvec_t &vec);

// Converts a Python list, to a vector of the given type.
// An exception will be raised in case:
//  - py_list is not a sequence
//  - a member of py_list cannot be converted to the numeric target type
idaman Py_ssize_t ida_export PyW_PySeqToSizeVec(sizevec_t *out, PyObject *py_list, size_t maxsize=size_t(-1));
idaman Py_ssize_t ida_export PyW_PySeqToEaVec(eavec_t *out, PyObject *py_list, size_t maxsize=size_t(-1));
idaman Py_ssize_t ida_export PyW_PySeqToStrVec(qstrvec_t *out, PyObject *py_list, size_t maxsize=size_t(-1));
idaman Py_ssize_t ida_export PyW_PySeqToTidVec(qvector<tid_t> *out, PyObject *py_list, size_t maxsize=size_t(-1));

idaman PyObject *ida_export PyW_from_jvalue_t(const jvalue_t &v);
idaman bool ida_export PyW_to_jvalue_t(jvalue_t *out, PyObject *py);
idaman PyObject *ida_export PyW_from_jobj_t(const jobj_t &o);
idaman bool ida_export PyW_to_jobj_t(jobj_t *out, PyObject *py);

#ifndef LUMINA_HPP // I'd rather put the def of ea64_t and ea64vec_t into pro.h...
#ifdef __EA64__
typedef ea_t ea64_t;
#else
typedef uint64 ea64_t;
#endif
typedef qvector<ea64_t> ea64vec_t;
#endif // LUMINA_HPP
idaman Py_ssize_t ida_export PyW_PySeqToEa64Vec(ea64vec_t *out, PyObject *py_list, size_t maxsize=size_t(-1));

//-------------------------------------------------------------------------
#include <idd.hpp>
idaman PyObject *ida_export meminfo_vec_t_to_py(meminfo_vec_t &ranges);

//-------------------------------------------------------------------------
idaman void ida_export PyW_register_compiled_form(PyObject *py_form);

//-------------------------------------------------------------------------
idaman void ida_export PyW_unregister_compiled_form(PyObject *py_form);

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

  inline bool success() const { return result.o != nullptr; }

  newref_t result;

private:
  pycall_res_t() = delete;
};

#include <loader.hpp>

//-------------------------------------------------------------------------
//                        CustomIDAMemo wrappers
//-------------------------------------------------------------------------i
class lookup_info_t;
class py_customidamemo_t;
struct lookup_entry_t
{
  lookup_entry_t() : view(nullptr), py_view(nullptr) {}

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

#ifdef __NT__
  #ifdef PLUGIN_SUBMODULE
    #define plugin_export_data __declspec(dllimport)
  #else
    #define plugin_export_data __declspec(dllexport)
  #endif
#else // unix
  #define plugin_export_data __attribute__((visibility("default")))
#endif

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

#define PY_CIM_HLPPRM_unbind (py_customidamemo_t *_this)
#define PY_CIM_PARAMS_unbind ()
#define PY_CIM_TRANSM_unbind (this)

#define DECL_CIM_HELPER(decl, RType, MName, MParams)            \
  decl RType ida_export py_customidamemo_t_##MName MParams

#define DECL_CIM_HELPERS(decl)                                          \
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
  // can use up to 16 bits; not more! (GRCODE_HAVE_* uses the rest)
  enum
  {
    GRBASE_HAVE_VIEW_MOUSE_MOVED = 0x0001,
  };

  int cb_flags;

  // View events
  void on_view_mouse_moved(const view_mouse_event_t *event);

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
  py_customidamemo_t();
  virtual ~py_customidamemo_t();

  virtual void refresh()
  {
    refresh_viewer(view);
  }
  inline bool has_callback(int flag) { return (cb_flags & flag) != 0; }

  PY_CIM_TRAMPOLINE(PyObject*, create_groups,             PY_CIM_PARAMS_create_groups,             PY_CIM_TRANSM_create_groups);
  PY_CIM_TRAMPOLINE(PyObject*, delete_groups,             PY_CIM_PARAMS_delete_groups,             PY_CIM_TRANSM_delete_groups);
  PY_CIM_TRAMPOLINE(PyObject*, set_groups_visibility,     PY_CIM_PARAMS_set_groups_visibility,     PY_CIM_TRANSM_set_groups_visibility);
};
#undef PY_CIM_TRAMPOLINE

#undef DECL_CIM_HELPERS
#undef DECL_CIM_HELPER

//-------------------------------------------------------------------------
inline void *view_extract_this(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_this(PyW_TryGetAttrString(self, S_M_THIS));
  if ( py_this == nullptr || !PyCapsule_IsValid(py_this.o, VALID_CAPSULE_NAME) )
    return nullptr;
  return PyCapsule_GetPointer(py_this.o, VALID_CAPSULE_NAME);
}

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
#include <typeinf.hpp>
#define DECL_REG_UNREG_REFCOUNTED(Type)                                 \
  idaman void ida_export til_register_python_##Type##_instance(Type *inst); \
  idaman void ida_export til_deregister_python_##Type##_instance(Type *inst);
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
  py_timer_ctx_t() : timer_id(nullptr) {}
  qtimer_t timer_id;
  ref_t pyfunc;
};

//-------------------------------------------------------------------------
idaman py_timer_ctx_t *ida_export python_timer_new(PyObject *py_callback);
idaman void ida_export python_timer_del(py_timer_ctx_t *t);

//-------------------------------------------------------------------------
idaman ref_t ida_export try_create_swig_wrapper(ref_t mod, const char *clsname, void *cobj);

//-------------------------------------------------------------------------
idaman ssize_t ida_export get_callable_arg_count(ref_t callable);

//-------------------------------------------------------------------------
// Useful for small operations that must not be interrupted: e.g., when
// wrapping an insn_t into a SWiG proxy object, or when destroying
// such an instance from the kernel. Use 'uninterruptible_op_t' if you can.
idaman void ida_export set_interruptible_state(bool interruptible);
struct uninterruptible_op_t
{
  uninterruptible_op_t() { set_interruptible_state(false); }
  ~uninterruptible_op_t() { set_interruptible_state(true); }
};

//-------------------------------------------------------------------------
struct new_execution_t;
idaman void ida_export setup_new_execution(new_execution_t *instance, bool setup);
struct new_execution_t
{
  bool created;
  new_execution_t() { setup_new_execution(this, true); }
  ~new_execution_t() { setup_new_execution(this, false); }
};

//-------------------------------------------------------------------------
enum run_script_when_t
{
  RSW_UNKNOWN = 0,
  RSW_ui_database_inited,  // run script after opening database (default)
  RSW_ui_ready_to_run,     // run script when UI is ready
  RSW_on_init,             // run script immediately on plugin load (shortly after IDA starts)
};

//-------------------------------------------------------------------------
struct idapython_plugin_config_t
{
  struct run_script_t
  {
    qstring path;
    run_script_when_t when;
    run_script_t() : when(RSW_UNKNOWN) {}
  };
  run_script_t run_script;
  uint32 execution_timeout = 0;
  bool alert_auto_scripts = true;
  bool remove_cwd_sys_path = false;
  bool autoimport_compat_idaapi = true;
  bool namespace_aware = true;
  bool repl_use_sys_displayhook = true;
  bool idausr_syspath = true;
};

//-------------------------------------------------------------------------
struct idapython_plugin_t : public plugmod_t, public event_listener_t
{
  idapython_plugin_config_t config;
  lookup_info_t pycim_lookup_info;
  qstring idapython_dir;
  qstring requested_plugin_path;
#ifdef __MAC__
  qvector<wchar_t> pyhomepath;
#endif
  bool initialized;
  bool ui_ready;
#ifdef TESTABLE_BUILD
  int user_code_lenient;
#endif

  idapython_plugin_t();
  ~idapython_plugin_t();

  bool init();
  void parse_plugin_options();
  ref_t get_sys_displayhook();
#ifdef TESTABLE_BUILD
  bool is_user_code_lenient();
#endif

  virtual bool idaapi run(size_t arg) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  static ssize_t idaapi on_idb_notification(void *, int code, va_list va);

  static idapython_plugin_t *get_instance() { return instance; }

  static bool idaapi extlang_compile_file(
        const char *path,
        qstring *errbuf)
  {
    return get_instance()->_extlang_compile_file(path, errbuf);
  }

  static bool idaapi extlang_compile_expr(
        const char *name,
        ea_t current_ea,
        const char *expr,
        qstring *errbuf)
  {
    return get_instance()->_extlang_compile_expr(name, current_ea, expr, errbuf);
  }

  static bool idaapi extlang_eval_expr(
        idc_value_t *rv,
        ea_t current_ea,
        const char *expr,
        qstring *errbuf)
  {
    return get_instance()->_extlang_eval_expr(rv, current_ea, expr, errbuf);
  }

  static bool idaapi extlang_load_procmod(
        idc_value_t *procobj,
        const char *path,
        qstring *errbuf)
  {
    return get_instance()->_extlang_load_procmod(procobj, path, errbuf);
  }

  static bool idaapi extlang_unload_procmod(
        const char *path,
        qstring *errbuf)
  {
    return get_instance()->_extlang_unload_procmod(path, errbuf);
  }

  static bool idaapi extlang_create_object(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf)
  {
    return get_instance()->_extlang_create_object(result, name, args, nargs, errbuf);
  }

  static bool idaapi extlang_eval_snippet(
        const char *str,
        qstring *errbuf)
  {
    return get_instance()->_extlang_eval_snippet(str, errbuf);
  }

  static bool idaapi extlang_call_func(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf)
  {
    return get_instance()->_extlang_call_func(result, name, args, nargs, errbuf);
  }

  static bool idaapi extlang_call_method(
        idc_value_t *result,
        const idc_value_t *idc_obj,
        const char *method_name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf)
  {
    return get_instance()->_extlang_call_method(result, idc_obj, method_name, args, nargs, errbuf);
  }

  static bool idaapi extlang_get_attr(
        idc_value_t *result,
        const idc_value_t *obj,
        const char *attr)
  {
    return get_instance()->_extlang_get_attr(result, obj, attr);
  }

  static bool idaapi extlang_set_attr(
        idc_value_t *obj,
        const char *attr,
        const idc_value_t &value)
  {
    return get_instance()->_extlang_set_attr(obj, attr, value);
  }

  static bool idaapi cli_execute_line(
        const char *line)
  {
    return get_instance()->_cli_execute_line(line);
  }

  static bool idaapi cli_find_completions(
        qstrvec_t *out_completions,
        int *out_match_start,
        int *out_match_end,
        const char *line,
        int x)
  {
    return get_instance()->_cli_find_completions(out_completions, out_match_start, out_match_end, line, x);
  }

private:
  bool _extlang_compile_file(
        const char *path,
        qstring *errbuf);
  bool _extlang_compile_expr(
        const char *name,
        ea_t current_ea,
        const char *expr,
        qstring *errbuf);
  bool _extlang_eval_expr(
        idc_value_t *rv,
        ea_t current_ea,
        const char *expr,
        qstring *errbuf);
  bool _extlang_load_procmod(
        idc_value_t *procobj,
        const char *path,
        qstring *errbuf);
  bool _extlang_unload_procmod(
        const char *path,
        qstring *errbuf);
  bool _extlang_create_object(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf);
  bool _extlang_eval_snippet(
        const char *str,
        qstring *errbuf);
  bool _extlang_call_func(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf);
  bool _extlang_call_method(
        idc_value_t *result,
        const idc_value_t *idc_obj,
        const char *method_name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf);
  bool _extlang_get_attr(
        idc_value_t *result,
        const idc_value_t *obj,
        const char *attr);
  bool _extlang_set_attr(
        idc_value_t *obj,
        const char *attr,
        const idc_value_t &value);

  bool _cli_execute_line(
        const char *line);
  bool _cli_find_completions(
        qstrvec_t *out_completions,
        int *out_match_start,
        int *out_match_end,
        const char *line,
        int x);

  bool _handle_file(
        const char *path,
        PyObject *globals,
        qstring *errbuf,
        const char *idaapi_executor_func_name = S_IDAAPI_EXECSCRIPT,
        idc_value_t *second_res = nullptr,
        bool want_tuple = false);

  bool _run_user_script();

  bool _check_python_dir();
  void _prepare_sys_path();
  bool _run_init_py();

  PyObject *_get_module_globals(const char *modname=nullptr);
  PyObject *_get_module_globals_from_path_with_kind(
        const char *path,
        const char *kind);
  PyObject *_get_module_globals_from_path(
        const char *path);

  static idapython_plugin_t *instance;
};

idaman idapython_plugin_t *ida_export get_plugin_instance();

//-------------------------------------------------------------------------
py_customidamemo_t::py_customidamemo_t()
  : cb_flags(0),
    self(newref_t(nullptr)),
    view(nullptr)
{
  PYGLOG("%p: py_customidamemo_t()\n", this);
}

//-------------------------------------------------------------------------
py_customidamemo_t::~py_customidamemo_t()
{
  PYGLOG("%p: ~py_customidamemo_t()\n", this);
  unbind();
  get_plugin_instance()->pycim_lookup_info.del_by_py_view(this);
}

//-------------------------------------------------------------------------
idaman void ida_export idapython_register_hook(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data,
        bool is_hooks_base);
idaman void ida_export idapython_unregister_hook(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data);

//-------------------------------------------------------------------------
idaman bool ida_export idapython_hook_to_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data,
        bool is_hooks_base);
idaman bool ida_export idapython_unhook_from_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data);
#define hook_to_notification_point USE_IDAPYTHON_HOOK_TO_NOTIFICATION_POINT
#define unhook_from_notification_point USE_IDAPYTHON_UNHOOK_FROM_NOTIFICATION_POINT

//-------------------------------------------------------------------------
#define HBF_CALL_WITH_NEW_EXEC  0x00000001
#define HBF_VOLATILE_METHOD_SET 0x00000002
struct hooks_base_t
{
  struct idapython_listener_t : public event_listener_t
  {
    hook_cb_t *cb;
    void *ud;
    idapython_listener_t(hook_cb_t *_cb, void *_ud) : cb(_cb), ud(_ud) {}
    virtual ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
      return cb(ud, code, va);
    }
  };

  const char *class_name;
  qstring identifier;
  idapython_listener_t listener;
  hook_type_t type;
  uint32 flags;
  uint32 hkcb_flags;
  typedef std::map<int,uchar> has_nondef_map_t;
  has_nondef_map_t has_nondef;
  bool hook_added = false;

  bool hook()
  {
    if ( !hook_added
      && listener.cb != nullptr
      && hook_event_listener(type, &listener, nullptr /*owner*/, hkcb_flags) )
    {
      idapython_register_hook(type, listener.cb, this, true);
      hook_added = true;
    }
    return hook_added;
  }
  bool unhook()
  {
    if ( hook_added && listener.cb != nullptr )
    {
      // there is no need to check the return result of unhook_event_listener,
      // if HKCB_GLOBAL flag is not used
      // the LISTENER will be freed earlier
      // than this method will be called.
      unhook_event_listener(type, &listener);
      idapython_unregister_hook(type, listener.cb, this);
      hook_added = false;
    }
    return !hook_added;
  }

  bool call_requires_new_execution() const { return (flags & HBF_CALL_WITH_NEW_EXEC) != 0; }
  bool has_fixed_method_set() const { return (flags & HBF_VOLATILE_METHOD_SET) == 0; }

  hooks_base_t(
          const char *_class_name,
          hook_cb_t *_cb,
          hook_type_t _type,
          uint32 _flags,
          uint32 _hkcb_flags)
    : class_name(_class_name),
      listener(_cb, this),
      type(_type),
      flags(_flags),
      hkcb_flags(_hkcb_flags) {}

  virtual ~hooks_base_t() { unhook(); }

  struct ida_local event_code_to_method_name_t
  {
    int code;
    const char *method_name;
  };

protected:
  void init_director_hooks(
        PyObject *self,
        const event_code_to_method_name_t *mappings,
        size_t count)
  {
    // identifier
    {
      ref_t py_id;
      if ( PyObject_HasAttrString(self, "id") )
        py_id = newref_t(PyObject_GetAttrString(self, "id"));
      if ( !py_id || !PyUnicode_Check(py_id.o) )
        py_id = newref_t(PyObject_Repr(self));
      if ( py_id && PyUnicode_Check(py_id.o) )
        PyUnicode_as_qstring(&identifier, py_id.o);
    }

    // method set
    QASSERT(30588, has_fixed_method_set());
    qstring buf(class_name);
    QASSERT(30589, !buf.empty());
    char *p = qstrchr(buf.begin(), '.');
    QASSERT(30590, p != nullptr);
    *p++ = '\0';
    newref_t py_mod(PyImport_ImportModule(buf.c_str()));
#ifdef TESTABLE_BUILD
    QASSERT(30591, py_mod);
#endif
    if ( py_mod )
    {
      newref_t py_def_class(PyObject_GetAttrString(py_mod.o, p));
      newref_t py_this_class(PyObject_GetAttrString(self, "__class__"));
#ifdef TESTABLE_BUILD
      QASSERT(30592, py_def_class && py_this_class);
#endif
      if ( py_def_class && py_this_class )
      {
        for ( size_t i = 0; i < count; ++i )
        {
          const event_code_to_method_name_t &cur = mappings[i];
          uchar _has_nondef = 0;
          newref_t py_def_meth(PyObject_GetAttrString(py_def_class.o, cur.method_name));
          newref_t py_this_meth(PyObject_GetAttrString(py_this_class.o, cur.method_name));
#ifdef TESTABLE_BUILD
          QASSERT(30593, py_def_meth && py_this_meth);
#endif
          if ( py_def_meth && py_this_meth )
          {
            if ( PyObject_HasAttrString(py_def_meth.o, "__trampoline") > 0 )
              _has_nondef = 2;
            else
              _has_nondef = PyObject_RichCompareBool(py_this_meth.o, py_def_meth.o, Py_EQ) == 0 ? 1 : 0;
          }
          has_nondef[cur.code] = _has_nondef;
        }
      }
    }
  }

  void ensure_no_method(
        PyObject *self,
        const char *forbidden_method_name,
        const char *replacement_method_name)
  {
    if ( PyObject_HasAttrString(self, "__class__") )
    {
      newref_t py_this_class(PyObject_GetAttrString(self, "__class__"));
      if ( py_this_class
        && PyObject_HasAttrString(py_this_class.o, forbidden_method_name) )
      {
        msg("WARNING: The method \"%s::%s\" won't be called (it has been replaced with \"%s::%s\")\n",
            class_name, forbidden_method_name, class_name, replacement_method_name);
      }
    }
  }

#ifdef TESTABLE_BUILD
  PyObject *dump_state(
          const event_code_to_method_name_t *mappings,
          size_t mappings_size,
          bool assert_all_reimplemented) const
  {
    qstring buf;
    qstrvec_t missing_reimpls;
    buf.sprnt("%s(this=%p) \"%s\" {type=%d, cb=%p, flags=%x}",
              class_name, this, identifier.c_str(), int(type), listener.cb, flags);
    if ( has_fixed_method_set() )
    {
      for ( size_t i = 0; i < mappings_size; ++i )
      {
        const hooks_base_t::event_code_to_method_name_t &m = mappings[i];
        has_nondef_map_t::const_iterator it = has_nondef.find(m.code);
        if ( it != has_nondef.end() && it->second > 0 )
        {
          const char *how = "";
          if ( it->second == 2 )
            how = " (as compat trampoline)";
          else if ( it->second == 3 )
            how = " (as 6.95 bw-compat)";
          buf.cat_sprnt("\n\treimplements \"%s\"%s", m.method_name, how);
        }
        else
        {
          missing_reimpls.push_back(m.method_name);
        }
      }
      const size_t nmr = missing_reimpls.size();
      if ( assert_all_reimplemented && nmr > 0 )
      {
        qstring ebuf;
        for ( size_t i = 0; i < nmr; ++i )
        {
          if ( !ebuf.empty() )
            ebuf.append(", ", 2);
          ebuf.append(missing_reimpls[i]);
        }
        PyErr_Format(PyExc_NotImplementedError,
                     "%s(this=%p) \"%s\" {type=%d, cb=%p, flags=%x} is "
                     "missing reimplementations for: \"%s\"",
                     class_name, this, identifier.c_str(), int(type), listener.cb,
                     flags, ebuf.c_str());
        return nullptr;
      }
    }
    else
    {
      buf.append(" is fully dynamic, and won't use 'has_nondef' lookup");
      QASSERT(30594, has_nondef.empty());
    }
    if ( buf.last() != '\n' )
      buf.append('\n');
    return PyUnicode_from_qstring(buf);
  }
#endif
};

//-------------------------------------------------------------------------
idaman THREAD_SAFE void ida_export idapython_show_wait_box(
        bool internal,
        const char *message);
idaman void ida_export idapython_hide_wait_box();
#define show_wait_box USE_IDAPYTHON_SHOW_WAIT_BOX
#define hide_wait_box USE_IDAPYTHON_HIDE_WAIT_BOX

//-------------------------------------------------------------------------
idaman bool ida_export idapython_convert_cli_completions(
        qstrvec_t *out_completions,
        int *out_match_start,
        int *out_match_end,
        ref_t py_res);

//-------------------------------------------------------------------------
idaman int ida_export pylong_to_byte_array(
        bytevec_t *out_allocated_buffer,
        PyObject *in,
        bool little_endian=true,
        bool is_signed=true);

//-------------------------------------------------------------------------
struct module_callbacks_t
{
  module_callbacks_t() { memset(this, 0, sizeof(*this)); }
  void (*init) (void);
  void (*term) (void);
  void (*closebase) (void);
};
DECLARE_TYPE_AS_MOVABLE(module_callbacks_t);
idaman void register_module_lifecycle_callbacks(
        const module_callbacks_t &cbs);

idaman void ida_export prepare_programmatic_plugin_load(const char *path);

#endif // __PYWRAPS_HPP__
