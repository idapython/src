%module(docstring="IDA Pro Plugin SDK API wrapper",directors="1") idaapi
// Suppress 'previous definition of XX' warnings
#pragma SWIG nowarn=302
// and others...
#pragma SWIG nowarn=312
#pragma SWIG nowarn=325
#pragma SWIG nowarn=314
#pragma SWIG nowarn=362
#pragma SWIG nowarn=383
#pragma SWIG nowarn=389
#pragma SWIG nowarn=401
#pragma SWIG nowarn=451
#pragma SWIG nowarn=454 // Setting a pointer/reference variable may leak memory

// Enable automatic docstring generation
%feature(autodoc);

// We use those special maps because SWIG wraps passed PyObject* with 'SwigPtr_PyObject' and 'SwigVar_PyObject'
// They act like autoptr and decrement the reference of the object when the scope ends
// We need to keep a reference outside SWIG and let the caller manage its references
%typemap(directorin)  PyObject * "/*%din%*/Py_XINCREF($1_name);$input = $1_name;"
%typemap(directorout) PyObject * "/*%dout%*/$result = result;Py_XINCREF($result);"
%{
#include <Python.h>

#ifndef USE_DANGEROUS_FUNCTIONS
  #define USE_DANGEROUS_FUNCTIONS 1
#endif

#ifndef NO_OBSOLETE_FUNCS
  #define NO_OBSOLETE_FUNCS 1
#endif  

#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif

#if defined(__NT__) && !defined(_WINDOWS_)
  #define _WINDOWS_ // kernwin.hpp needs it to declare create_tform()
  typedef void *HWND; // we don't need to include windows.h for just this definition
#endif

#include "ida.hpp"
#include "idp.hpp"
#include "allins.hpp"
#include "auto.hpp"
#include "bytes.hpp"
#include "dbg.hpp"
#include "diskio.hpp"
#include "entry.hpp"
#include "enum.hpp"
#include "expr.hpp"
#include "frame.hpp"
#include "fixup.hpp"
#include "funcs.hpp"
#include "gdl.hpp"
#include "idd.hpp"
#include "ints.hpp"
#include "kernwin.hpp"
#include "lines.hpp"
#include "loader.hpp"
#include "moves.hpp"
#include "netnode.hpp"
#include "nalt.hpp"
#include "name.hpp"
#include "offset.hpp"
#include "queue.hpp"
#include "search.hpp"
#include "srarea.hpp"
#include "strlist.hpp"
#include "struct.hpp"
#include "typeinf.hpp"
#include "ua.hpp"
#include "xref.hpp"
#include "ieee.h"
#include "err.h"
#include "fpro.h"
#include <map>
#include "graph.hpp"
#include "pywraps.hpp"

//<code(py_idaapi)>

//---------------------------------------------------------------------------
// Use these macros to define script<->C fields
#define DEFINE_SCFIELDX(name, type, is_opt) { #name, type, qoffsetof(CUR_STRUC, name), is_opt }
#define DEFINE_SCFIELD(name, type) DEFINE_SCFIELDX(name, type, 0)
#define DEFINE_SCFIELD_OPT(name, type) DEFINE_SCFIELDX(name, type, 1)

//---------------------------------------------------------------------------
enum scfield_types_t
{
  // Numeric fields
  FT_FIRST_NUM,
  FT_INT,
  FT_SIZET,
  FT_SSIZET,
  FT_NUM16,
  FT_NUM32,
  FT_LAST_NUM,
  // String field
  FT_STR,
  FT_CHAR,
  // Object fields
  FT_ARR,
  // Allocated array of strings
  FT_STRARR,
  // Allocated array of 16bit numbers
  FT_NUM16ARR,
  // Fixed size character array. The size must be passed in the definition
  FT_CHRARR_STATIC,
};

struct scfld_t
{
  const char *field_name;
  uint32 field_type;
  size_t field_offs;
  bool is_optional;
};

#define FT_VALUE_MASK        0xFFFF0000
// Possible return values of conversion functions
#define FT_NOT_FOUND         -1
#define FT_BAD_TYPE          -2
#define FT_OK                1

//-----------------------------------------------------------------------
class pycvt_t
{
  struct attr_t
  {
    qstring str;
    uint64 u64;
    // User is responsible to release this attribute when done
    PyObject *py_obj;
  };

  //-----------------------------------------------------------------------
  static int get_attr(
    PyObject *py_obj, 
    const char *attrname, 
    int ft, 
    attr_t &val)
  {
    PyObject *py_attr;
    if ( (py_attr = PyW_TryGetAttrString(py_obj, attrname)) == NULL )
      return FT_NOT_FOUND;

    int cvt = FT_OK;
    if ( ft == FT_STR || ft == FT_CHAR && PyString_Check(py_attr) )
      val.str = PyString_AsString(py_attr);
    else if ( (ft > FT_FIRST_NUM && ft < FT_LAST_NUM) && PyW_GetNumber(py_attr, &val.u64) )
      ; // nothing to be done
    // A string array?
    else if ( (ft == FT_STRARR || ft == FT_NUM16ARR || FT_CHRARR_STATIC ) 
      && (PyList_CheckExact(py_attr) || PyW_IsSequenceType(py_attr)) )
    {
      // Return a reference to the attribute
      val.py_obj = py_attr;
      // Do not decrement the reference to this attribute
      py_attr = NULL;
    }
    else
      cvt = FT_BAD_TYPE;
    Py_XDECREF(py_attr);
    return cvt;
  }

  //-----------------------------------------------------------------------
  static int idaapi make_str_list_cb(
    PyObject *py_item, 
    Py_ssize_t index, 
    void *ud)
  {
    if ( !PyString_Check(py_item) )
      return CIP_FAILED;
    char **a = (char **)ud;
    a[index] = qstrdup(PyString_AsString(py_item));
    return CIP_OK;
  }

  //-----------------------------------------------------------------------
  // Converts an IDC list of strings to a C string list
  static Py_ssize_t str_list_to_str_arr(
    PyObject *py_list,
    char ***arr)
  {
    // Take the size
    Py_ssize_t size = pyvar_walk_list(py_list);
    
    // Allocate a buffer
    char **a = (char **)qalloc((size + 1) * sizeof(char *));
    
    // Walk and populate
    size = pyvar_walk_list(py_list, make_str_list_cb, a);
    
    // Make the list NULL terminated
    a[size] = NULL;
    
    // Return the list to the user
    *arr = a;
    
    // Return the size of items processed
    return size;
  }

  //-----------------------------------------------------------------------
  typedef qvector<uint64> uint64vec_t;
  static int idaapi make_int_list(
    PyObject *py_item, 
    Py_ssize_t /*index*/, 
    void *ud)
  {
    uint64 val;
    if ( !PyW_GetNumber(py_item, &val) )
      return CIP_FAILED;
    uint64vec_t *vec = (uint64vec_t *)ud;
    vec->push_back(val);
    return CIP_OK;
  }

public:
  //-----------------------------------------------------------------------
  // Frees a NULL terminated list of fields
  static void free_fields(
    const scfld_t *fields,
    void *store_area)
  {
    for ( int i=0; ; i++ )
    {
      // End of list?
      const scfld_t &fd = fields[i];
      if ( fd.field_name == NULL )
        break;

      void *store = (void *)((char *)store_area + fd.field_offs);
      int ft = fd.field_type & ~FT_VALUE_MASK;
      switch ( ft )
      {
      case FT_STR:      // Simple string
        {
          char **s = (char **)store;
          if ( *s != NULL )
          {
            qfree(*s);
            *s = NULL;
          }
        }
        break;

      case FT_STRARR:   // Array of strings
        {
          char ***op = (char ***)store, **p = *op;
          while ( *p != NULL )
            qfree((void *)*p++);
          qfree(*op);
          *op = NULL;
        }
        break;

      case FT_NUM16ARR:
        {
          uint16 **arr = (uint16 **)store;
          if ( *arr != NULL )
          {
            qfree(*arr);
            *arr = NULL;
          }
        }
        break;
      }
    }
  }

  //-----------------------------------------------------------------------
  // Converts from a C structure to Python
  static int from_c(
    const scfld_t *fields,
    void *read_area,
    PyObject *py_obj)
  {
    PyObject *py_attr;
    int i;
    bool ok = false;
    for ( i=0; ; i++ )
    {
      // End of list?
      const scfld_t &fd = fields[i];
      if ( fd.field_name == NULL )
      {
        ok = true;
        break;
      }

      // Point to structure member
      int ft = fd.field_type & ~FT_VALUE_MASK;
      void *read = (void *)((char *)read_area + fd.field_offs);
      // Create the python attribute properly
      if ( ft > FT_FIRST_NUM && ft < FT_LAST_NUM )
      {
        if ( ft == FT_NUM16 )
          py_attr = Py_BuildValue("H", *(uint16 *)read);
        else if ( ft == FT_NUM32 )
          py_attr = Py_BuildValue("I", *(uint32 *)read);
        else if ( ft == FT_INT )
          py_attr = Py_BuildValue("i", *(int *)read);
        else if ( ft == FT_SIZET )
          py_attr = Py_BuildValue(PY_FMT64,*(size_t *)read);
        else if ( ft == FT_SSIZET )
          py_attr = Py_BuildValue(PY_SFMT64,*(ssize_t *)read);
      }
      else if ( ft == FT_STR || ft == FT_CHAR )
      {
        if ( ft == FT_STR )
          py_attr = PyString_FromString(*(char **)read);
        else
          py_attr = Py_BuildValue("c", *(char *)read);
      }
      else if ( ft == FT_STRARR )
      {
        char **arr = *(char ***)read;
        py_attr = PyList_New(0);
        while ( *arr != NULL )
          PyList_Append(py_attr, PyString_FromString(*arr++));
      }
      else
        continue;
      PyObject_SetAttrString(py_obj, fd.field_name, py_attr);
      Py_XDECREF(py_attr);
    }
    return ok ? -1 : i;
  }
  
  //-----------------------------------------------------------------------
  // Converts fields from IDC and field description into a C structure
  // If 'use_extlang' is specified, then the passed idc_obj is considered
  // to be an opaque object and thus can be queried only through extlang
  static int from_script(
    const scfld_t *fields,
    void *store_area,
    PyObject *py_obj)
  {
    int i;
    bool ok = false;
    attr_t attr;
    for ( i=0; ; i++ )
    {
      // End of list?
      const scfld_t &fd = fields[i];
      if ( fd.field_name == NULL )
      {
        ok = true;
        break;
      }

      // Get field type
      int ft = fd.field_type & ~FT_VALUE_MASK;
      
      // Point to structure member
      void *store = (void *)((char *)store_area + fd.field_offs);
      
      // Retrieve attribute and type
      int cvt = get_attr(py_obj, fd.field_name, ft, attr);
      
      // Attribute not found?
      if ( cvt == FT_NOT_FOUND )
      {
        // Skip optional fields
        if ( fd.is_optional )
          continue;
        break;
      }

      if ( ft == FT_STR )
        *(char **)store = qstrdup(attr.str.c_str());
      else if ( ft == FT_NUM32 )
        *(uint32 *)store = uint32(attr.u64);
      else if ( ft == FT_NUM16 )
        *(uint16 *)store = attr.u64 & 0xffff;
      else if ( ft == FT_INT )
        *(int *)store = int(attr.u64);
      else if ( ft == FT_SIZET )
        *(size_t *)store = size_t(attr.u64);
      else if ( ft == FT_SSIZET )
        *(ssize_t *)store = ssize_t(attr.u64);
      else if ( ft == FT_CHAR )
        *(char *)store = *attr.str.c_str();
      else if ( ft == FT_STRARR )
      {
        str_list_to_str_arr(attr.py_obj, (char ***)store);
        Py_DECREF(attr.py_obj);
      }
      else if ( ft == FT_CHRARR_STATIC )
      {
        size_t sz = (fd.field_type & FT_VALUE_MASK) >> 16;
        if ( sz == 0 )
          break;
        uint64vec_t w;
        char *a = (char *) store;
        if ( pyvar_walk_list(attr.py_obj, make_int_list, &w) )
        {
          sz = qmin(w.size(), sz);
          for ( size_t i=0; i < sz; i++ )
            a[i] = w[i] & 0xFF;
        }
      }
      else if ( ft == FT_NUM16ARR )
      {
        uint64vec_t w;
        if ( pyvar_walk_list(attr.py_obj, make_int_list, &w) > 0 )
        {
          size_t max_sz = (fd.field_type & FT_VALUE_MASK) >> 16;
          bool zero_term;
          if ( max_sz == 0 )
          {
            zero_term = true;
            max_sz = w.size();
          }
          else
          {
            zero_term = false;
            max_sz = qmin(max_sz, w.size());
          }
          // Allocate as much as we parsed elements
          // Add one more element if list was zero terminated
          uint16 *a = (uint16 *)qalloc(sizeof(uint16) * (max_sz + (zero_term ? 1 : 0))) ;
          for ( size_t i=0; i < max_sz; i++ )
            a[i] = w[i] & 0xFF;

          if ( zero_term )
            a[max_sz] = 0;
          *(uint16 **)store = a;
        }
      }
      else
      {
        // Unsupported field type!
        break;
      }
    }
    return ok ? -1 : i;
  }
};

//-------------------------------------------------------------------------
Py_ssize_t pyvar_walk_list(
  PyObject *py_list, 
  int (idaapi *cb)(PyObject *py_item, Py_ssize_t index, void *ud),
  void *ud)
{
  if ( !PyList_CheckExact(py_list) && !PyW_IsSequenceType(py_list) )
    return CIP_FAILED;

  bool is_seq = !PyList_CheckExact(py_list);
  Py_ssize_t size = is_seq ? PySequence_Size(py_list) : PyList_Size(py_list);

  if ( cb == NULL )
    return size;

  Py_ssize_t i;
  for ( i=0; i<size; i++ )
  {
    // Get the item
    PyObject *py_item = is_seq ? PySequence_GetItem(py_list, i) : PyList_GetItem(py_list, i);
    if ( py_item == NULL )
      break;

    int r = cb(py_item, i, ud);
    
    // Decrement reference (if needed)
    if ( r != CIP_OK_NODECREF && is_seq )
        Py_DECREF(py_item); // Only sequences require us to decrement the reference
    if ( r < CIP_OK )
      break;
  }
  return i;
}

//---------------------------------------------------------------------------
PyObject *PyW_IntVecToPyList(const intvec_t &intvec)
{
  size_t c = intvec.size();
  PyObject *py_list = PyList_New(c);

  for ( size_t i=0; i<c; i++ )
    PyList_SetItem(py_list, i, PyInt_FromLong(intvec[i]));

  return py_list;
}

//---------------------------------------------------------------------------
static int idaapi pylist_to_intvec_cb(
    PyObject *py_item, 
    Py_ssize_t index, 
    void *ud)
{
  intvec_t &intvec = *(intvec_t *)ud;
  uint64 num;
  if (!PyW_GetNumber(py_item, &num))
    num = 0;

  intvec.push_back(int(num));
  return CIP_OK;
}

void PyW_PyListToIntVec(PyObject *py_list, intvec_t &intvec)
{
  intvec.clear();
  (void)pyvar_walk_list(py_list, pylist_to_intvec_cb, &intvec);
}
//---------------------------------------------------------------------------





//------------------------------------------------------------------------
// String constants used
static const char S_PY_SWIEX_CLSNAME[]       = "switch_info_ex_t";
static const char S_PY_OP_T_CLSNAME[]        = "op_t";
static const char S_PY_IDC_GLOBAL_VAR_FMT[]  = "__py_cvt_gvar_%d";
static const char S_PY_IDCCVT_ID_ATTR[]      = "__idc_cvt_id__";
static const char S_PY_IDCCVT_VALUE_ATTR[]   = "__idc_cvt_value__";
static const char S_PY_IDC_OPAQUE_T[]        = "py_idc_cvt_helper_t";
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
static const char S_ON_REFRESHED[]           = "OnRefreshed";
static const char S_ON_EXECUTE_LINE[]        = "OnExecuteLine";
static const char S_ON_SELECT_LINE[]         = "OnSelectLine";
static const char S_ON_SELECTION_CHANGE[]    = "OnSelectionChange";
static const char S_ON_COMMAND[]             = "OnCommand";
static const char S_ON_GET_ICON[]            = "OnGetIcon";
static const char S_ON_GET_LINE_ATTR[]       = "OnGetLineAttr";
static const char S_ON_GET_SIZE[]            = "OnGetSize";
static const char S_ON_GETTEXT[]             = "OnGetText";
static const char S_ON_ACTIVATE[]            = "OnActivate";
static const char S_ON_DEACTIVATE[]          = "OnDeactivate";
static const char S_ON_SELECT[]              = "OnSelect";
static const char S_M_EDGES[]                = "_edges";
static const char S_M_NODES[]                = "_nodes";
static const char S_M_THIS[]                 = "_this";
static const char S_M_TITLE[]                = "_title";
static const char S_CLINK_NAME[]             = "__clink__";

#ifdef __PYWRAPS__
static const char S_PY_IDAAPI_MODNAME[]      = "__main__";
#else
static const char S_PY_IDAAPI_MODNAME[]      = S_IDAAPI_MODNAME;
#endif

//------------------------------------------------------------------------
// Constants used by get_idaapi_class_reference()
#define PY_CLSID_CVT_INT64                       0
#define PY_CLSID_APPCALL_SKEL_OBJ                1
#define PY_CLSID_CVT_BYREF                       2
#define PY_CLSID_LAST                            3

//------------------------------------------------------------------------
static PyObject *py_cvt_helper_module = NULL;
static bool pywraps_initialized = false;

//---------------------------------------------------------------------------
// Context structure used by add|del_menu_item()
struct py_add_del_menu_item_ctx
{
  qstring menupath;
  PyObject *cb_data;
};

//------------------------------------------------------------------------
const char *pywraps_check_autoscripts()
{
#define STRING1(x) #x
#define STRING2(x) STRING1(x)
  static const char *exts[] = {"py", "pyw", "pyc", "pyo"};

  static const char *fns[] = 
  {
    "swig_runtime_data" STRING2(SWIG_RUNTIME_VERSION),
    "sitecustomize",
    "usercustomize"
  };

  for (size_t ifn=0; ifn < qnumber(fns); ++ifn )
  {
    for ( size_t iext=0; iext < qnumber(exts); ++iext )
    {
      static char fn[QMAXPATH];
      qsnprintf(fn, sizeof(fn), "%s.%s", fns[ifn], exts[iext]);
      if ( qfileexist(fn) )
        return fn;
    }
  }
  return NULL;
#undef STRING1
#undef STRING2
}

//------------------------------------------------------------------------
static idc_class_t *get_py_idc_cvt_opaque()
{
  return find_idc_class(S_PY_IDC_OPAQUE_T);
}

//-------------------------------------------------------------------------
// Utility function to convert a python object to an IDC object
// and sets a python exception on failure.
bool convert_pyobj_to_idc_exc(PyObject *py_obj, idc_value_t *idc_obj)
{
  int sn = 0;
  if ( pyvar_to_idcvar(py_obj, idc_obj, &sn) < CIP_OK )
  {
    PyErr_SetString(PyExc_ValueError, "Could not convert Python object to IDC object!");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------
// IDC Opaque object destructor: when the IDC object dies we kill the
// opaque Python object along with it
static const char py_idc_cvt_helper_dtor_args[] = { VT_OBJ, 0 };
static error_t idaapi py_idc_opaque_dtor(
  idc_value_t *argv,
  idc_value_t * /*res*/)
{
  // Get the value from the object
  idc_value_t idc_val;
  VarGetAttr(&argv[0], S_PY_IDCCVT_VALUE_ATTR, &idc_val);

  // Extract the Python object reference
  PyObject *py_obj = (PyObject *)idc_val.pvoid;
  
  // Decrease its reference (and eventually destroy it)
  Py_DECREF(py_obj);

  return eOk;
}

//------------------------------------------------------------------------
// This function must be called on initialization
bool init_pywraps()
{
  if ( pywraps_initialized )
    return true;

  // Take a reference to the idaapi python module
  // (We need it to create instances of certain classes)
  if ( py_cvt_helper_module == NULL )
  {
    // Take a reference to the module so we can create the needed class instances
    py_cvt_helper_module = PyW_TryImportModule(S_PY_IDAAPI_MODNAME);
    if ( py_cvt_helper_module == NULL )
      return false;
  }

  if ( get_py_idc_cvt_opaque() == NULL )
  {
    // Add the class
    idc_class_t *idc_cvt_opaque = add_idc_class(S_PY_IDC_OPAQUE_T);
    if ( idc_cvt_opaque == NULL )
      return false;

    // Form the dtor name
    char dtor_name[MAXSTR];
    qsnprintf(dtor_name, sizeof(dtor_name), "%s.dtor", S_PY_IDC_OPAQUE_T);

    // register the dtor function
    if ( !set_idc_func_ex(dtor_name, py_idc_opaque_dtor, py_idc_cvt_helper_dtor_args, 0) )
      return false;

    // Link the dtor function to the class
    set_idc_dtor(idc_cvt_opaque, dtor_name);
  }

  pywraps_initialized = true;
  return true;
}

//------------------------------------------------------------------------
// This function must be called on de-initialization
void deinit_pywraps()
{
  if ( !pywraps_initialized )
    return;

  pywraps_initialized = false;
  Py_XDECREF(py_cvt_helper_module);
  py_cvt_helper_module = NULL;
}

//------------------------------------------------------------------------
// Utility function to create a class instance whose constructor takes zero arguments
PyObject *create_idaapi_class_instance0(const char *clsname)
{
  PyObject *py_cls = get_idaapi_attr(clsname);
  if ( py_cls == NULL )
    return NULL;

  PYW_GIL_ENSURE;
  PyObject *py_obj = PyObject_CallFunctionObjArgs(py_cls, NULL);
  PYW_GIL_RELEASE;

  Py_DECREF(py_cls);
  if ( PyW_GetError() || py_obj == NULL )
  {
    Py_XDECREF(py_obj);
    Py_RETURN_NONE;
  }
  return py_obj;
}

//------------------------------------------------------------------------
// Utility function to create linked class instances
PyObject *create_idaapi_linked_class_instance(
    const char *clsname, 
    void *lnk)
{
  PyObject *py_cls = get_idaapi_attr(clsname);
  if ( py_cls == NULL )
    return NULL;

  PyObject *py_lnk = PyCObject_FromVoidPtr(lnk, NULL);
  PYW_GIL_ENSURE;
  PyObject *py_obj = PyObject_CallFunctionObjArgs(py_cls, py_lnk, NULL);
  PYW_GIL_RELEASE;
  Py_DECREF(py_cls);
  Py_DECREF(py_lnk);

  if ( PyW_GetError() || py_obj == NULL )
  {
    Py_XDECREF(py_obj);
    py_obj = NULL;
  }
  return py_obj;
}

//------------------------------------------------------------------------
// Gets a class type reference in idaapi
// With the class type reference we can create a new instance of that type
// This function takes a reference to the idaapi module and keeps the reference
static PyObject *get_idaapi_attr(const int class_id)
{
  if ( class_id >= PY_CLSID_LAST )
    return NULL;

  // Some class names. The array is parallel with the PY_CLSID_xxx consts
  static const char *class_names[]=
  {
    "PyIdc_cvt_int64__",
    "object_t",
    "PyIdc_cvt_refclass__"
  };
  return PyObject_GetAttrString(py_cvt_helper_module, class_names[class_id]);
}

//------------------------------------------------------------------------
// Gets a class reference by name
PyObject *get_idaapi_attr(const char *attrname)
{
  return PyW_TryGetAttrString(py_cvt_helper_module, attrname);
}

//------------------------------------------------------------------------
// Returns a qstring from an object attribute
bool PyW_GetStringAttr(
    PyObject *py_obj, 
    const char *attr_name, 
    qstring *str)
{
  PyObject *py_attr = PyW_TryGetAttrString(py_obj, attr_name);
  if ( py_attr == NULL )
    return false;

  bool ok = PyString_Check(py_attr) != 0;
  if ( ok )
    *str = PyString_AsString(py_attr);

  Py_DECREF(py_attr);
  return ok;
}

//------------------------------------------------------------------------
// Returns an attribute or NULL
// No errors will be set if the attribute did not exist
PyObject *PyW_TryGetAttrString(PyObject *py_obj, const char *attr)
{
  if ( !PyObject_HasAttrString(py_obj, attr) )
    return NULL;
  else
    return PyObject_GetAttrString(py_obj, attr);
}

//------------------------------------------------------------------------
// Tries to import a module and clears the exception on failure
PyObject *PyW_TryImportModule(const char *name)
{
  PYW_GIL_ENSURE;
  PyObject *result = PyImport_ImportModule(name);
  PYW_GIL_RELEASE;
  if ( result != NULL )
    return result;
  if ( PyErr_Occurred() )
    PyErr_Clear();
  return NULL;
}

//-------------------------------------------------------------------------
// Converts a Python number into an IDC value (32 or 64bits)
// The function will first try to convert the number into a 32bit value
// If the number does not fit then VT_INT64 will be used
// NB: This function cannot properly detect if the Python value should be
// converted to a VT_INT64 or not. For example: 2**32-1 = 0xffffffff which
// can fit in a C long but Python creates a PyLong object for it.
// And because of that we are confused as to whether to convert to 32 or 64
bool PyW_GetNumberAsIDC(PyObject *py_var, idc_value_t *idc_var)
{
  if ( !(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)) )
    return false;

  // Can we convert to C long?
  long l = PyInt_AsLong(py_var);
  if ( !PyErr_Occurred() )
  {
    idc_var->set_long(l);
    return true;
  }
  // Clear last error
  PyErr_Clear();
  // Can be fit into a C unsigned long?
  l = (long) PyLong_AsUnsignedLong(py_var);
  if ( !PyErr_Occurred() )
  {
    idc_var->set_long(l);
    return true;
  }
  PyErr_Clear();
  idc_var->set_int64(PyLong_AsLongLong(py_var));
  return true;
}

//-------------------------------------------------------------------------
// Parses a Python object as a long or long long
bool PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64)
{
  if ( !(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)) )
    return false;

  // Can we convert to C long?
  long l = PyInt_AsLong(py_var);
  if ( !PyErr_Occurred() )
  {
    if ( num != NULL )
      *num = uint64(l);
    if ( is_64 != NULL )
      *is_64 = false;
    return true;
  }

  // Clear last error
  PyErr_Clear();

  // Can be fit into a C unsigned long?
  unsigned long ul = PyLong_AsUnsignedLong(py_var);
  if ( !PyErr_Occurred() )
  {
    if ( num != NULL )
      *num = uint64(ul);
    if ( is_64 != NULL )
      *is_64 = false;
    return true;
  }
  PyErr_Clear();

  // Try to parse as int64
  PY_LONG_LONG ll = PyLong_AsLongLong(py_var);
  if ( !PyErr_Occurred() )
  {
    if ( num != NULL )
      *num = uint64(ll);
    if ( is_64 != NULL )
      *is_64 = true;
    return true;
  }
  PyErr_Clear();

  // Try to parse as uint64
  unsigned PY_LONG_LONG ull = PyLong_AsUnsignedLongLong(py_var);
  PyObject *err = PyErr_Occurred();
  if ( err == NULL )
  {
    if ( num != NULL )
      *num = uint64(ull);
    if ( is_64 != NULL )
      *is_64 = true;
    return true;
  }
  // Negative number? _And_ it with uint64(-1)
  bool ok = false;
  if ( err == PyExc_TypeError )
  {
    PyObject *py_mask = Py_BuildValue("K", 0xFFFFFFFFFFFFFFFFull);
    PyObject *py_num = PyNumber_And(py_var, py_mask);
    if ( py_num != NULL && py_mask != NULL )
    {
      PyErr_Clear();
      ull = PyLong_AsUnsignedLongLong(py_num);
      if ( !PyErr_Occurred() )
      {
        if ( num != NULL )
          *num = uint64(ull);
        if ( is_64 != NULL )
          *is_64 = true;
        ok = true;
      }
    }
    Py_XDECREF(py_num);
    Py_XDECREF(py_mask);
  }
  PyErr_Clear();
  return ok;
}

//-------------------------------------------------------------------------
// Checks if a given object is of sequence type
bool PyW_IsSequenceType(PyObject *obj)
{
  if ( !PySequence_Check(obj) )
    return false;

  Py_ssize_t sz = PySequence_Size(obj);
  if ( sz == -1 || PyErr_Occurred() != NULL )
  {
    PyErr_Clear();
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
// Returns the string representation of an object
bool PyW_ObjectToString(PyObject *obj, qstring *out)
{
  PyObject *py_str = PyObject_Str(obj);
  if ( py_str != NULL )
  {
    *out = PyString_AsString(py_str);
    Py_DECREF(py_str);
    return true;
  }
  else
  {
    out->qclear();
    return false;
  }
}

//--------------------------------------------------------------------------
// Checks if a Python error occured and fills the out parameter with the
// exception string
bool PyW_GetError(qstring *out)
{
  if ( PyErr_Occurred() == NULL )
    return false;

  // Error occurred but details not needed?
  if ( out == NULL )
  {
    // Just clear the error
    PyErr_Clear();
  }
  else
  {
    PyObject *err_type, *err_value, *err_traceback;
    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    PyW_ObjectToString(err_value, out);
  }
  return true;
}

//-------------------------------------------------------------------------
// A loud version of PyGetError() which gets the error and displays it
// This method is used to display errors that occurred in a callback
bool PyW_ShowCbErr(const char *cb_name)
{
  static qstring err_str;
  if ( !PyW_GetError(&err_str) )
    return false;

  warning("IDAPython: Error while calling Python callback <%s>:\n%s", cb_name, err_str.c_str());
  return true;
}

//-------------------------------------------------------------------------
// Checks if the given py_var is a special PyIdc_cvt_helper object.
// It does that by examining the magic attribute and returns its numeric value.
// It returns -1 if the object is not a recognized helper object.
// Any Python object can be treated as an cvt object if this attribute is created.
static int get_pyidc_cvt_type(PyObject *py_var)
{
  // Check if this our special by reference object
  PyObject *attr = PyW_TryGetAttrString(py_var, S_PY_IDCCVT_ID_ATTR);
  if ( attr == NULL )
    return -1;
  
  if ( !(PyInt_Check(attr) || PyLong_Check(attr)) )
  {
    Py_DECREF(attr);
    return -1;
  }
  int r = (int)PyInt_AsLong(attr);
  Py_DECREF(attr);
  return r;
}

//-------------------------------------------------------------------------
// Utility function to create opaque / convertible Python <-> IDC variables
// The referred Python variable will have its reference increased
static bool create_py_idc_opaque_obj(PyObject *py_var, idc_value_t *idc_var)
{
  // Create an IDC object of this special helper class
  if ( VarObject(idc_var, get_py_idc_cvt_opaque()) != eOk )
    return false;

  // Store the CVT id
  idc_value_t idc_val;
  idc_val.set_long(PY_ICID_OPAQUE);
  VarSetAttr(idc_var, S_PY_IDCCVT_ID_ATTR, &idc_val);

  // Store the value as a PVOID referencing the given Python object
  idc_val.set_pvoid(py_var);
  VarSetAttr(idc_var, S_PY_IDCCVT_VALUE_ATTR, &idc_val);

  return true;
}

//-------------------------------------------------------------------------
// Converts a Python variable into an IDC variable
// This function returns on one CIP_XXXX
int pyvar_to_idcvar(
  PyObject *py_var,
  idc_value_t *idc_var,
  int *gvar_sn)
{
  PyObject *attr;
  // None / NULL
  if ( py_var == NULL || py_var == Py_None )
    idc_var->set_long(0);
  // Numbers?
  else if ( PyW_GetNumberAsIDC(py_var, idc_var) )
    return CIP_OK;
  // String
  else if ( PyString_Check(py_var) )
    idc_var->_set_string(PyString_AsString(py_var), PyString_Size(py_var));
  // Float
  else if ( PyBool_Check(py_var) )
    idc_var->set_long(py_var == Py_True ? 1 : 0);
  // Boolean
  else if ( PyFloat_Check(py_var) )
  {
    double dresult = PyFloat_AsDouble(py_var);
    ieee_realcvt((void *)&dresult, idc_var->e, 3);
    idc_var->vtype = VT_FLOAT;
  }
  // void*
  else if ( PyCObject_Check(py_var) )
    idc_var->set_pvoid(PyCObject_AsVoidPtr(py_var));
  // Is it a Python list?
  else if ( PyList_CheckExact(py_var) || PyW_IsSequenceType(py_var) )
  {
    // Create the object
    VarObject(idc_var);

    // Determine list size and type
    bool is_seq = !PyList_CheckExact(py_var);
    Py_ssize_t size = is_seq ? PySequence_Size(py_var) : PyList_Size(py_var);
    bool ok = true;
    qstring attr_name;

    // Convert each item
    for ( Py_ssize_t i=0; i<size; i++ )
    {
      // Get the item
      PyObject *py_item = is_seq ? PySequence_GetItem(py_var, i) : PyList_GetItem(py_var, i);

      // Convert the item into an IDC variable
      idc_value_t v;
      ok = pyvar_to_idcvar(py_item, &v, gvar_sn) >= CIP_OK;
      if ( ok )
      {
        // Form the attribute name
        PyObject *py_int = PyInt_FromSsize_t(i);
        ok = PyW_ObjectToString(py_int, &attr_name);
        if ( !ok )
          break;
        Py_DECREF(py_int);
        // Store the attribute
        VarSetAttr(idc_var, attr_name.c_str(), &v);
      }
      // Sequences return a new reference for GetItem()
      if ( is_seq )
        Py_DECREF(py_var);
      if ( !ok )
        break;
    }
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Dictionary: we convert to an IDC object
  else if ( PyDict_Check(py_var) )
  {
    // Create an empty IDC object
    VarObject(idc_var);

    // Get the dict.items() list
    PyObject *py_items = PyDict_Items(py_var);

    // Get the size of the list
    qstring key_name;
    bool ok = true;
    Py_ssize_t size = PySequence_Size(py_items);
    for ( Py_ssize_t i=0; i<size; i++ )
    {
      // Get item[i] -> (key, value)
      PyObject *py_item = PyList_GetItem(py_items, i);

      // Extract key/value
      PyObject *key  = PySequence_GetItem(py_item, 0);
      PyObject *val  = PySequence_GetItem(py_item, 1);

      // Get key's string representation
      PyW_ObjectToString(key, &key_name);

      // Convert the attribute into an IDC value
      idc_value_t v;
      ok = pyvar_to_idcvar(val, &v, gvar_sn) >= CIP_OK;
      if ( ok )
      {
        // Store the attribute
        VarSetAttr(idc_var, key_name.c_str(), &v);
      }
      Py_XDECREF(key);
      Py_XDECREF(val);
      if ( !ok )
        break;
    }
    // Decrement attribute reference
    Py_DECREF(py_items);
    return ok ? CIP_OK : CIP_FAILED;
  }
  // Possible function?
  else if ( PyCallable_Check(py_var) )
  {
    idc_var->clear();
    idc_var->vtype = VT_FUNC;
    idc_var->funcidx = -1; // Does not apply
    return CIP_OK;
  }
  // Objects:
  // - pyidc_cvt objects: int64, byref, opaque
  // - other python objects
  else
  {
    // Get the type
    int cvt_id = get_pyidc_cvt_type(py_var);
    switch ( cvt_id )
    {
    //
    // INT64
    //
    case PY_ICID_INT64:
      // Get the value attribute
      attr = PyW_TryGetAttrString(py_var, S_PY_IDCCVT_VALUE_ATTR);
      if ( attr == NULL )
        return false;
      idc_var->set_int64(PyLong_AsLongLong(attr));
      Py_DECREF(attr);
      return CIP_OK;
    //
    // BYREF
    //
    case PY_ICID_BYREF:
      {
        // BYREF always require this parameter
        if ( gvar_sn == NULL )
          return CIP_FAILED;

        // Get the value attribute
        attr = PyW_TryGetAttrString(py_var, S_PY_IDCCVT_VALUE_ATTR);
        if ( attr == NULL )
          return CIP_FAILED;

        // Create a global variable
        char buf[MAXSTR];
        qsnprintf(buf, sizeof(buf), S_PY_IDC_GLOBAL_VAR_FMT, *gvar_sn);
        idc_value_t *gvar = add_idc_gvar(buf);
        // Convert the python value into the IDC global variable
        bool ok = pyvar_to_idcvar(attr, gvar, gvar_sn) >= CIP_OK;
        if ( ok )
        {
          (*gvar_sn)++;
          // Create a reference to this global variable
          VarRef(idc_var, gvar);
        }
        Py_DECREF(attr);
        return ok ? CIP_OK : CIP_FAILED;
      }
    //
    // OPAQUE
    //
    case PY_ICID_OPAQUE:
      {
        if ( !create_py_idc_opaque_obj(py_var, idc_var) )
          return CIP_FAILED;
        return CIP_OK_NODECREF;
      }
    //
    // Other objects
    //
    default:
      // A normal object?
      PyObject *py_dir = PyObject_Dir(py_var);
      Py_ssize_t size  = PyList_Size(py_dir);
      if ( py_dir == NULL || !PyList_Check(py_dir) || size == 0 )
      {
        Py_XDECREF(py_dir);
        return CIP_FAILED;
      }
      // Create the IDC object
      VarObject(idc_var);
      for ( Py_ssize_t i=0; i<size; i++ )
      {
        PyObject *item = PyList_GetItem(py_dir, i);
        const char *field_name = PyString_AsString(item);
        if ( field_name == NULL )
          continue;

        size_t len = strlen(field_name);
        
        // Skip private attributes
        if ( (len > 2 )
          && (strncmp(field_name, "__", 2) == 0 )
          && (strncmp(field_name+len-2, "__", 2) == 0) )
        {
          continue;
        }

        idc_value_t v;
        // Get the non-private attribute from the object
        attr = PyObject_GetAttrString(py_var, field_name);
        if (attr == NULL
          // Convert the attribute into an IDC value
          || pyvar_to_idcvar(attr, &v, gvar_sn) < CIP_OK)
        {
          Py_XDECREF(attr);
          return CIP_FAILED;
        }

        // Store the attribute
        VarSetAttr(idc_var, field_name, &v);

        // Decrement attribute reference
        Py_DECREF(attr);
      }
    }
  }
  return CIP_OK;
}

//-------------------------------------------------------------------------
// Converts an IDC variable to a Python variable
// If py_var points to an existing object then the object will be updated
// If py_var points to an existing immutable object then ZERO is returned
// Returns one of CIP_xxxx. Check pywraps.hpp
int idcvar_to_pyvar(
  const idc_value_t &idc_var,
  PyObject **py_var)
{
  switch ( idc_var.vtype )
  {
  case VT_PVOID:
    if ( *py_var == NULL )
      *py_var = PyCObject_FromVoidPtr(idc_var.pvoid, NULL);
    else
      return CIP_IMMUTABLE;
    break;

  case VT_INT64:
    {
      // Recycle?
      if ( *py_var != NULL )
      {
        // Recycling an int64 object?
        int t = get_pyidc_cvt_type(*py_var);
        if ( t != PY_ICID_INT64 )
          return CIP_IMMUTABLE; // Cannot recycle immutable object
        // Update the attribute
        PyObject_SetAttrString(*py_var, S_PY_IDCCVT_VALUE_ATTR, PyLong_FromLongLong(idc_var.i64));
        return CIP_OK;
      }
      PyObject *py_cls = get_idaapi_attr(PY_CLSID_CVT_INT64);
      if ( py_cls == NULL )
        return CIP_FAILED;
      *py_var = PyObject_CallFunctionObjArgs(py_cls, PyLong_FromLongLong(idc_var.i64), NULL);
      Py_DECREF(py_cls);
      if ( PyW_GetError() || *py_var == NULL )
        return CIP_FAILED;
      break;
    }

#if !defined(NO_OBSOLETE_FUNCS) || defined(__EXPR_SRC)
  case VT_STR:
    *py_var = PyString_FromString(idc_var.str);
    break;

#endif
  case VT_STR2:
    if ( *py_var == NULL )
    {
      const qstring &s = idc_var.qstr();
      *py_var = PyString_FromStringAndSize(s.begin(), s.length());
      break;
    }
    else
      return CIP_IMMUTABLE; // Cannot recycle immutable object
  case VT_LONG:
    // Cannot recycle immutable objects
    if ( *py_var != NULL )
      return CIP_IMMUTABLE;
#ifdef __EA64__
    *py_var = PyLong_FromLongLong(idc_var.num);
#else
    *py_var = PyLong_FromLong(idc_var.num);
#endif
    break;
  case VT_FLOAT:
    if ( *py_var == NULL )
    {
      double x;
      if ( ph.realcvt(&x, (uint16 *)idc_var.e, (sizeof(x)/2-1)|010) != 0 )
        INTERR(30160);

      *py_var = PyFloat_FromDouble(x);
      break;
    }
    else
      return CIP_IMMUTABLE;
  
  case VT_REF:
    {
      if ( *py_var == NULL )
      {
        PyObject *py_cls = get_idaapi_attr(PY_CLSID_CVT_BYREF);
        if ( py_cls == NULL )
          return CIP_FAILED;
  
        // Create a byref object with None value. We populate it later
        *py_var = PyObject_CallFunctionObjArgs(py_cls, Py_None, NULL);
        Py_DECREF(py_cls);
        if ( PyW_GetError() || *py_var == NULL )
          return CIP_FAILED;
      }
      int t = *py_var == NULL ? -1 : get_pyidc_cvt_type(*py_var);
      if ( t != PY_ICID_BYREF )
        return CIP_FAILED;

      // Dereference
      // (Since we are not using VREF_COPY flag, we can safely const_cast)
      idc_value_t *dref_v = VarDeref(const_cast<idc_value_t *>(&idc_var), VREF_LOOP);
      if ( dref_v == NULL )
        return CIP_FAILED;

      // Can we recycle the object?
      PyObject *new_py_val = PyW_TryGetAttrString(*py_var, S_PY_IDCCVT_VALUE_ATTR);
      if ( new_py_val != NULL )
      {
        // Recycle
        t = idcvar_to_pyvar(*dref_v, &new_py_val);
        Py_XDECREF(new_py_val); // DECREF because of GetAttrStr

        // Success? Nothing more to be done
        if ( t == CIP_OK )
          return CIP_OK;

        // Clear it so we don't recycle it
        new_py_val = NULL;
      }
      // Try to convert (not recycle)
      if ( idcvar_to_pyvar(*dref_v, &new_py_val) != CIP_OK )
        return CIP_FAILED;

      // Update the attribute
      PyObject_SetAttrString(*py_var, S_PY_IDCCVT_VALUE_ATTR, new_py_val);
      Py_DECREF(new_py_val);
      break;
    }

    // Can convert back into a Python object or Python dictionary
    // (Depending if py_var will be recycled and it was a dictionary)
  case VT_OBJ:
    {
      // Check if this IDC object has __cvt_id__ and the __idc_cvt_value__ fields
      idc_value_t idc_val;
      if (    VarGetAttr(&idc_var, S_PY_IDCCVT_ID_ATTR, &idc_val) == eOk
           && VarGetAttr(&idc_var, S_PY_IDCCVT_VALUE_ATTR, &idc_val) == eOk )
      {
        // Extract the object
        *py_var = (PyObject *) idc_val.pvoid;
        return CIP_OK_NODECREF;
      }
      PyObject *obj;
      bool is_dict = false;
      
      // Need to create a new object?
      if ( *py_var == NULL )
      {
        // Get skeleton class reference
        PyObject *py_cls = get_idaapi_attr(PY_CLSID_APPCALL_SKEL_OBJ);
        if ( py_cls == NULL )
          return CIP_FAILED;

        // Call constructor
        obj = PyObject_CallFunctionObjArgs(py_cls, NULL);
        Py_DECREF(py_cls);
        if ( PyW_GetError() || obj == NULL )
          return CIP_FAILED;
      }
      else
      {
        // Recycle existing variable
        obj = *py_var;
        if ( PyDict_Check(obj) )
          is_dict = true;
      }

      // Walk the IDC attributes and store into python
      for (const char *attr_name = VarFirstAttr(&idc_var);
           attr_name != NULL;
           attr_name = VarNextAttr(&idc_var, attr_name) )
      {
        // Get the attribute
        idc_value_t v;
        VarGetAttr(&idc_var, attr_name, &v, true);
        
        // Convert attribute to a python value (recursively)
        PyObject *py_attr(NULL);
        int cvt = idcvar_to_pyvar(v, &py_attr);
        if ( cvt <= CIP_IMMUTABLE )
        {
          // Delete the object (if we created it)
          if ( *py_var == NULL )
            Py_DECREF(obj);

          return CIP_FAILED;
        }
        if ( is_dict )
          PyDict_SetItemString(obj, attr_name, py_attr);
        else
          PyObject_SetAttrString(obj, attr_name, py_attr);
        
        if ( cvt == CIP_OK )
          Py_XDECREF(py_attr);
      }
      *py_var = obj;
      break;
    }
    // Unhandled type
  default:
    *py_var = NULL;
    return CIP_FAILED;
  }
  return CIP_OK;
}



//------------------------------------------------------------------------

//------------------------------------------------------------------------
class pywraps_notify_when_t
{
  ppyobject_vec_t table[NW_EVENTSCNT];
  qstring err;
  bool in_notify;
  struct notify_when_args_t
  {
    int when;
    PyObject *py_callable;
  };
  typedef qvector<notify_when_args_t> notify_when_args_vec_t;
  notify_when_args_vec_t delayed_notify_when_list;

  //------------------------------------------------------------------------
  static int idaapi idp_callback(void *ud, int event_id, va_list va)
  {
    pywraps_notify_when_t *_this = (pywraps_notify_when_t *)ud;
    switch ( event_id )
    {
    case processor_t::newfile:
    case processor_t::oldfile:
      {
        int old = event_id == processor_t::oldfile ? 1 : 0;
        char *dbname = va_arg(va, char *);
        _this->notify(NW_OPENIDB_SLOT, old);
      }
      break;
    case processor_t::closebase:
      _this->notify(NW_CLOSEIDB_SLOT);
      break;
    }
    // event not processed, let other plugins or the processor module handle it
    return 0;
  }

  //------------------------------------------------------------------------
  bool unnotify_when(int when, PyObject *py_callable)
  {
    int cnt = 0;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
    {
      // convert index to flag and see
      if ( ((1 << slot) & when) != 0 )
      {
        unregister_callback(slot, py_callable);
        ++cnt;
      }
    }
    return cnt > 0;
  }

  //------------------------------------------------------------------------
  void register_callback(int slot, PyObject *py_callable)
  {
    ppyobject_vec_t &tbl = table[slot];
    ppyobject_vec_t::iterator it_end = tbl.end(), it = std::find(tbl.begin(), it_end, py_callable);

    // Already added
    if ( it != it_end )
      return;

    // Increment reference
    Py_INCREF(py_callable);

    // Insert the element
    tbl.push_back(py_callable);
  }

  //------------------------------------------------------------------------
  void unregister_callback(int slot, PyObject *py_callable)
  {
    ppyobject_vec_t &tbl = table[slot];
    ppyobject_vec_t::iterator it_end = tbl.end(), it = std::find(tbl.begin(), it_end, py_callable);
    // Not found?
    if ( it == it_end )
      return;

    // Decrement reference
    Py_DECREF(py_callable);

    // Delete the element
    tbl.erase(it);
  }

public:
  //------------------------------------------------------------------------
  bool init()
  {
    return hook_to_notification_point(HT_IDP, idp_callback, this);
  }

  //------------------------------------------------------------------------
  bool deinit()
  {
    // Uninstall all objects
    ppyobject_vec_t::iterator it, it_end;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
    {
      for ( it = table[slot].begin(), it_end = table[slot].end(); it!=it_end; ++it )
        unregister_callback(slot, *it);
    }
    // ...and remove the notification
    return unhook_from_notification_point(HT_IDP, idp_callback, this);
  }

  //------------------------------------------------------------------------
  bool notify_when(int when, PyObject *py_callable)
  {
    // While in notify() do not allow insertion or deletion to happen on the spot
    // Instead we will queue them so that notify() will carry the action when it finishes
    // dispatching the notification handlers
    if ( in_notify )
    {
      notify_when_args_t &args = delayed_notify_when_list.push_back();
      args.when = when;
      args.py_callable = py_callable;
      return true;
    }
    // Uninstalling the notification?
    if ( (when & NW_REMOVE) != 0 )
      return unnotify_when(when & ~NW_REMOVE, py_callable);

    int cnt = 0;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
    {
      // is this flag set?
      if ( ((1 << slot) & when) != 0 )
      {
        register_callback(slot, py_callable);
        ++cnt;
      }
    }
    return cnt > 0;
  }

  //------------------------------------------------------------------------
  bool notify(int slot, ...)
  {
    va_list va;
    va_start(va, slot);
    bool ok = notify_va(slot, va);
    va_end(va);
    return ok;
  }

  //------------------------------------------------------------------------
  bool notify_va(int slot, va_list va)
  {
    // Sanity bounds check!
    if ( slot < 0 || slot >= NW_EVENTSCNT )
      return false;

    bool ok = true;
    in_notify = true;
    int old = slot == NW_OPENIDB_SLOT ? va_arg(va, int) : 0;
    for (ppyobject_vec_t::iterator it = table[slot].begin(), it_end = table[slot].end();
      it != it_end;
      ++it)
    {
      // Form the notification code
      PyObject *py_code = PyInt_FromLong(1 << slot);
      PyObject *py_result(NULL);
      switch ( slot )
      {
      case NW_CLOSEIDB_SLOT:
      case NW_INITIDA_SLOT:
      case NW_TERMIDA_SLOT:
        {
          PYW_GIL_ENSURE;
          py_result = PyObject_CallFunctionObjArgs(*it, py_code, NULL);
          PYW_GIL_RELEASE;
          break;
        }
      case NW_OPENIDB_SLOT:
        {
          PyObject *py_old = PyInt_FromLong(old);
          PYW_GIL_ENSURE;
          py_result = PyObject_CallFunctionObjArgs(*it, py_code, py_old, NULL);
          PYW_GIL_RELEASE;
          Py_DECREF(py_old);
        }
        break;
      }
      Py_DECREF(py_code);
      if ( PyW_GetError(&err) || py_result == NULL )
      {
        PyErr_Clear();
        warning("notify_when(): Error occured while notifying object.\n%s", err.c_str());
        ok = false;
      }
      Py_XDECREF(py_result);
    }
    in_notify = false;

    // Process any delayed notify_when() calls that
    if ( !delayed_notify_when_list.empty() )
    {
      for (notify_when_args_vec_t::iterator it = delayed_notify_when_list.begin(), it_end=delayed_notify_when_list.end();
           it != it_end;
           ++it)
      {
        notify_when(it->when, it->py_callable);
      }
      delayed_notify_when_list.qclear();
    }
    return ok;
  }

  //------------------------------------------------------------------------
  pywraps_notify_when_t()
  {
    in_notify = false;
  }
};

static pywraps_notify_when_t *g_nw = NULL;

//------------------------------------------------------------------------
// Initializes the notify_when mechanism
// (Normally called by IDAPython plugin.init())
bool pywraps_nw_init()
{
  if ( g_nw != NULL )
    return true;

  g_nw = new pywraps_notify_when_t();
  if ( g_nw->init() )
    return true;

  // Things went bad, undo!
  delete g_nw;
  g_nw = NULL;
  return false;
}

//------------------------------------------------------------------------
bool pywraps_nw_notify(int slot, ...)
{
  if ( g_nw == NULL )
    return false;

  va_list va;
  va_start(va, slot);
  bool ok = g_nw->notify_va(slot, va);
  va_end(va);

  return ok;
}

//------------------------------------------------------------------------
// Deinitializes the notify_when mechanism
bool pywraps_nw_term()
{
  if ( g_nw == NULL )
    return true;
  
  // If could not deinitialize then return w/o stopping nw
  if ( !g_nw->deinit() )
    return false;
  
  // Cleanup
  delete g_nw;
  g_nw = NULL;
  return true;
}

//</code(py_idaapi)>
%}

// Do not create separate wrappers for default arguments
%feature("compactdefaultargs");

#ifdef __EA64__
#ifdef __GNUC__
%constant ea_t BADADDR = 0xFFFFFFFFFFFFFFFFll;
%constant sel_t BADSEL = 0xFFFFFFFFFFFFFFFFll;
%constant nodeidx_t BADNODE = 0xFFFFFFFFFFFFFFFFll;
#else  // __GNUC__
%constant ea_t BADADDR = 0xFFFFFFFFFFFFFFFFui64;
%constant sel_t BADSEL = 0xFFFFFFFFFFFFFFFFui64;
%constant nodeidx_t BADNODE = 0xFFFFFFFFFFFFFFFFui64;
#endif // __GNUC__
#else  //__EA64__
%constant ea_t BADADDR = 0xFFFFFFFFL;
%constant sel_t BADSEL = 0xFFFFFFFFL;
%constant nodeidx_t BADNODE = 0xFFFFFFFFL;
#endif

// Help SWIG to figure out the ulonglong type
#ifdef SWIGWIN
typedef unsigned __int64 ulonglong;
typedef          __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef          long long longlong;
#endif

typedef int error_t;

%include "typemaps.i"

%include "cstring.i"
%include "carrays.i"
%include "cpointer.i"

%include "typeconv.i"

%pythoncode %{
#<pycode(py_idaapi)>

import struct
import traceback
import os
import sys
import __builtin__

# -----------------------------------------------------------------------

# Seek constants
SEEK_SET = 0 # from the file start
SEEK_CUR = 1 # from the current position
SEEK_END = 2 # from the file end

# Plugin constants
PLUGIN_MOD  = 0x0001
PLUGIN_DRAW = 0x0002
PLUGIN_SEG  = 0x0004
PLUGIN_UNL  = 0x0008
PLUGIN_HIDE = 0x0010
PLUGIN_DBG  = 0x0020
PLUGIN_PROC = 0x0040
PLUGIN_FIX  = 0x0080
PLUGIN_SKIP = 0
PLUGIN_OK   = 1
PLUGIN_KEEP = 2

# PyIdc conversion object IDs
PY_ICID_INT64  = 0
"""int64 object"""
PY_ICID_BYREF  = 1
"""byref object"""
PY_ICID_OPAQUE = 2
"""opaque object"""

# -----------------------------------------------------------------------
class pyidc_opaque_object_t(object):
    """This is the base class for all Python<->IDC opaque objects"""
    __idc_cvt_id__ = PY_ICID_OPAQUE

# -----------------------------------------------------------------------
class py_clinked_object_t(pyidc_opaque_object_t):
    """This is a utility and base class for C linked objects"""
    def __init__(self, lnk = None):
        # static link: if a link was provided
        self.__static_clink__ = True if lnk else False

        # Create link if it was not provided
        self.__clink__ = lnk if lnk else self._create_clink()

    def __del__(self):
        """Delete the link upon object destruction (only if not static)"""
        if not self.__static_clink__:
            self._del_clink(self.__clink__)

    def _create_clink(self):
        """
        Overwrite me.
        Creates a new clink
        @return: PyCObject representing the C link
        """
        pass

    def _del_clink(self, lnk):
        """Overwrite me.
        This method deletes the link
        """
        pass

    def copy(self):
        """Returns a new copy of this class"""

        # Create an unlinked instance
        inst = self.__class__()

        # Assign self to the new instance
        inst.assign(self)

        return inst

    def assign(self, other):
        """
        Overwrite me.
        This method allows you to assign an instance contents to anothers
        @return: Boolean
        """
        pass

    clink = property(lambda self: self.__clink__)

# -----------------------------------------------------------------------
class object_t(object):
    """Helper class used to initialize empty objects"""
    def __init__(self, **kwds):
        self.__dict__ = kwds

    def __getitem__(self, idx):
        """Allow access to object attributes by index (like dictionaries)"""
        return getattr(self, idx)

# -----------------------------------------------------------------------
class plugin_t(pyidc_opaque_object_t):
    """Base class for all scripted plugins."""
    pass

# -----------------------------------------------------------------------
class pyidc_cvt_helper__(object):
    """
    This is a special helper object that helps detect which kind
    of object is this python object wrapping and how to convert it
    back and from IDC.
    This object is characterized by its special attribute and its value
    """
    def __init__(self, cvt_id, value):
        self.__idc_cvt_id__ = cvt_id
        self.value = value

    def __set_value(self, v):
        self.__idc_cvt_value__ = v
    def __get_value(self):
        return self.__idc_cvt_value__
    value = property(__get_value, __set_value)

# -----------------------------------------------------------------------
class PyIdc_cvt_int64__(pyidc_cvt_helper__):
    """Helper class for explicitly representing VT_INT64 values"""

    def __init__(self, v):
        # id = 0 = int64 object
        super(self.__class__, self).__init__(PY_ICID_INT64, v)

    # operation table
    __op_table = \
    {
        0: lambda a, b: a + b,
        1: lambda a, b: a - b,
        2: lambda a, b: a * b,
        3: lambda a, b: a / b
    }
    # carries the operation given its number
    def __op(self, op_n, other, rev=False):
        a = self.value
        # other operand of same type? then take its value field
        if type(other) == type(self):
            b = other.value
        else:
            b = other
        if rev:
            t = a
            a = b
            b = t
        # construct a new object and return as the result
        return self.__class__(self.__op_table[op_n](a, b))

    # overloaded operators
    def __add__(self, other):  return self.__op(0, other)
    def __sub__(self, other):  return self.__op(1, other)
    def __mul__(self, other):  return self.__op(2, other)
    def __div__(self, other):  return self.__op(3, other)
    def __radd__(self, other): return self.__op(0, other, True)
    def __rsub__(self, other): return self.__op(1, other, True)
    def __rmul__(self, other): return self.__op(2, other, True)
    def __rdiv__(self, other): return self.__op(3, other, True)

# -----------------------------------------------------------------------
class PyIdc_cvt_refclass__(pyidc_cvt_helper__):
    """Helper class for representing references to immutable objects"""
    def __init__(self, v):
        # id = one = byref object
        super(self.__class__, self).__init__(PY_ICID_BYREF, v)

    def cstr(self):
        """Returns the string as a C string (up to the zero termination)"""
        return as_cstr(self.value)

# -----------------------------------------------------------------------
def as_cstr(val):
    """
    Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref())
    It scans for the first \x00 and returns the string value up to that point.
    """
    if isinstance(val, PyIdc_cvt_refclass__):
        val = val.value

    n = val.find('\x00')
    return val if n == -1 else val[:n]

# -----------------------------------------------------------------------
def as_unicode(s):
    """Convenience function to convert a string into appropriate unicode format"""
    # use UTF16 big/little endian, depending on the environment?
    return unicode(s).encode("UTF-16" + ("BE" if _idaapi.cvar.inf.mf else "LE"))

# -----------------------------------------------------------------------
def as_uint32(v):
    """Returns a number as an unsigned int32 number"""
    return v & 0xffffffff

# -----------------------------------------------------------------------
def as_int32(v):
    """Returns a number as a signed int32 number"""
    return -((~v & 0xffffffff)+1)

# -----------------------------------------------------------------------
def as_signed(v, nbits = 32):
    """
    Returns a number as signed. The number of bits are specified by the user.
    The MSB holds the sign.
    """
    return -(( ~v & ((1 << nbits)-1) ) + 1) if v & (1 << nbits-1) else v

# ----------------------------------------------------------------------
def copy_bits(v, s, e=-1):
    """
    Copy bits from a value
    @param v: the value
    @param s: starting bit (0-based)
    @param e: ending bit
    """
    # end-bit not specified? use start bit (thus extract one bit)
    if e == -1:
        e = s
    # swap start and end if start > end
    if s > e:
        e, s = s, e

    mask = ~(((1 << (e-s+1))-1) << s)

    return (v & mask) >> s

# ----------------------------------------------------------------------
__struct_unpack_table = {
  1: ('b', 'B'),
  2: ('h', 'H'),
  4: ('l', 'L'),
  8: ('q', 'Q')
}

# ----------------------------------------------------------------------
def struct_unpack(buffer, signed = False, offs = 0):
    """
    Unpack a buffer given its length and offset using struct.unpack_from().
    This function will know how to unpack the given buffer by using the lookup table '__struct_unpack_table'
    If the buffer is of unknown length then None is returned. Otherwise the unpacked value is returned.
    """
    # Supported length?
    n = len(buffer)
    if n not in __struct_unpack_table:
        return None
    # Conver to number
    signed = 1 if signed else 0

    # Unpack
    return struct.unpack_from(__struct_unpack_table[n][signed], buffer, offs)[0]


# ------------------------------------------------------------
def IDAPython_ExecSystem(cmd):
    """
    Executes a command with popen().
    """
    try:
        f = os.popen(cmd, "r")
        s = ''.join(f.readlines())
        f.close()
        return s
    except Exception, e:
        return str(e)


# ------------------------------------------------------------
def IDAPython_ExecScript(script, g):
    """
    Run the specified script.
    It also addresses http://code.google.com/p/idapython/issues/detail?id=42

    This function is used by the low-level plugin code.
    """
    scriptpath = os.path.dirname(script)
    if len(scriptpath) and scriptpath not in sys.path:
        sys.path.append(scriptpath)

    # Save the argv, path, I/O and base modules for later cleanup
    argv = sys.argv
    path = sys.path
    stdio = [sys.stdin, sys.stdout, sys.stderr]
    basemodules = sys.modules.copy()
    sys.argv = [ script ]

    # Adjust the __file__ path in the globals we pass to the script
    old__file__ = g['__file__'] if '__file__' in g else ''
    g['__file__'] = script

    PY_COMPILE_ERR = None
    try:
        execfile(script, g)
    except Exception, e:
        PY_COMPILE_ERR = str(e) + "\n" + traceback.format_exc()
        print PY_COMPILE_ERR
    finally:
        # Restore the globals to the state before the script was run
        g['__file__'] = old__file__

        sys.argv = argv
        sys.path = path
        sys.stdin, sys.stdout, sys.stderr = stdio

        # Clean up the modules loaded by the script
        for module in sys.modules.keys():
            if not module in basemodules:
                del sys.modules[module]

    return PY_COMPILE_ERR

# ----------------------------------------------------------------------
class __IDAPython_Completion_Util(object):
    """Internal utility class for auto-completion support"""
    def __init__(self):
        self.n = 0
        self.completion = None
        self.lastmodule = None

    @staticmethod
    def parse_identifier(line, prefix, prefix_start):
        """Parse a line and extracts"""
        id_start = prefix_start
        while id_start > 0:
            ch = line[id_start]
            if not ch.isalpha() and ch != '.' and ch != '_':
                id_start += 1
                break
            id_start -= 1

        return line[id_start:prefix_start + len(prefix)]

    @staticmethod
    def dir_of(m, prefix):
        return [x for x in dir(m) if x.startswith(prefix)]

    @classmethod
    def get_completion(cls, id, prefix):
        try:
            m = sys.modules['__main__']

            parts = id.split('.')
            c = len(parts)

            for i in xrange(0, c-1):
                m = getattr(m, parts[i])
        except Exception, e:
            return (None, None)
        else:
            # search in the module
            completion = cls.dir_of(m, prefix)

            # no completion found? looking from the global scope? then try the builtins
            if not completion and c == 1:
                completion = cls.dir_of(__builtin__, prefix)

            return (m, completion) if completion else (None, None)

    def __call__(self, prefix, n, line, prefix_start):
        if n == 0:
            self.n = n
            id = self.parse_identifier(line, prefix, prefix_start)
            self.lastmodule, self.completion = self.get_completion(id, prefix)

        if self.completion is None or n >= len(self.completion):
            return None

        s = self.completion[n]
        try:
            attr = getattr(self.lastmodule, s)
            # Is it callable?
            if callable(attr):
                return s + ("" if line.startswith("?") else "(")
            # Is it iterable?
            elif isinstance(attr, basestring) or getattr(attr, '__iter__', False):
                return s + "["
        except:
            pass

        return s

# Instantiate a completion object
IDAPython_Completion = __IDAPython_Completion_Util()



# The general callback format of notify_when() is:
#    def notify_when_callback(nw_code)
# In the case of NW_OPENIDB, the callback is:
#    def notify_when_callback(nw_code, is_old_database)
NW_OPENIDB    = 0x0001
"""Notify when the database is opened. Its callback is of the form: def notify_when_callback(nw_code, is_old_database)"""
NW_CLOSEIDB   = 0x0002
"""Notify when the database is closed. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_INITIDA    = 0x0004
"""Notify when the IDA starts. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_TERMIDA    = 0x0008
"""Notify when the IDA terminates. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_REMOVE     = 0x0010
"""Use this flag with other flags to uninstall a notifywhen callback"""

#</pycode(py_idaapi)>
%}

%include "pro.i"

// Do not move this. We need to override the define from pro.h
#define CASSERT(type)

// Convert all of these
%cstring_output_maxstr_none(char *buf, size_t bufsize);
%binary_output_or_none(void *buf, size_t bufsize);
%binary_output_with_size(void *buf, size_t *bufsize);

// Accept single Python string for const void * + size input arguments
// For example: put_many_bytes() and patch_many_bytes()
%apply (char *STRING, int LENGTH) { (const void *buf, size_t size) };
%apply (char *STRING, int LENGTH) { (const void *buf, size_t len) };
%apply (char *STRING, int LENGTH) { (const void *value, size_t length) };
%apply (char *STRING, int LENGTH) { (const void *dataptr,size_t len) };

// Create wrapper classes for basic type arrays
%array_class(uchar, uchar_array);
%array_class(tid_t, tid_array);
%array_class(ea_t, ea_array);
%array_class(sel_t, sel_array);
%array_class(uval_t, uval_array);
%pointer_class(int, int_pointer);
%pointer_class(ea_t, ea_pointer);
%pointer_class(sval_t, sval_pointer);
%pointer_class(sel_t, sel_pointer);

%include "ida.i"
%include "idd.i"
%include "idp.i"
%include "netnode.i"
%include "nalt.i"

%include "allins.i"
%include "area.i"
%include "auto.i"
%include "bytes.i"
%include "dbg.i"
%include "diskio.i"
%include "entry.i"
%include "enum.i"
%include "expr.i"
%include "fixup.i"
%include "frame.i"
%include "funcs.i"

%inline %{

//<inline(py_idaapi)>
//------------------------------------------------------------------------
/*
#<pydoc>
def parse_command_line(cmdline):
    """
    Parses a space separated string (quotes and escape character are supported)
    @param cmdline: The command line to parse
    @return: A list of strings or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *py_parse_command_line(const char *cmdline)
{
  qstrvec_t args;
  if ( parse_command_line(cmdline, &args) == 0 )
    Py_RETURN_NONE;

  PyObject *py_list = PyList_New(args.size());
  for ( size_t i=0; i<args.size(); i++ )
    PyList_SetItem(py_list, i, PyString_FromString(args[i].c_str()));

  return py_list;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_inf_structure():
    """
    Returns the global variable 'inf' (an instance of idainfo structure, see ida.hpp)
    """
    pass
#</pydoc>
*/
idainfo *get_inf_structure(void)
{
  return &inf;
}

//-------------------------------------------------------------------------
// Declarations from Python.cpp
/*
#<pydoc>
def set_script_timeout(timeout):
    """
    Changes the script timeout value. 
    @param timeout: This value is in seconds.
                    If this value is set to zero then the script will never timeout.
    @return: returns the old timeout value
    """
    pass
#</pydoc>
*/
int set_script_timeout(int timeout);
/*
#<pydoc>
def enable_extlang_python(enable):
    """
    Enables or disables Python extlang.
    When enabled, all expressions will be evaluated by Python.
    @param enable: Set to True to enable, False otherwise
    """
    pass
#</pydoc>
*/
void enable_extlang_python(bool enable);
void enable_python_cli(bool enable);

/*
#<pydoc>
def RunPythonStatement(stmt):
    """
    This is an IDC function exported from the Python plugin.
    It is used to evaluate Python statements from IDC.
    @param stmt: The statement to evaluate
    @return: 0 - on success otherwise a string containing the error
    """
    pass
#</pydoc>
*/



//------------------------------------------------------------------------
/*
#<pydoc>
def notify_when(when, callback):
    """
    Register a callback that will be called when an event happens.
    @param when: one of NW_XXXX constants
    @param callback: This callback prototype varies depending on the 'when' parameter:
                     The general callback format:
                         def notify_when_callback(nw_code)
                     In the case of NW_OPENIDB:
                         def notify_when_callback(nw_code, is_old_database)
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool notify_when(int when, PyObject *py_callable)
{
  if ( g_nw == NULL || !PyCallable_Check(py_callable) )
    return false;
  return g_nw->notify_when(when, py_callable);
}

//</inline(py_idaapi)>
%}

%include "gdl.i"
%include "ints.i"
%include "kernwin.i"
%include "lines.i"
%include "loader.i"
%include "moves.i"
%include "name.i"
%include "offset.i"
%include "queue.i"
%include "search.i"
%include "segment.i"
%include "srarea.i"
%include "strlist.i"
%include "struct.i"
%include "typeinf.i"
%include "ua.i"
%include "xref.i"
%include "graph.i"
%include "fpro.i"
