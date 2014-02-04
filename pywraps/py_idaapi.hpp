#ifndef __PY_IDAAPI__
#define __PY_IDAAPI__

//<code(py_idaapi)>

//------------------------------------------------------------------------
// String constants used
static const char S_PYINVOKE0[]              = "_py_invoke0";
static const char S_PY_SWIEX_CLSNAME[]       = "switch_info_ex_t";
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
static const char S_ON_CREATING_GROUP[]      = "OnCreatingGroup";
static const char S_ON_DELETING_GROUP[]      = "OnDeletingGroup";
static const char S_ON_GROUP_VISIBILITY[]    = "OnGroupVisibility";
static const char S_M_EDGES[]                = "_edges";
static const char S_M_NODES[]                = "_nodes";
static const char S_M_THIS[]                 = "_this";
static const char S_M_TITLE[]                = "_title";
static const char S_CLINK_NAME[]             = "__clink__";
static const char S_ON_VIEW_ACTIVATED[]      = "OnViewActivated";
static const char S_ON_VIEW_DEACTIVATED[]    = "OnViewDeactivated";
static const char S_ON_VIEW_KEYDOWN[]        = "OnViewKeydown";
static const char S_ON_VIEW_CLICK[]          = "OnViewClick";
static const char S_ON_VIEW_DBLCLICK[]       = "OnViewDblclick";
static const char S_ON_VIEW_CURPOS[]         = "OnViewCurpos";
static const char S_ON_VIEW_SWITCHED[]       = "OnViewSwitched";
static const char S_ON_VIEW_MOUSE_OVER[]     = "OnViewMouseOver";


#ifdef __PYWRAPS__
static const char S_PY_IDAAPI_MODNAME[]      = "__main__";
#else
static const char S_PY_IDAAPI_MODNAME[]      = S_IDAAPI_MODNAME;
#endif

//------------------------------------------------------------------------
static ref_t py_cvt_helper_module;
static bool pywraps_initialized = false;

//---------------------------------------------------------------------------
// Context structure used by add|del_menu_item()
struct py_add_del_menu_item_ctx
{
  qstring menupath;
  PyObject *cb_data;
};

//---------------------------------------------------------------------------
// Context structure used by add|del_idc_hotkey()
struct py_idchotkey_ctx_t
{
  qstring hotkey;
  PyObject *pyfunc;
};

//---------------------------------------------------------------------------
// Context structure used by register/unregister timer
struct py_timer_ctx_t
{
  qtimer_t timer_id;
  PyObject *pycallback;
};

//------------------------------------------------------------------------
// check if we have a file which is known to be executed automatically
// by SWIG or Python runtime
bool pywraps_check_autoscripts(char *buf, size_t bufsize)
{
  static const char *const exts[] =
  {
    "py",
    "pyc",
    "pyd",
    "pyo",
    "pyw",
  };

  static const char *const fns[] =
  {
    "swig_runtime_data" SWIG_RUNTIME_VERSION,
    "sitecustomize",
    "usercustomize"
  };

  for ( size_t ifn=0; ifn < qnumber(fns); ++ifn )
  {
    // check for a script or module with several possible extensions
    for ( size_t iext=0; iext < qnumber(exts); ++iext )
    {
      qsnprintf(buf, bufsize, "%s.%s", fns[ifn], exts[iext]);
      if ( qfileexist(buf) )
        return true;
    }
    // check for a subdirectory under current directory
    if ( qfileexist(fns[ifn]) )
    {
      qstrncpy(buf, fns[ifn], bufsize);
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------
error_t PyW_CreateIdcException(idc_value_t *res, const char *msg)
{
  // Create exception object
  VarObject(res, find_idc_class("exception"));

  // Set the message field
  idc_value_t v;
  v.set_string(msg);
  VarSetAttr(res, "message", &v);

  // Throw exception
  return set_qerrno(eExecThrow);
}

//------------------------------------------------------------------------
// Calls a Python callable encoded in IDC.pvoid member
static const char idc_py_invoke0_args[] = { VT_PVOID, 0 };
static error_t idaapi idc_py_invoke0(
    idc_value_t *argv,
    idc_value_t *res)
{
  PYW_GIL_GET;
  PyObject *pyfunc = (PyObject *) argv[0].pvoid;
  newref_t py_result(PyObject_CallFunctionObjArgs(pyfunc, NULL));

  // Report Python error as IDC exception
  qstring err;
  error_t err_code = eOk;
  if ( PyW_GetError(&err) )
    err_code = PyW_CreateIdcException(res, err.c_str());
  return err_code;
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

  // Register the IDC PyInvoke0 method (helper function for add_idc_hotkey())
  if ( !set_idc_func_ex(S_PYINVOKE0, idc_py_invoke0, idc_py_invoke0_args, 0) )
    return false;

  // IDC opaque class not registered?
  if ( get_py_idc_cvt_opaque() == NULL )
  {
    // Add the class
    idc_class_t *idc_cvt_opaque = add_idc_class(S_PY_IDC_OPAQUE_T);
    if ( idc_cvt_opaque == NULL )
      return false;

    // Form the dtor name
    char dtor_name[MAXSTR];
    qsnprintf(dtor_name, sizeof(dtor_name), "%s.dtor", S_PY_IDC_OPAQUE_T);

    // Register the dtor function
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

  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    py_cvt_helper_module = ref_t(); // Deref.
  }

  // Unregister the IDC PyInvoke0 method (helper function for add_idc_hotkey())
  set_idc_func_ex(S_PYINVOKE0, NULL, idc_py_invoke0_args, 0);
}

//------------------------------------------------------------------------
// Utility function to create a class instance whose constructor takes zero arguments
ref_t create_idaapi_class_instance0(const char *clsname)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_cls(get_idaapi_attr(clsname));
  if ( py_cls == NULL )
    return ref_t();

  ref_t py_obj = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, NULL));
  if ( PyW_GetError() || py_obj == NULL )
    py_obj = ref_t();
  return py_obj;
}

//------------------------------------------------------------------------
// Utility function to create linked class instances
ref_t create_idaapi_linked_class_instance(
    const char *clsname,
    void *lnk)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_cls(get_idaapi_attr(clsname));
  if ( py_cls == NULL )
    return ref_t();

  newref_t py_lnk(PyCObject_FromVoidPtr(lnk, NULL));
  ref_t py_obj = newref_t(PyObject_CallFunctionObjArgs(py_cls.o, py_lnk.o, NULL));
  if ( PyW_GetError() || py_obj == NULL )
    py_obj = ref_t();
  return py_obj;
}

//------------------------------------------------------------------------
// Gets a class type reference in idaapi
// With the class type reference we can create a new instance of that type
// This function takes a reference to the idaapi module and keeps the reference
ref_t get_idaapi_attr_by_id(const int class_id)
{
  if ( class_id >= PY_CLSID_LAST || py_cvt_helper_module == NULL )
    return ref_t();

  // Some class names. The array is parallel with the PY_CLSID_xxx consts
  static const char *class_names[]=
  {
    "PyIdc_cvt_int64__",
    "object_t",
    "PyIdc_cvt_refclass__"
  };
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return newref_t(PyObject_GetAttrString(py_cvt_helper_module.o, class_names[class_id]));
}

//------------------------------------------------------------------------
// Gets a class reference by name
ref_t get_idaapi_attr(const char *attrname)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return py_cvt_helper_module == NULL
    ? ref_t()
    : PyW_TryGetAttrString(py_cvt_helper_module.o, attrname);
}

//------------------------------------------------------------------------
// Returns a qstring from an object attribute
bool PyW_GetStringAttr(
    PyObject *py_obj,
    const char *attr_name,
    qstring *str)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_attr(PyW_TryGetAttrString(py_obj, attr_name));
  if ( py_attr == NULL )
    return false;

  bool ok = PyString_Check(py_attr.o) != 0;
  if ( ok )
    *str = PyString_AsString(py_attr.o);

  return ok;
}

//------------------------------------------------------------------------
// Returns an attribute or NULL
// No errors will be set if the attribute did not exist
ref_t PyW_TryGetAttrString(PyObject *py_obj, const char *attr)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t o;
  if ( PyObject_HasAttrString(py_obj, attr) )
    o = newref_t(PyObject_GetAttrString(py_obj, attr));
  return o;
}

//------------------------------------------------------------------------
// Tries to import a module and clears the exception on failure
ref_t PyW_TryImportModule(const char *name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t result(PyImport_ImportModule(name));
  if ( result == NULL && PyErr_Occurred() )
      PyErr_Clear();
  return result;
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
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = true;
  do
  {
    if ( !(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)) )
    {
      rc = false;
      break;
    }

    // Can we convert to C long?
    long l = PyInt_AsLong(py_var);
    if ( !PyErr_Occurred() )
    {
      idc_var->set_long(l);
      break;
    }
    // Clear last error
    PyErr_Clear();
    // Can be fit into a C unsigned long?
    l = (long) PyLong_AsUnsignedLong(py_var);
    if ( !PyErr_Occurred() )
    {
      idc_var->set_long(l);
      break;
    }
    PyErr_Clear();
    idc_var->set_int64(PyLong_AsLongLong(py_var));
  } while ( false );
  return rc;
}

//-------------------------------------------------------------------------
// Parses a Python object as a long or long long
bool PyW_GetNumber(PyObject *py_var, uint64 *num, bool *is_64)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = true;
#define SETNUM(numexpr, is64_expr)              \
  do                                            \
  {                                             \
    if ( num != NULL )                          \
      *num = numexpr;                           \
    if ( is_64 != NULL )                        \
      *is_64 = is64_expr;                       \
  } while ( false )

  do
  {
    if ( !(PyInt_CheckExact(py_var) || PyLong_CheckExact(py_var)) )
    {
      rc = false;
      break;
    }

    // Can we convert to C long?
    long l = PyInt_AsLong(py_var);
    if ( !PyErr_Occurred() )
    {
      SETNUM(uint64(l), false);
      break;
    }

    // Clear last error
    PyErr_Clear();

    // Can be fit into a C unsigned long?
    unsigned long ul = PyLong_AsUnsignedLong(py_var);
    if ( !PyErr_Occurred() )
    {
      SETNUM(uint64(ul), false);
      break;
    }
    PyErr_Clear();

    // Try to parse as int64
    PY_LONG_LONG ll = PyLong_AsLongLong(py_var);
    if ( !PyErr_Occurred() )
    {
      SETNUM(uint64(ll), true);
      break;
    }
    PyErr_Clear();

    // Try to parse as uint64
    unsigned PY_LONG_LONG ull = PyLong_AsUnsignedLongLong(py_var);
    PyObject *err = PyErr_Occurred();
    if ( err == NULL )
    {
      SETNUM(uint64(ull), true);
      break;
    }
    // Negative number? _And_ it with uint64(-1)
    rc = false;
    if ( err == PyExc_TypeError )
    {
      newref_t py_mask(Py_BuildValue("K", 0xFFFFFFFFFFFFFFFFull));
      newref_t py_num(PyNumber_And(py_var, py_mask.o));
      if ( py_num != NULL && py_mask != NULL )
      {
        PyErr_Clear();
        ull = PyLong_AsUnsignedLongLong(py_num.o);
        if ( !PyErr_Occurred() )
        {
          SETNUM(uint64(ull), true);
          rc = true;
        }
      }
    }
    PyErr_Clear();
  } while ( false );
  return rc;
#undef SETNUM
}

//-------------------------------------------------------------------------
// Checks if a given object is of sequence type
bool PyW_IsSequenceType(PyObject *obj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = true;
  do
  {
    if ( !PySequence_Check(obj) )
    {
      rc = false;
      break;
    }

    Py_ssize_t sz = PySequence_Size(obj);
    if ( sz == -1 || PyErr_Occurred() != NULL )
    {
      PyErr_Clear();
      rc = false;
      break;
    }
  } while ( false );
  return rc;
}

//-------------------------------------------------------------------------
// Returns the string representation of an object
bool PyW_ObjectToString(PyObject *obj, qstring *out)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_str(PyObject_Str(obj));
  bool ok = py_str != NULL;
  if ( ok )
    *out = PyString_AsString(py_str.o);
  else
    out->qclear();
  return ok;
}

//--------------------------------------------------------------------------
// Checks if a Python error occured and fills the out parameter with the
// exception string
bool PyW_GetError(qstring *out, bool clear_err)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( PyErr_Occurred() == NULL )
    return false;

  // Error occurred but details not needed?
  if ( out == NULL )
  {
    // Just clear the error
    if ( clear_err )
      PyErr_Clear();
    return true;
  }

  // Get the exception info
  PyObject *err_type, *err_value, *err_traceback, *py_ret(NULL);
  PyErr_Fetch(&err_type, &err_value, &err_traceback);

  if ( !clear_err )
    PyErr_Restore(err_type, err_value, err_traceback);

  // Resolve FormatExc()
  ref_t py_fmtexc(get_idaapi_attr(S_IDAAPI_FORMATEXC));

  // Helper there?
  if ( py_fmtexc != NULL )
  {
    // Call helper
    py_ret = PyObject_CallFunctionObjArgs(
      py_fmtexc.o,
      err_type,
      err_value,
      err_traceback,
      NULL);
  }

  // Clear the error
  if ( clear_err )
    PyErr_Clear();

  // Helper failed?!
  if ( py_ret == NULL )
  {
    // Just convert the 'value' part of the original error
    py_ret = PyObject_Str(err_value);
  }

  // No exception text?
  if ( py_ret == NULL )
  {
    *out = "IDAPython: unknown error!";
  }
  else
  {
    *out = PyString_AsString(py_ret);
    Py_DECREF(py_ret);
  }

  if ( clear_err )
  {
    Py_XDECREF(err_traceback);
    Py_XDECREF(err_value);
    Py_XDECREF(err_type);
  }
  return true;
}

//-------------------------------------------------------------------------
bool PyW_GetError(char *buf, size_t bufsz, bool clear_err)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstring s;
  if ( !PyW_GetError(&s, clear_err) )
    return false;

  qstrncpy(buf, s.c_str(), bufsz);
  return true;
}

//-------------------------------------------------------------------------
// A loud version of PyGetError() which gets the error and displays it
// This method is used to display errors that occurred in a callback
bool PyW_ShowCbErr(const char *cb_name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  static qstring err_str;
  if ( !PyW_GetError(&err_str) )
    return false;

  warning("IDAPython: Error while calling Python callback <%s>:\n%s", cb_name, err_str.c_str());
  return true;
}

//---------------------------------------------------------------------------
void *pyobj_get_clink(PyObject *pyobj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Try to query the link attribute
  ref_t attr(PyW_TryGetAttrString(pyobj, S_CLINK_NAME));
  void *t = attr != NULL && PyCObject_Check(attr.o) ? PyCObject_AsVoidPtr(attr.o) : NULL;
  return t;
}

//</code(py_idaapi)>

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
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t args;
  if ( parse_command_line3(cmdline, &args, NULL, LP_PATH_WITH_ARGS) == 0 )
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
    Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses.
    See also L{disable_script_timeout}.

    @param timeout: This value is in seconds.
                    If this value is set to zero then the script will never timeout.
    @return: Returns the old timeout value
    """
    pass
#</pydoc>
*/
int set_script_timeout(int timeout);

/*
#<pydoc>
def disable_script_timeout():
    """
    Disables the script timeout and hides the script wait box.
    Calling L{set_script_timeout} will not have any effects until the script is compiled and executed again

    @return: None
    """
    pass
#</pydoc>
*/
void disable_script_timeout();

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

/*
//---------------------------------------------------------------------------
// qstrvec_t wrapper
//---------------------------------------------------------------------------
DECLARE_PY_CLINKED_OBJECT(qstrvec_t);

static bool qstrvec_t_assign(PyObject *self, PyObject *other)
{
  qstrvec_t *lhs = qstrvec_t_get_clink(self);
  qstrvec_t *rhs = qstrvec_t_get_clink(other);
  if (lhs == NULL || rhs == NULL)
    return false;
  *lhs = *rhs;
  return true;
}

static PyObject *qstrvec_t_addressof(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    Py_RETURN_NONE;
  else
    return PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG)&sv->at(idx));
}


static bool qstrvec_t_set(
    PyObject *self,
    size_t idx,
    const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    return false;
  (*sv)[idx] = s;
  return true;
}

static bool qstrvec_t_from_list(
  PyObject *self,
  PyObject *py_list)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  return sv == NULL ? false : PyW_PyListToStrVec(py_list, *sv);
}

static size_t qstrvec_t_size(PyObject *self)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  return sv == NULL ? 0 : sv->size();
}

static PyObject *qstrvec_t_get(PyObject *self, size_t idx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    Py_RETURN_NONE;
  return PyString_FromString(sv->at(idx).c_str());
}

static bool qstrvec_t_add(PyObject *self, const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL )
    return false;
  sv->push_back(s);
  return true;
}

static bool qstrvec_t_clear(PyObject *self, bool qclear)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL )
    return false;

  if ( qclear )
    sv->qclear();
  else
    sv->clear();

  return true;
}

static bool qstrvec_t_insert(
    PyObject *self,
    size_t idx,
    const char *s)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    return false;
  sv->insert(sv->begin() + idx, s);
  return true;
}

static bool qstrvec_t_remove(PyObject *self, size_t idx)
{
  qstrvec_t *sv = qstrvec_t_get_clink(self);
  if ( sv == NULL || idx >= sv->size() )
    return false;

  sv->erase(sv->begin()+idx);
  return true;
}
*/
//---------------------------------------------------------------------------
//</inline(py_idaapi)>

#endif
