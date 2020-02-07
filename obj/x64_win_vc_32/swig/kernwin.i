%module(docstring="IDA Plugin SDK API wrapper: kernwin",directors="1",threads="1") ida_kernwin
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_KERNWIN
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_KERNWIN
  #define HAS_DEP_ON_INTERFACE_KERNWIN
#endif
%include "header.i"
%{
#include <kernwin.hpp>
#include <parsejson.hpp>
%}

%{
#ifdef __NT__
idaman __declspec(dllimport) plugin_t PLUGIN;
#else
extern plugin_t PLUGIN;
#endif
%}


%typemap(out) void *get_window_id
{
  // %typemap(out) void *get_window_id
  $result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
}

// Ignore the va_list functions
%ignore vask_form;
%ignore ask_form;
%ignore open_form;
%ignore vopen_form;
%ignore close_form;
%ignore vask_str;
%ignore ask_str;
%ignore ask_ident;
%ignore vask_buttons;
%ignore vask_file;
%ignore vask_yn;
%ignore strvec_t;
%ignore load_custom_icon;
%ignore vask_text;
%ignore ask_text;
%ignore vwarning;
// Note: don't do that for ask_form(), since that calls back into Python.
%thread ask_addr;
%thread ask_seg;
%thread ask_long;
%thread ask_yn;
%thread ask_buttons;
%thread ask_file;

%calls_execute_sync(clr_cancelled);
%calls_execute_sync(set_cancelled);
%calls_execute_sync(user_cancelled);
%calls_execute_sync(hide_wait_box);

%ignore choose_idasgn;
%rename (choose_idasgn) py_choose_idasgn;

%ignore get_chooser_data;
%rename (get_chooser_data) py_get_chooser_data;

%rename (del_hotkey) py_del_hotkey;
%rename (add_hotkey) py_add_hotkey;

%ignore msg;
%rename (msg) py_msg;

%ignore vinfo;
%ignore UI_Callback;
%ignore vnomem;
%ignore vmsg;
%ignore show_wait_box_v;
%ignore create_custom_viewer;
%ignore take_database_snapshot;
%rename (take_database_snapshot) py_take_database_snapshot;
%ignore restore_database_snapshot;
%rename (restore_database_snapshot) py_restore_database_snapshot;
%ignore destroy_custom_viewer;
%ignore destroy_custom_viewerdestroy_custom_viewer;
%ignore set_custom_viewer_handler;
%ignore set_custom_viewer_range;
%ignore is_idaview;
%ignore refresh_custom_viewer;
%ignore set_custom_viewer_handlers;
%ignore get_viewer_name;
// Ignore these string functions. There are trivial replacements in Python.
%ignore trim;
%ignore skip_spaces;
%ignore stristr;
%ignore set_nav_colorizer;
%rename (set_nav_colorizer) py_set_nav_colorizer;
%rename (call_nav_colorizer) py_call_nav_colorizer;

%ignore get_highlight;
%rename (get_highlight) py_get_highlight;

%ignore action_desc_t::handler;
%ignore action_handler_t;
%ignore register_action;
%rename (register_action) py_register_action;
%ignore attach_dynamic_action_to_popup;
%rename (attach_dynamic_action_to_popup) py_attach_dynamic_action_to_popup;
%ignore get_registered_actions;
%rename (get_registered_actions) py_get_registered_actions;

%include "typemaps.i"

%rename (ask_text) py_ask_text;
%rename (ask_str) py_ask_str;
%rename (str2ea)  py_str2ea;
%ignore process_ui_action;
%rename (process_ui_action) py_process_ui_action;
%ignore execute_sync;
%ignore exec_request_t;
%rename (execute_sync) py_execute_sync;

%ignore ui_request_t;
%ignore execute_ui_requests;
%rename (execute_ui_requests) py_execute_ui_requests;

%ignore timer_t;
%ignore register_timer;
%rename (register_timer) py_register_timer;
%ignore unregister_timer;
%rename (unregister_timer) py_unregister_timer;

%ignore chooser_item_attrs_t::cb;

// Make ask_addr(), ask_seg(), and ask_long() return a
// tuple: (result, value)
%rename (_ask_long) ask_long;
%rename (_ask_addr) ask_addr;
%rename (_ask_seg) ask_seg;

%ignore gen_disasm_text;
%rename (gen_disasm_text) py_gen_disasm_text;

%ignore UI_Hooks::handle_hint_output;
%ignore UI_Hooks::handle_get_ea_hint_output;
%ignore UI_Hooks::wrap_widget_cfg;
%ignore UI_Hooks::handle_create_desktop_widget_output;
%ignore jobj_wrapper_t::jobj_wrapper_t;
%ignore jobj_wrapper_t::~jobj_wrapper_t;

// We will %ignore those ATM, since they cannot be trivially
// wrapped: bytevec_t is not exposed.
// (besides, serializing/deserializing should probably
// be done by locstack_t instances only.)
%ignore place_t::serialize;
%ignore place_t__serialize;
%ignore place_t::deserialize;
%ignore place_t__deserialize;
%ignore place_t::generate;
%ignore place_t__generate;
%rename (generate) py_generate;

%ignore register_place_class;
%ignore register_loc_converter;
%ignore lookup_loc_converter;

%ignore hexplace_t;
%ignore hexplace_gen_t;

%ignore msg_get_lines;
%rename (msg_get_lines) py_msg_get_lines;

%feature("director") UI_Hooks;

//-------------------------------------------------------------------------
%{
struct py_action_handler_t : public action_handler_t
{
  py_action_handler_t(); // No.
  py_action_handler_t(PyObject *_o)
    : pyah(borref_t(_o)), has_activate(false), has_update(false)
  {
    ref_t act(PyW_TryGetAttrString(pyah.o, "activate"));
    if ( act != NULL && PyCallable_Check(act.o) > 0 )
      has_activate = true;

    ref_t upd(PyW_TryGetAttrString(pyah.o, "update"));
    if ( upd != NULL && PyCallable_Check(upd.o) > 0 )
      has_update = true;
  }
  virtual idaapi ~py_action_handler_t()
  {
    PYW_GIL_GET;
    // NOTE: We need to do the decref _within_ the PYW_GIL_GET scope,
    // and not leave it to the destructor to clean it up, because when
    // ~ref_t() gets called, the GIL will have already been released.
    pyah = ref_t();
  }
  virtual int idaapi activate(action_activation_ctx_t *ctx)
  {
    if ( !has_activate )
      return 0;
    PYW_GIL_GET_AND_REPORT_ERROR;
    newref_t pyctx(SWIG_NewPointerObj(SWIG_as_voidptr(ctx), SWIGTYPE_p_action_ctx_base_t, 0));
    newref_t pyres(PyObject_CallMethod(pyah.o, (char *)"activate", (char *) "O", pyctx.o));
    return PyErr_Occurred() ? 0 : ((pyres != NULL && IDAPyInt_Check(pyres.o)) ? IDAPyInt_AsLong(pyres.o) : 0);
  }
  virtual action_state_t idaapi update(action_update_ctx_t *ctx)
  {
    if ( !has_update )
      return AST_DISABLE;
    PYW_GIL_GET_AND_REPORT_ERROR;
    newref_t pyctx(SWIG_NewPointerObj(SWIG_as_voidptr(ctx), SWIGTYPE_p_action_ctx_base_t, 0));
    newref_t pyres(PyObject_CallMethod(pyah.o, (char *)"update", (char *) "O", pyctx.o));
    return PyErr_Occurred() ? AST_DISABLE_ALWAYS : ((pyres != NULL && IDAPyInt_Check(pyres.o)) ? action_state_t(IDAPyInt_AsLong(pyres.o)) : AST_DISABLE);
  }

private:
  ref_t pyah;
  bool has_activate;
  bool has_update;
};

%}

%inline %{
void refresh_choosers(void)
{
  Py_BEGIN_ALLOW_THREADS;
  callui(ui_refresh_choosers);
  Py_END_ALLOW_THREADS;
}
%}

// get_cursor()
%apply int *OUTPUT {int *x, int *y};

// get_navband_pixel()
%apply bool *OUTPUT {bool *out_is_vertical};


%ignore textctrl_info_t;
SWIG_DECLARE_PY_CLINKED_OBJECT(textctrl_info_t)

%{
static void _py_unregister_compiled_form(PyObject *py_form, bool shutdown);
%}

%{
//<decls(py_kernwin)>
//------------------------------------------------------------------------

//-------------------------------------------------------------------------
// Context structure used by add|del_idc_hotkey()
struct py_idchotkey_ctx_t
{
  qstring hotkey;
  PyObject *pyfunc;
};

//------------------------------------------------------------------------
//</decls(py_kernwin)>
%}

%inline %{
//<inline(py_kernwin)>
//------------------------------------------------------------------------

//------------------------------------------------------------------------
/*
#<pydoc>
def register_timer(interval, callback):
    """
    Register a timer

    @param interval: Interval in milliseconds
    @param callback: A Python callable that takes no parameters and returns an integer.
                     The callback may return:
                     -1   : to unregister the timer
                     >= 0 : the new or same timer interval
    @return: None or a timer object
    """
    pass
#</pydoc>
*/
static PyObject *py_register_timer(int interval, PyObject *py_callback)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( py_callback == NULL || !PyCallable_Check(py_callback) )
    Py_RETURN_NONE;

  // An inner class hosting the callback method
  struct tmr_t
  {
    static int idaapi callback(void *ud)
    {
      PYW_GIL_GET;
      py_timer_ctx_t *ctx = (py_timer_ctx_t *)ud;
      newref_t py_result(PyObject_CallFunctionObjArgs(ctx->pycallback, NULL));
      int ret = -1;
      if ( PyErr_Occurred() )
      {
        msg("Exception in timer callback. This timer will be unregistered.\n");
        PyErr_Print();
      }
      else if ( py_result != NULL )
      {
        ret = PyLong_AsLong(py_result.o);
      }

      // Timer has been unregistered?
      if ( ret == -1 )
        python_timer_del(ctx);
      return ret;
    };
  };

  py_timer_ctx_t *ctx = python_timer_new(py_callback);
  ctx->timer_id = register_timer(
          interval,
          tmr_t::callback,
          ctx);

  if ( ctx->timer_id == NULL )
  {
    python_timer_del(ctx);
    Py_RETURN_NONE;
  }
  return PyCapsule_New(ctx,VALID_CAPSULE_NAME, NULL);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def unregister_timer(timer_obj):
    """
    Unregister a timer

    @param timer_obj: a timer object previously returned by a register_timer()
    @return: Boolean
    @note: After the timer has been deleted, the timer_obj will become invalid.
    """
    pass
#</pydoc>
*/
static PyObject *py_unregister_timer(PyObject *py_timerctx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( py_timerctx == NULL || !PyCapsule_IsValid(py_timerctx, VALID_CAPSULE_NAME) )
    Py_RETURN_FALSE;

  py_timer_ctx_t *ctx = (py_timer_ctx_t *) PyCapsule_GetPointer(py_timerctx, VALID_CAPSULE_NAME);
  if ( ctx == NULL || !unregister_timer(ctx->timer_id) )
    Py_RETURN_FALSE;

  python_timer_del(ctx);
  PyCapsule_SetName(py_timerctx, INVALID_CAPSULE_NAME);
  Py_RETURN_TRUE;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def choose_idasgn():
    """
    Opens the signature chooser

    @return: None or the selected signature name
    """
    pass
#</pydoc>
*/
static PyObject *py_choose_idasgn()
{
  char *name = choose_idasgn();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( name == NULL )
  {
    Py_RETURN_NONE;
  }
  else
  {
    PyObject *py_str = IDAPyStr_FromUTF8(name);
    qfree(name);
    return py_str;
  }
}

//------------------------------------------------------------------------
/*
#<pydoc>
def get_highlight():
    """
    Returns the currently highlighted identifier and flags

    @return: a tuple (text, flags), or None if nothing
             is highlighted or in case of error.
    """
    pass
#</pydoc>
*/
static PyObject *py_get_highlight(TWidget *v)
{
  qstring buf;
  uint32 flags;
  bool ok = get_highlight(&buf, v, &flags);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !ok )
    Py_RETURN_NONE;
  return Py_BuildValue("(sk)", buf.c_str(), flags);
}

//------------------------------------------------------------------------
static int py_load_custom_icon_fn(const char *filename)
{
  return load_custom_icon(filename);
}

//------------------------------------------------------------------------
static int py_load_custom_icon_data(PyObject *data, const char *format)
{
  Py_ssize_t len;
  char *s;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( IDAPyBytes_AsMemAndSize(data, &s, &len) == -1 )
    return 0;
  else
    return load_custom_icon(s, len, format);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def free_custom_icon(icon_id):
    """
    Frees an icon loaded with load_custom_icon()
    """
    pass
#</pydoc>
*/

//-------------------------------------------------------------------------
/*
#<pydoc>
def read_selection(view, p0, p1):
    """
    Read the user selection, and store its information in p0 (from) and p1 (to).

    This can be used as follows:


    >>> p0 = idaapi.twinpos_t()
    p1 = idaapi.twinpos_t()
    view = idaapi.get_current_viewer()
    idaapi.read_selection(view, p0, p1)


    At that point, p0 and p1 hold information for the selection.
    But, the 'at' property of p0 and p1 is not properly typed.
    To specialize it, call #place() on it, passing it the view
    they were retrieved from. Like so:


    >>> place0 = p0.place(view)
    place1 = p1.place(view)


    This will effectively "cast" the place into a specialized type,
    holding proper information, depending on the view type (e.g.,
    disassembly, structures, enums, ...)

    @param view: The view to retrieve the selection for.
    @param p0: Storage for the "from" part of the selection.
    @param p1: Storage for the "to" part of the selection.
    @return: a bool value indicating success.
    """
    pass
#</pydoc>
*/

//------------------------------------------------------------------------
/*
#<pydoc>
def msg(text):
    """
    Prints text into IDA's Output window

    @param text: text to print
                 Can be Unicode, or string in local encoding
    @return: number of bytes printed
    """
    pass
#</pydoc>
*/
static PyObject *py_msg(PyObject *o)
{
  const char *utf8 = NULL;
  ref_t py_utf8;
  if ( PyUnicode_Check(o) )
  {
    py_utf8 = newref_t(PyUnicode_AsUTF8String(o));
    utf8 = IDAPyBytes_AsString(py_utf8.o);
  }
  else if ( IDAPyStr_Check(o) )
  {
    utf8 = IDAPyBytes_AsString(o);
  }
  else
  {
    PyErr_SetString(PyExc_TypeError, "A string expected");
    return NULL;
  }
  int rc;
  Py_BEGIN_ALLOW_THREADS;
  rc = msg("%s", utf8);
  Py_END_ALLOW_THREADS;
  return IDAPyInt_FromLong(rc);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def ask_text(defval, prompt):
    """
    Asks for a long text

    @param max_size: Maximum text length, 0 for unlimited
    @param defval: The default value
    @param prompt: The prompt value
    @return: None or the entered string
    """
    pass
#</pydoc>
*/
PyObject *py_ask_text(size_t max_size, const char *defval, const char *prompt)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstring qbuf;

  PyObject *py_ret;
  if ( ask_text(&qbuf, max_size, defval, "%s", prompt) )
  {
    py_ret = IDAPyStr_FromUTF8AndSize(qbuf.begin(), qbuf.length());
  }
  else
  {
    py_ret = Py_None;
    Py_INCREF(py_ret);
  }
  return py_ret;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def ask_str(defval, hist, prompt):
    """
    Asks for a long text

    @param hist:   history id
    @param defval: The default value
    @param prompt: The prompt value
    @return: None or the entered string
    """
    pass
#</pydoc>
*/
PyObject *py_ask_str(qstring *defval, int hist, const char *prompt)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  PyObject *py_ret;
  if ( ask_str(defval, hist, "%s", prompt) )
  {
    py_ret = IDAPyStr_FromUTF8AndSize(defval->begin(), defval->length());
  }
  else
  {
    py_ret = Py_None;
    Py_INCREF(py_ret);
  }
  return py_ret;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def str2ea(addr):
    """
    Converts a string express to EA. The expression evaluator may be called as well.

    @return: BADADDR or address value
    """
    pass
#</pydoc>
*/
ea_t py_str2ea(const char *str, ea_t screenEA = BADADDR)
{
  ea_t ea;
  bool ok = str2ea(&ea, str, screenEA);
  return ok ? ea : BADADDR;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def process_ui_action(name):
    """
    Invokes an IDA UI action by name

    @param name:  action name
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_process_ui_action(const char *name, int flags = 0)
{
  return process_ui_action(name, flags, NULL);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def del_hotkey(ctx):
    """
    Deletes a previously registered function hotkey

    @param ctx: Hotkey context previously returned by add_hotkey()

    @return: Boolean.
    """
    pass
#</pydoc>
*/
bool py_del_hotkey(PyObject *pyctx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCapsule_IsValid(pyctx, VALID_CAPSULE_NAME) )
    return false;

  py_idchotkey_ctx_t *ctx = (py_idchotkey_ctx_t *) PyCapsule_GetPointer(pyctx, VALID_CAPSULE_NAME);
  if ( ctx == NULL || !del_idc_hotkey(ctx->hotkey.c_str()) )
    return false;

  Py_DECREF(ctx->pyfunc);
  delete ctx;
  // Here we must ensure that the python object is invalidated.
  // This is to avoid the possibility of this function being called again
  // with the same ctx, which would contain a pointer to a deleted object.
  PyCapsule_SetName(pyctx, INVALID_CAPSULE_NAME);

  return true;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def add_hotkey(hotkey, pyfunc):
    """
    Associates a function call with a hotkey.
    Callable pyfunc will be called each time the hotkey is pressed

    @param hotkey: The hotkey
    @param pyfunc: Callable

    @return: Context object on success or None on failure.
    """
    pass
#</pydoc>
*/
PyObject *py_add_hotkey(const char *hotkey, PyObject *pyfunc)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  // Make sure a callable was passed
  if ( !PyCallable_Check(pyfunc) )
    return NULL;

  // Form the function name
  qstring idc_func_name;
  idc_func_name.sprnt("py_hotkeycb_%p", pyfunc);

  // Can add the hotkey?
  if ( add_idc_hotkey(hotkey, idc_func_name.c_str()) == IDCHK_OK )
  {
    do
    {
      // Generate global variable name
      qstring idc_gvarname;
      idc_gvarname.sprnt("_g_pyhotkey_ref_%p", pyfunc);

      // Now add the global variable
      idc_value_t *gvar = add_idc_gvar(idc_gvarname.c_str());
      if ( gvar == NULL )
        break;

      // The function body will call a registered IDC function that
      // will take a global variable that wraps a PyCallable as a pvoid
      qstring idc_func;
      idc_func.sprnt("static %s() { %s(%s); }",
        idc_func_name.c_str(),
        S_PYINVOKE0,
        idc_gvarname.c_str());

      // Compile the IDC condition
      qstring errbuf;
      if ( !compile_idc_text(idc_func.c_str(), &errbuf) )
        break;

      // Create new context
      // Define context
      py_idchotkey_ctx_t *ctx = new py_idchotkey_ctx_t();

      // Remember the hotkey
      ctx->hotkey = hotkey;

      // Take reference to the callable
      ctx->pyfunc = pyfunc;
      Py_INCREF(pyfunc);

      // Bind IDC variable w/ the PyCallable
      gvar->set_pvoid(pyfunc);

      // Return the context
      return PyCapsule_New(ctx,VALID_CAPSULE_NAME, NULL);
    } while (false);
  }
  // Cleanup
  del_idc_hotkey(hotkey);
  Py_RETURN_NONE;
}

//------------------------------------------------------------------------
static PyObject *py_take_database_snapshot(snapshot_t *ss)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstring err_msg;

  bool b = take_database_snapshot(ss, &err_msg);

  // Return (b, err_msg)
  return Py_BuildValue("(Ns)", PyBool_FromLong(b), err_msg.empty() ? NULL : err_msg.c_str());
}

//------------------------------------------------------------------------
static void idaapi py_ss_restore_callback(const char *err_msg, void *userdata)
{
  PYW_GIL_GET;

  // userdata is a tuple of ( func, args )
  // func and args are borrowed references from userdata
  PyObject *o = (PyObject *) userdata;
  if ( !PyTuple_Check(o) )
    return;

  PyObject *func = PyTuple_GetItem(o, 0);
  PyObject *args = PyTuple_GetItem(o, 1);

  // Create arguments tuple for python function
  PyObject *cb_args = Py_BuildValue("(sO)", err_msg, args);

  // Call the python function
  newref_t result(PyEval_CallObject(func, cb_args));

  // Free cb_args and userdata
  Py_DECREF(cb_args);
  Py_DECREF(userdata);

  // We cannot raise an exception in the callback, just print it.
  if ( result == NULL )
    PyErr_Print();
}
static PyObject *py_restore_database_snapshot(
        const snapshot_t *ss,
        PyObject *pyfunc_or_none,
        PyObject *pytuple_or_none)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // If there is no callback, just call the function directly
  if ( pyfunc_or_none == Py_None )
    return PyBool_FromLong(restore_database_snapshot(ss, NULL, NULL));

  // Create a new tuple or increase reference to pytuple_or_none
  if ( pytuple_or_none == Py_None )
  {
    pytuple_or_none = PyTuple_New(0);
    if ( pytuple_or_none == NULL )
      return NULL;
  }
  else
  {
    Py_INCREF(pytuple_or_none);
  }

  // Create callback data tuple (use 'N' for pytuple_or_none, since its
  // reference has already been incremented)
  PyObject *cb_data = Py_BuildValue("(ON)", pyfunc_or_none, pytuple_or_none);

  bool b = restore_database_snapshot(ss, py_ss_restore_callback, (void *) cb_data);

  if ( !b )
    Py_DECREF(cb_data);

  return PyBool_FromLong(b);
}

//------------------------------------------------------------------------
/*
#<pydoc>

MFF_FAST = 0x0000
"""execute code as soon as possible
this mode is ok call ui related functions
that do not query the database."""

MFF_READ = 0x0001
"""execute code only when ida is idle and it is safe to query the database.
this mode is recommended only for code that does not modify the database.
(nb: ida may be in the middle of executing another user request, for example it may be waiting for him to enter values into a modal dialog box)"""

MFF_WRITE = 0x0002
"""execute code only when ida is idle and it is safe to modify the database. in particular, this flag will suspend execution if there is
a modal dialog box on the screen this mode can be used to call any ida api function. MFF_WRITE implies MFF_READ"""

MFF_NOWAIT = 0x0004
"""Do not wait for the request to be executed.
he caller should ensure that the request is not
destroyed until the execution completes.
if not, the request will be ignored.
the return code of execute_sync() is meaningless
in this case.
This flag can be used to delay the code execution
until the next UI loop run even from the main thread"""

def execute_sync(callable, reqf):
    """
    Executes a function in the context of the main thread.
    If the current thread not the main thread, then the call is queued and
    executed afterwards.

    @param callable: A python callable object, must return an integer value
    @param reqf: one of MFF_ flags
    @return: -1 or the return value of the callable
    """
    pass
#</pydoc>
*/
//------------------------------------------------------------------------
static int py_execute_sync(PyObject *py_callable, int reqf)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  int rc = -1;
  // Callable?
  if ( PyCallable_Check(py_callable) )
  {
    struct py_exec_request_t : exec_request_t
    {
      ref_t py_callable;
      virtual int idaapi execute()
      {
        PYW_GIL_GET;
        newref_t py_result(PyObject_CallFunctionObjArgs(py_callable.o, NULL));
        int ret = py_result == NULL || !IDAPyInt_Check(py_result.o)
                ? -1
                : IDAPyInt_AsLong(py_result.o);
        // if the requesting thread decided not to wait for the request to
        // complete, we have to self-destroy, nobody else will do it
        if ( (code & MFF_NOWAIT) != 0 )
          delete this;
        return ret;
      }
      py_exec_request_t(PyObject *pyc)
      {
        // No need to GIL-ensure here, since this is created
        // within the py_execute_sync() scope.
        py_callable = borref_t(pyc);
      }
      virtual ~py_exec_request_t()
      {
        // Need to GIL-ensure here, since this might be called
        // from the main thread.
        PYW_GIL_GET;
        py_callable = ref_t(); // Release callable
      }
    };
    py_exec_request_t *req = new py_exec_request_t(py_callable);

    // Release GIL before executing, or if this is running in the
    // non-main thread, this will wait on the req.sem, while the main
    // thread might be waiting for the GIL to be available.
    Py_BEGIN_ALLOW_THREADS;
    rc = execute_sync(*req, reqf);
    Py_END_ALLOW_THREADS;
    // destroy the request once it is finished. exception: NOWAIT requests
    // will be handled in the future, so do not destroy them yet!
    if ( (reqf & MFF_NOWAIT) == 0 )
      delete req;
  }
  return rc;
}

//------------------------------------------------------------------------
/*
#<pydoc>

def execute_ui_requests(callable_list):
    """
    Inserts a list of callables into the UI message processing queue.
    When the UI is ready it will call one callable.
    A callable can request to be called more than once if it returns True.

    @param callable_list: A list of python callable objects.
    @note: A callable should return True if it wants to be called more than once.
    @return: Boolean. False if the list contains a non callabale item
    """
    pass
#</pydoc>
*/
static bool py_execute_ui_requests(PyObject *py_list)
{
  struct py_ui_request_t: public ui_request_t
  {
  private:
    ref_vec_t py_callables;
    size_t py_callable_idx;

    static int idaapi s_py_list_walk_cb(
            const ref_t &py_item,
            Py_ssize_t index,
            void *ud)
    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      // Not callable? Terminate iteration
      if ( !PyCallable_Check(py_item.o) )
        return CIP_FAILED;

      // Append this callable and increment its reference
      py_ui_request_t *_this = (py_ui_request_t *)ud;
      _this->py_callables.push_back(py_item);
      return CIP_OK;
    }
  public:
    py_ui_request_t(): py_callable_idx(0)
    {
    }

    virtual bool idaapi run()
    {
      PYW_GIL_GET;

      // Get callable
      ref_t py_callable = py_callables.at(py_callable_idx);
      bool reschedule;
      newref_t py_result(PyObject_CallFunctionObjArgs(py_callable.o, NULL));
      reschedule = py_result != NULL && PyObject_IsTrue(py_result.o);

      // No rescheduling? Then advance to the next callable
      if ( !reschedule )
        ++py_callable_idx;

      // Reschedule this C callback only if there are more callables
      return py_callable_idx < py_callables.size();
    }

    // Walk the list and extract all callables
    bool init(PyObject *py_list)
    {
      Py_ssize_t count = pyvar_walk_list(
              py_list,
              s_py_list_walk_cb,
              this);
      return count > 0;
    }

    virtual idaapi ~py_ui_request_t()
    {
      PYW_GIL_GET;
      py_callables.clear();
    }
  };

  py_ui_request_t *req = new py_ui_request_t();
  if ( !req->init(py_list) )
  {
    delete req;
    return false;
  }
  execute_ui_requests(req, NULL);
  return true;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def set_dock_pos(src, dest, orient, left = 0, top = 0, right = 0, bottom = 0):
    """
    Sets the dock orientation of a window relatively to another window.

    @param src: Source docking control
    @param dest: Destination docking control
    @param orient: One of DOR_XXXX constants
    @param left, top, right, bottom: These parameter if DOR_FLOATING is used, or if you want to specify the width of docked windows
    @return: Boolean

    Example:
        set_dock_pos('Structures', 'Enums', DOR_RIGHT) <- docks the Structures window to the right of Enums window
    """
    pass
#</pydoc>
*/

//------------------------------------------------------------------------
/*
#<pydoc>
def is_idaq():
    """
    Returns True or False depending if IDAPython is hosted by IDAQ
    """
#</pydoc>
*/


struct jobj_wrapper_t
{
private:
  const jobj_t *o;

public:
  jobj_wrapper_t(const jobj_t *_o) : o(_o) {}

  PyObject *get_dict()
  {
    newref_t json_module(PyImport_ImportModule("json"));
    if ( json_module != NULL )
    {
      borref_t json_globals(PyModule_GetDict(json_module.o));
      if ( json_globals != NULL )
      {
        borref_t json_loads(PyDict_GetItemString(json_globals.o, "loads"));
        if ( json_loads != NULL )
        {
          qstring clob;
          if ( serialize_json(&clob, o) )
          {
            newref_t dict(PyObject_CallFunction(json_loads.o, "s", clob.c_str()));
            if ( dict != NULL )
            {
              dict.incref();
              return dict.o;
            }
          }
        }
      }
    }
    Py_RETURN_NONE;
  }
};

//---------------------------------------------------------------------------
// UI hooks
//---------------------------------------------------------------------------
ssize_t idaapi UI_Callback(void *ud, int notification_code, va_list va);
/*
#<pydoc>
class UI_Hooks(object):
    def hook(self):
        """
        Creates an UI hook

        @return: Boolean true on success
        """
        pass

    def unhook(self):
        """
        Removes the UI hook
        @return: Boolean true on success
        """
        pass

    def preprocess_action(self, name):
        """
        IDA ui is about to handle a user action

        @param name: ui action name
                     (these names can be looked up in ida[tg]ui.cfg)
        @return: 0-ok, nonzero - a plugin has handled the action
        """
        pass

    def postprocess_action(self):
        """
        An ida ui action has been handled

        @return: Ignored
        """
        pass

    def saving(self):
        """
        The kernel is saving the database.

        @return: Ignored
        """
        pass

    def saved(self):
        """
        The kernel has saved the database.

        @return: Ignored
        """
        pass

    def get_ea_hint(self, ea):
        """
        The UI wants to display a simple hint for an address in the navigation band

        @param ea: The address
        @return: String with the hint or None
        """
        pass

    def updating_actions(self, ctx):
        """
        The UI is about to batch-update some actions.

        @param ctx: The action_update_ctx_t instance
        @return: Ignored
        """
        pass

    def updated_actions(self):
        """
        The UI is done updating actions.

        @return: Ignored
        """
        pass

    def populating_widget_popup(self, widget, popup):
        """
        The UI is populating the TWidget's popup menu.
        Now is a good time to call idaapi.attach_action_to_popup()

        @param widget: The widget
        @param popup: The popup menu.
        @return: Ignored
        """
        pass

    def finish_populating_widget_popup(self, widget, popup):
        """
        The UI is about to be done populating the TWidget's popup menu.
        Now is a good time to call idaapi.attach_action_to_popup()

        @param widget: The widget
        @param popup: The popup menu.
        @return: Ignored
        """
        pass

    def term(self):
        """
        IDA is terminated and the database is already closed.
        The UI may close its windows in this callback.
        """
        # if the user forgot to call unhook, do it for him
        self.unhook()

    def __term__(self):
        self.term()

#</pydoc>
*/
class UI_Hooks
{
public:
  virtual ~UI_Hooks()
  {
    unhook();
  }

  bool hook()
  {
    return idapython_hook_to_notification_point(HT_UI, UI_Callback, this);
  }

  bool unhook()
  {
    return idapython_unhook_from_notification_point(HT_UI, UI_Callback, this);
  }

  static ssize_t handle_get_ea_hint_output(PyObject *o, qstring *buf, ea_t)
  {
    ssize_t rc = 0;
    char *_buf;
    Py_ssize_t _len;
    if ( o != NULL && IDAPyStr_Check(o) && IDAPyBytes_AsMemAndSize(o, &_buf, &_len) != -1 )
    {
      buf->append(_buf, _len);
      rc = 1;
    }
    Py_XDECREF(o);
    return rc;
  }

  static ssize_t handle_hint_output(PyObject *o, qstring *hint, int *important_lines)
  {
    ssize_t rc = 0;
    if ( o != NULL && PyTuple_Check(o) && PyTuple_Size(o) == 2 )
    {
      borref_t el0(PyTuple_GetItem(o, 0));
      char *_buf;
      Py_ssize_t _len;
      if ( el0 != NULL
        && IDAPyStr_Check(el0.o)
        && IDAPyBytes_AsMemAndSize(el0.o, &_buf, &_len) != -1
        && _len > 0 )
      {
        borref_t el1(PyTuple_GetItem(o, 1));
        if ( el1 != NULL && IDAPyInt_Check(el1.o) )
        {
          long lns = IDAPyInt_AsLong(el1.o);
          if ( lns > 0 )
          {
            *important_lines = lns;
            hint->append(_buf, _len);
            rc = 1;
          }
        }
      }
    }
    return rc;
  }

  static ssize_t handle_hint_output(PyObject *o, qstring *hint, ea_t, int, int *important_lines)
  {
    return handle_hint_output(o, hint, important_lines);
  }

  static ssize_t handle_hint_output(PyObject *o, qstring *hint, TWidget *, place_t *, int *important_lines)
  {
    return handle_hint_output(o, hint, important_lines);
  }

  static jobj_wrapper_t wrap_widget_cfg(const jobj_t *jobj)
  {
    return jobj_wrapper_t(jobj);
  }

  static ssize_t handle_create_desktop_widget_output(PyObject *o)
  {
    if ( o == Py_None )
      return 0;
    TWidget *widget = NULL;
    int cvt = SWIG_ConvertPtr(o, (void **) &widget, SWIGTYPE_p_TWidget, 0);
    if ( !SWIG_IsOK(cvt) || widget == NULL )
      return 0;
    return ssize_t(widget);
  }

  // hookgenUI:methods
virtual void range() {}
virtual void idcstart() {}
virtual void idcstop() {}
virtual void suspend() {}
virtual void resume() {}
virtual void saving() {}
virtual void saved() {}
virtual void term() {}
virtual int debugger_menu_change(bool enable) {qnotused(enable); return 1;}
virtual void widget_visible(TWidget * widget) {qnotused(widget); }
virtual void widget_closing(TWidget * widget) {qnotused(widget); }
virtual void widget_invisible(TWidget * widget) {qnotused(widget); }
virtual PyObject * get_ea_hint(ea_t ea) {qnotused(ea); Py_RETURN_NONE;}
virtual PyObject * get_item_hint(ea_t ea, int max_lines) {qnotused(ea); qnotused(max_lines); Py_RETURN_NONE;}
virtual PyObject * get_custom_viewer_hint(TWidget* viewer, place_t * place) {qnotused(viewer); qnotused(place); Py_RETURN_NONE;}
virtual void database_inited(int is_new_database, const char * idc_script) {qnotused(is_new_database); qnotused(idc_script); }
virtual void ready_to_run() {}
virtual void preprocess_action(const char * name) {qnotused(name); }
virtual void postprocess_action() {}
virtual void get_chooser_item_attrs(const chooser_base_t * chooser, size_t n, chooser_item_attrs_t * attrs) {qnotused(chooser); qnotused(n); qnotused(attrs); }
virtual void updating_actions(action_update_ctx_t * ctx) {qnotused(ctx); }
virtual void updated_actions() {}
virtual void populating_widget_popup(TWidget * widget, TPopupMenu * popup_handle, const action_activation_ctx_t * ctx=NULL) {qnotused(widget); qnotused(popup_handle); qnotused(ctx); }
virtual void finish_populating_widget_popup(TWidget * widget, TPopupMenu * popup_handle, const action_activation_ctx_t * ctx=NULL) {qnotused(widget); qnotused(popup_handle); qnotused(ctx); }
virtual void plugin_loaded(const plugin_info_t * plugin_info) {qnotused(plugin_info); }
virtual void plugin_unloading(const plugin_info_t * plugin_info) {qnotused(plugin_info); }
virtual void current_widget_changed(TWidget * widget, TWidget * prev_widget) {qnotused(widget); qnotused(prev_widget); }
virtual void screen_ea_changed(ea_t ea, ea_t prev_ea) {qnotused(ea); qnotused(prev_ea); }
virtual PyObject * create_desktop_widget(const char * title, jobj_wrapper_t cfg) {qnotused(title); qnotused(cfg); Py_RETURN_NONE;}
};

//-------------------------------------------------------------------------
bool py_register_action(action_desc_t *desc)
{
  desc->flags |= ADF_OWN_HANDLER;
  bool ok = register_action(*desc);
  if ( ok )
  {
    // Let's set this to NULL, so when the wrapping Python action_desc_t
    // instance is deleted, it doesn't try to delete the handler (See
    // kernwin.i's action_desc_t::~action_desc_t()).
    desc->handler = NULL;
  }
  return ok;
}

//-------------------------------------------------------------------------
PyObject *py_get_registered_actions()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t actions;
  get_registered_actions(&actions);
  return qstrvec2pylist(actions);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def py_attach_dynamic_action_to_popup(
        widget,
        popup_handle,
        desc,
        popuppath = None,
        flags = 0)
    """
    Create & insert an action into the widget's popup menu
    (::ui_attach_dynamic_action_to_popup).
    Note: The action description in the 'desc' parameter is modified by
          this call so you should prepare a new description for each call.
    For example:
        desc = idaapi.action_desc_t(None, 'Dynamic popup action', Handler())
        idaapi.attach_dynamic_action_to_popup(form, popup, desc)

    @param widget:       target widget
    @param popup_handle: target popup
    @param desc:         action description of type action_desc_t
    @param popuppath:    can be None
    @param flags:        a combination of SETMENU_ constants
    @return: success
    """
    pass
#</pydoc>
*/
bool py_attach_dynamic_action_to_popup(
        TWidget *widget,
        TPopupMenu *popup_handle,
        action_desc_t *desc,
        const char *popuppath = NULL,
        int flags = 0)
{
  bool ok = attach_dynamic_action_to_popup(
          widget, popup_handle, *desc, popuppath, flags);
  if ( ok )
    // Set the handler to null, so the desc won't destroy
    // it, as it noticed ownership was taken by IDA.
    // In addition, we don't need to register into the
    // 'py_action_handlers', because IDA will destroy the
    // handler as soon as the popup menu is closed.
    desc->handler = NULL;
  return ok;
}

// This is similar to a twinline_t, with improved memory management:
// twinline_t has a dummy destructor, that performs no cleanup.
struct disasm_line_t
{
  disasm_line_t() : at(NULL) {}
  ~disasm_line_t() { qfree(at); }
  disasm_line_t(const disasm_line_t &other) { *this = other; }
  disasm_line_t &operator=(const disasm_line_t &other)
  {
    qfree(at);
    at = other.at == NULL ? NULL : other.at->clone();
    return *this;
  }
  place_t *at;
  qstring line;
  color_t prefix_color;
  bgcolor_t bg_color;
  bool is_default;
};
DECLARE_TYPE_AS_MOVABLE(disasm_line_t);
typedef qvector<disasm_line_t> disasm_text_t;

//-------------------------------------------------------------------------
void py_gen_disasm_text(disasm_text_t &text, ea_t ea1, ea_t ea2, bool truncate_lines)
{
  text_t _text;
  gen_disasm_text(_text, ea1, ea2, truncate_lines);
  for ( size_t i = 0, n = _text.size(); i < n; ++i )
  {
    twinline_t &tl = _text[i];
    disasm_line_t &dl = text.push_back();
    dl.at = tl.at;           // Transfer ownership
    dl.line.swap(tl.line);   // Transfer ownership
  }
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def set_nav_colorizer(callback):
    """
    Set a new colorizer for the navigation band.

    The 'callback' is a function of 2 arguments:
       - ea (the EA to colorize for)
       - nbytes (the number of bytes at that EA)
    and must return a 'long' value.

    The previous colorizer is returned, allowing
    the new 'callback' to use 'call_nav_colorizer'
    with it.

    Note that the previous colorizer is returned
    only the first time set_nav_colorizer() is called:
    due to the way the colorizers API is defined in C,
    it is impossible to chain more than 2 colorizers
    in IDAPython: the original, IDA-provided colorizer,
    and a user-provided one.

    Example: colorizer inverting the color provided by the IDA colorizer:
        def my_colorizer(ea, nbytes):
            global ida_colorizer
            orig = idaapi.call_nav_colorizer(ida_colorizer, ea, nbytes)
            return long(~orig)

        ida_colorizer = idaapi.set_nav_colorizer(my_colorizer)
    """
    pass
#</pydoc>
*/
nav_colorizer_t *py_set_nav_colorizer(PyObject *new_py_colorizer)
{
  static ref_t py_colorizer;
  struct ida_local lambda_t
  {
    static uint32 idaapi call_py_colorizer(ea_t ea, asize_t nbytes)
    {
      PYW_GIL_GET;

      if ( py_colorizer == NULL ) // Shouldn't happen.
        return 0;
      newref_t pyres = PyObject_CallFunction(
              py_colorizer.o, "KK",
              (unsigned long long) ea,
              (unsigned long long) nbytes);
      PyW_ShowCbErr("nav_colorizer");
      if ( pyres.o == NULL )
        return 0;
      if ( !PyLong_Check(pyres.o) )
      {
        static bool warned = false;
        if ( !warned )
        {
          msg("WARNING: set_nav_colorizer() callback must return a 'long'.\n");
          warned = true;
        }
        return 0;
      }
      return PyLong_AsLong(pyres.o);
    }
  };

  // Always perform the call to set_nav_colorizer(): that has side-effects
  // (e.g., updating the legend.)
  bool first_install = py_colorizer == NULL;
  py_colorizer = borref_t(new_py_colorizer);
  nav_colorizer_t *prev = set_nav_colorizer(lambda_t::call_py_colorizer);
  return first_install ? prev : NULL;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def call_nav_colorizer(colorizer, ea, nbytes):
    """
    To be used with the IDA-provided colorizer, that is
    returned as result of the first call to set_nav_colorizer().

    This is a trivial trampoline, so that SWIG can generate a
    wrapper that will do the types checking.
    """
    pass
#</pydoc>
*/
uint32 py_call_nav_colorizer(
        nav_colorizer_t *col,
        ea_t ea,
        asize_t nbytes)
{
  return col(ea, nbytes);
}

PyObject *py_msg_get_lines(int count=-1)
{
  qstrvec_t lines;
  msg_get_lines(&lines, count);
  return qstrvec2pylist(lines);
}

/*
#<pydoc>
def msg(message):
    """
    Display an UTF-8 string in the message window

    The result of the stringification of the arguments
    will be treated as an UTF-8 string.

    @param message: message to print (formatting is done in Python)

    This function can be used to debug IDAPython scripts
    """
    pass

def warning(message):
    """
    Display a message in a message box

    @param message: message to print (formatting is done in Python)

    This function can be used to debug IDAPython scripts
    The user will be able to hide messages if they appear twice in a row on
    the screen
    """
    pass

def error(format):
    """
    Display a fatal message in a message box and quit IDA

    @param format: message to print
    """
    pass
#</pydoc>
*/

static TWidget *TWidget__from_ptrval__(size_t ptrval)
{
  return (TWidget *) ptrval;
}

//</inline(py_kernwin)>
%}

%{
//<code(py_kernwin)>
//---------------------------------------------------------------------------
ssize_t idaapi UI_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  UI_Hooks *proxy = (UI_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( notification_code )
    {
      // hookgenUI:notifications
case ui_range:
{
  proxy->range();
}
break;

case ui_idcstart:
{
  proxy->idcstart();
}
break;

case ui_idcstop:
{
  proxy->idcstop();
}
break;

case ui_suspend:
{
  proxy->suspend();
}
break;

case ui_resume:
{
  proxy->resume();
}
break;

case ui_saving:
{
  proxy->saving();
}
break;

case ui_saved:
{
  proxy->saved();
}
break;

case ui_term:
{
  proxy->term();
}
break;

case ui_debugger_menu_change:
{
  bool enable = bool(va_arg(va, int));
  ret = proxy->debugger_menu_change(enable);
}
break;

case ui_widget_visible:
{
  TWidget * widget = va_arg(va, TWidget *);
  proxy->widget_visible(widget);
}
break;

case ui_widget_closing:
{
  TWidget * widget = va_arg(va, TWidget *);
  proxy->widget_closing(widget);
}
break;

case ui_widget_invisible:
{
  TWidget * widget = va_arg(va, TWidget *);
  proxy->widget_invisible(widget);
}
break;

case ui_get_ea_hint:
{
  qstring * buf = va_arg(va, qstring *);
  ea_t ea = va_arg(va, ea_t);
  PyObject * _tmp = proxy->get_ea_hint(ea);
  ret = UI_Hooks::handle_get_ea_hint_output(_tmp, buf, ea);
}
break;

case ui_get_item_hint:
{
  qstring * hint = va_arg(va, qstring *);
  ea_t ea = va_arg(va, ea_t);
  int max_lines = va_arg(va, int);
  int * important_lines = va_arg(va, int *);
  PyObject * _tmp = proxy->get_item_hint(ea, max_lines);
  ret = UI_Hooks::handle_hint_output(_tmp, hint, ea, max_lines, important_lines);
}
break;

case ui_get_custom_viewer_hint:
{
  qstring * hint = va_arg(va, qstring *);
  TWidget* viewer = va_arg(va, TWidget*);
  place_t * place = va_arg(va, place_t *);
  int * important_lines = va_arg(va, int *);
  PyObject * _tmp = proxy->get_custom_viewer_hint(viewer, place);
  ret = UI_Hooks::handle_hint_output(_tmp, hint, viewer, place, important_lines);
}
break;

case ui_database_inited:
{
  int is_new_database = va_arg(va, int);
  const char * idc_script = va_arg(va, const char *);
  proxy->database_inited(is_new_database, idc_script);
}
break;

case ui_ready_to_run:
{
  proxy->ready_to_run();
}
break;

case ui_preprocess_action:
{
  const char * name = va_arg(va, const char *);
  proxy->preprocess_action(name);
}
break;

case ui_postprocess_action:
{
  proxy->postprocess_action();
}
break;

case ui_get_chooser_item_attrs:
{
  const chooser_base_t * chooser = va_arg(va, const chooser_base_t *);
  size_t n = va_arg(va, size_t);
  chooser_item_attrs_t * attrs = va_arg(va, chooser_item_attrs_t *);
  proxy->get_chooser_item_attrs(chooser, n, attrs);
}
break;

case ui_updating_actions:
{
  action_update_ctx_t * ctx = va_arg(va, action_update_ctx_t *);
  proxy->updating_actions(ctx);
}
break;

case ui_updated_actions:
{
  proxy->updated_actions();
}
break;

case ui_populating_widget_popup:
{
  TWidget * widget = va_arg(va, TWidget *);
  TPopupMenu * popup_handle = va_arg(va, TPopupMenu *);
  const action_activation_ctx_t * ctx = va_arg(va, const action_activation_ctx_t *);
  proxy->populating_widget_popup(widget, popup_handle, ctx);
}
break;

case ui_finish_populating_widget_popup:
{
  TWidget * widget = va_arg(va, TWidget *);
  TPopupMenu * popup_handle = va_arg(va, TPopupMenu *);
  const action_activation_ctx_t * ctx = va_arg(va, const action_activation_ctx_t *);
  proxy->finish_populating_widget_popup(widget, popup_handle, ctx);
}
break;

case ui_plugin_loaded:
{
  const plugin_info_t * plugin_info = va_arg(va, const plugin_info_t *);
  proxy->plugin_loaded(plugin_info);
}
break;

case ui_plugin_unloading:
{
  const plugin_info_t * plugin_info = va_arg(va, const plugin_info_t *);
  proxy->plugin_unloading(plugin_info);
}
break;

case ui_current_widget_changed:
{
  TWidget * widget = va_arg(va, TWidget *);
  TWidget * prev_widget = va_arg(va, TWidget *);
  proxy->current_widget_changed(widget, prev_widget);
}
break;

case ui_screen_ea_changed:
{
  ea_t ea = va_arg(va, ea_t);
  ea_t prev_ea = va_arg(va, ea_t);
  proxy->screen_ea_changed(ea, prev_ea);
}
break;

case ui_create_desktop_widget:
{
  const char * title = va_arg(va, const char *);
  const jobj_t * cfg = va_arg(va, const jobj_t *);
  PyObject * _tmp = proxy->create_desktop_widget(title, UI_Hooks::wrap_widget_cfg(cfg));
  ret = UI_Hooks::handle_create_desktop_widget_output(_tmp);
}
break;

    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in UI Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
}

//------------------------------------------------------------------------
bool idaapi py_menu_item_callback(void *userdata)
{
  PYW_GIL_GET;

  // userdata is a tuple of ( func, args )
  // func and args are borrowed references from userdata
  PyObject *o = (PyObject *) userdata;
  if ( !PyTuple_Check(o) )
    return false;

  PyObject *func = PyTuple_GetItem(o, 0);
  PyObject *args = PyTuple_GetItem(o, 1);

  // Call the python function
  newref_t result(PyEval_CallObject(func, args));

  // We cannot raise an exception in the callback, just print it.
  if ( result == NULL )
  {
    PyErr_Print();
    return false;
  }

  return PyObject_IsTrue(result.o) != 0;
}

/*
#<pydoc>
def get_navband_pixel(ea):
    """
    Maps an address, onto a pixel coordinate within the navband

    @param ea: The address to map
    @return: a list [pixel, is_vertical]
    """
    pass
#</pydoc>
*/

//</code(py_kernwin)>
%}

// CLI
%ignore cli_t;
%ignore install_command_interpreter;
%rename (install_command_interpreter) py_install_command_interpreter;
%ignore remove_command_interpreter;
%rename (remove_command_interpreter) py_remove_command_interpreter;

//<typemaps(kernwin)>
%typemap(check) (const  place_t  * tmplate, int flags, const  plugin_t  * owner)
{
if ( $3 == NULL )
  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$3_type'");
}
%typemap(check) (char * str, size_t bufsize, ssize_t len)
{
if ( $1 == NULL )
  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$1_type'");
}
//</typemaps(kernwin)>

%include "kernwin.hpp"

%uncomparable_elements_qvector(disasm_line_t, disasm_text_t);

%extend action_desc_t {
  action_desc_t(
          const char *name,
          const char *label,
          PyObject *handler,
          const char *shortcut = NULL,
          const char *tooltip = NULL,
          int icon = -1,
          int flags = 0)
  {
    action_desc_t *ad = new action_desc_t();
#define DUPSTR(Prop) ad->Prop = Prop == NULL ? NULL : qstrdup(Prop)
    DUPSTR(name);
    DUPSTR(label);
    DUPSTR(shortcut);
    DUPSTR(tooltip);
#undef DUPSTR
    ad->icon = icon;
    ad->handler = new py_action_handler_t(handler);
    ad->flags = flags | ADF_OWN_HANDLER;
    ad->owner = &PLUGIN;
    return ad;
  }

  ~action_desc_t()
  {
    if ( $self->handler != NULL ) // Ownership not taken?
      delete $self->handler;
#define FREESTR(Prop) qfree((char *) $self->Prop)
    FREESTR(name);
    FREESTR(label);
    FREESTR(shortcut);
    FREESTR(tooltip);
#undef FREESTR
    delete $self;
  }
}

%extend action_ctx_base_t {

#ifdef BC695
  TWidget *_get_form() const { return $self->widget; }
  twidget_type_t _get_form_type() const { return $self->widget_type; }
  qstring _get_form_title() const { return $self->widget_title; }
#endif

  %pythoncode {
#ifdef BC695
    form = property(_get_form)
    form_type = property(_get_form_type)
    form_title = property(_get_form_title)
#endif
  }
}

//-------------------------------------------------------------------------
%extend place_t {
  static idaplace_t *as_idaplace_t(place_t *p) { return (idaplace_t *) p; }
  static enumplace_t *as_enumplace_t(place_t *p) { return (enumplace_t *) p; }
  static structplace_t *as_structplace_t(place_t *p) { return (structplace_t *) p; }
  static simpleline_place_t *as_simpleline_place_t(place_t *p) { return (simpleline_place_t *) p; }

  PyObject *py_generate(void *ud, int maxsize)
  {
    qstrvec_t lines;
    int deflnnum = 0;
    color_t pfx_color = 0;
    bgcolor_t bgcolor = DEFCOLOR;
    int generated = $self->generate(&lines, &deflnnum, &pfx_color, &bgcolor, ud, maxsize);
    PyObject *tuple = PyTuple_New(4);
    PyTuple_SetItem(tuple, 0, qstrvec2pylist(lines));
    PyTuple_SetItem(tuple, 1, PyLong_FromLong(deflnnum));
    PyTuple_SetItem(tuple, 2, PyLong_FromLong(uchar(pfx_color)));
    PyTuple_SetItem(tuple, 3, PyLong_FromLong(bgcolor));
    return tuple;
  }
}

%extend twinpos_t {

  %pythoncode {
    def place_as_idaplace_t(self):
        return place_t.as_idaplace_t(self.at)
    def place_as_enumplace_t(self):
        return place_t.as_enumplace_t(self.at)
    def place_as_structplace_t(self):
        return place_t.as_structplace_t(self.at)
    def place_as_simpleline_place_t(self):
        return place_t.as_simpleline_place_t(self.at)

    def place(self, view):
        ptype = get_viewer_place_type(view)
        if ptype == TCCPT_IDAPLACE:
            return self.place_as_idaplace_t()
        elif ptype == TCCPT_ENUMPLACE:
            return self.place_as_enumplace_t()
        elif ptype == TCCPT_STRUCTPLACE:
            return self.place_as_structplace_t()
        elif ptype == TCCPT_SIMPLELINE_PLACE:
            return self.place_as_simpleline_place_t()
        else:
            return self.at
  }
}

%pythoncode %{
#<pycode(py_kernwin)>
DP_LEFT           = 0x0001
DP_TOP            = 0x0002
DP_RIGHT          = 0x0004
DP_BOTTOM         = 0x0008
DP_INSIDE         = 0x0010
# if not before, then it is after
# (use DP_INSIDE | DP_BEFORE to insert a tab before a given tab)
# this flag alone cannot be used to determine orientation
DP_BEFORE         = 0x0020
# used with combination of other flags
DP_TAB            = 0x0040
DP_FLOATING       = 0x0080

# ----------------------------------------------------------------------
def load_custom_icon(file_name=None, data=None, format=None):
    """
    Loads a custom icon and returns an identifier that can be used with other APIs

    If file_name is passed then the other two arguments are ignored.

    @param file_name: The icon file name
    @param data: The icon data
    @param format: The icon data format

    @return: Icon id or 0 on failure.
             Use free_custom_icon() to free it
    """
    if file_name is not None:
       return _ida_kernwin.py_load_custom_icon_fn(file_name)
    elif not (data is None and format is None):
       return _ida_kernwin.py_load_custom_icon_data(data, format)
    else:
      return 0

# ----------------------------------------------------------------------
def ask_long(defval, format):
    res, val = _ida_kernwin._ask_long(defval, format)

    if res == 1:
        return val
    else:
        return None

# ----------------------------------------------------------------------
def ask_addr(defval, format):
    res, ea = _ida_kernwin._ask_addr(defval, format)

    if res == 1:
        return ea
    else:
        return None

# ----------------------------------------------------------------------
def ask_seg(defval, format):
    res, sel = _ida_kernwin._ask_seg(defval, format)

    if res == 1:
        return sel
    else:
        return None

# ----------------------------------------------------------------------
def ask_ident(defval, format):
    return ask_str(defval, HIST_IDENT, format)

# ----------------------------------------------------------------------
class action_handler_t(object):
    def __init__(self):
        pass

    def activate(self, ctx):
        return 0

    def update(self, ctx):
        pass

# ----------------------------------------------------------------------
# bw-compat/deprecated. You shouldn't rely on this in new code
from ida_pro import str2user

#</pycode(py_kernwin)>
%}

//-------------------------------------------------------------------------
//                                Choose
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_choose)>

//------------------------------------------------------------------------
// Helper functions
class py_choose_t;
typedef std::map<PyObject *, py_choose_t *> py2c_choose_map_t;
static py2c_choose_map_t choosers;

py_choose_t *choose_find_instance(PyObject *self)
{
  py2c_choose_map_t::iterator it = choosers.find(self);
  return it == choosers.end() ? NULL : it->second;
}

void choose_add_instance(PyObject *self, py_choose_t *pych)
{
  choosers[self] = pych;
}

void choose_del_instance(PyObject *self)
{
  py2c_choose_map_t::iterator it = choosers.find(self);
  if ( it != choosers.end() )
    choosers.erase(it);
}

// set `prm` to the integer value of the `name` attribute
template <class T>
static void py_get_int(PyObject *self, T *prm, const char *name)
{
  ref_t attr(PyW_TryGetAttrString(self, name));
  if ( attr != NULL && attr.o != Py_None )
    *prm = T(IDAPyInt_AsLong(attr.o));
}

//------------------------------------------------------------------------
// Python's chooser class
class py_choose_t
{
public:
  // Python object link
  PyObject *self;

  // the chooser object will be created in the create() method
  chooser_base_t *chobj;

  enum
  {
    CHOOSE_HAVE_INIT      = 0x0001,
    CHOOSE_HAVE_GETICON   = 0x0002,
    CHOOSE_HAVE_GETATTR   = 0x0004,
    CHOOSE_HAVE_INS       = 0x0008,
    CHOOSE_HAVE_DEL       = 0x0010,
    CHOOSE_HAVE_EDIT      = 0x0020,
    CHOOSE_HAVE_ENTER     = 0x0040,
    CHOOSE_HAVE_REFRESH   = 0x0080,
    CHOOSE_HAVE_SELECT    = 0x0100,
    CHOOSE_HAVE_ONCLOSE   = 0x0200,
    CHOOSE_IS_EMBEDDED    = 0x0400,
  };

  // Callback flags (to tell which callback exists and which not)
  // One of CHOOSE_xxxx
  uint32 cb_flags;

  // Chooser title
  qstring title;

  // Column widths
  intvec_t widths;

  // Chooser headers
  qstrvec_t header_strings;
  qvector<const char *> header;

public:
  py_choose_t(PyObject *self_) : self(self_), chobj(NULL), cb_flags(0)
  {
    PYW_GIL_GET;
    choose_add_instance(self, this);

    // Increase object reference
    Py_INCREF(self);
  }

  // if the chooser object was created it will delete linked Python's
  // chooser.
  // if it was not created (e.g. because of the lack of a mandatory
  // callback) it will be deleted in choose_close().
  ~py_choose_t()
  {
    PYW_GIL_GET;
    // Remove from list
    choose_del_instance(self);

    Py_XDECREF(self);
  }

  // common callbacks
  bool idaapi init()
  {
    if ( (cb_flags & CHOOSE_HAVE_INIT) == 0 )
      return chobj->chooser_base_t::init();
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self, (char *)S_ON_INIT, NULL));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chobj->chooser_base_t::init();
    return bool(IDAPyInt_AsLong(pyres.result.o));
  }

  size_t idaapi get_count() const
  {
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self, (char *)S_ON_GET_SIZE, NULL));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return 0;

    return size_t(IDAPyInt_AsLong(pyres.result.o));
  }

  void idaapi get_row(
          qstrvec_t *cols,
          int *icon_,
          chooser_item_attrs_t *attrs,
          size_t n) const
  {
    PYW_GIL_GET;

    // Call Python
    PYW_GIL_CHECK_LOCKED_SCOPE();
    pycall_res_t list(
            PyObject_CallMethod(
                    self, (char *)S_ON_GET_LINE,
                    "i", int(n)));
    if ( list.result != NULL )
    {
      // Go over the List returned by Python and convert to C strings
      for ( int i = chobj->columns - 1; i >= 0; --i )
      {
        borref_t item(PyList_GetItem(list.result.o, Py_ssize_t(i)));
        if ( item == NULL )
          continue;

        const char *str = IDAPyBytes_AsString(item.o);
        if ( str != NULL )
          (*cols)[i] = str;
      }
    }

    *icon_ = chobj->icon;
    if ( (cb_flags & CHOOSE_HAVE_GETICON) != 0 )
    {
      pycall_res_t pyres(
              PyObject_CallMethod(
                      self, (char *)S_ON_GET_ICON,
                      "i", int(n)));
      if ( pyres.result != NULL )
        *icon_ = IDAPyInt_AsLong(pyres.result.o);
    }

    if ( (cb_flags & CHOOSE_HAVE_GETATTR) != 0 )
    {
      pycall_res_t pyres(
              PyObject_CallMethod(
                      self, (char *)S_ON_GET_LINE_ATTR,
                      "i", int(n)));
      if ( pyres.result != NULL && PyList_Check(pyres.result.o) )
      {
        PyObject *item;
        if ( (item = PyList_GetItem(pyres.result.o, 0)) != NULL )
          attrs->color = IDAPyInt_AsLong(item);
        if ( (item = PyList_GetItem(pyres.result.o, 1)) != NULL )
          attrs->flags = IDAPyInt_AsLong(item);
      }
    }
  }

  void idaapi closed()
  {
    if ( (cb_flags & CHOOSE_HAVE_ONCLOSE) == 0 )
    {
      chobj->chooser_base_t::closed();
      return;
    }
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(self, (char *)S_ON_CLOSE, NULL));
    // delete UI hook
    PyObject_DelAttrString(self, "ui_hooks_trampoline");
  }

public:
  static py_choose_t *find_chooser(const char *title)
  {
    return static_cast<py_choose_t *>(::get_chooser_obj(title));
  }

  void close()
  {
    // will trigger closed()
    close_chooser(chobj->title);
  }

  bool activate()
  {
    TWidget *widget = get_widget();
    if ( widget == NULL )
      return false;

    activate_widget(widget, true);
    return true;
  }

  TWidget *get_widget()
  {
    return find_widget(chobj->title);
  }

  // Create a chooser.
  // If it doesn't detect the "embedded" attribute, then the chooser window
  // is created and displayed.
  // See ::choose() for the returned values.
  // \retval NO_ATTR  some mandatory attribute is missing
  int create();

  inline PyObject *get_self()
  {
    return self;
  }

  void do_refresh()
  {
    refresh_chooser(chobj->title);
  }

  chooser_base_t *get_chobj() const
  {
    return chobj;
  }

  bool is_valid() const
  {
    return chobj != NULL;
  }

  bool is_embedded() const
  {
    return (cb_flags & CHOOSE_IS_EMBEDDED) != 0;
  }
};

//------------------------------------------------------------------------
// link from the chooser object to the Python's chooser
struct py_chooser_link_t
{
  py_choose_t *link;  // link to Python's chooser
  py_chooser_link_t(py_choose_t *pych) : link(pych) {}
  ~py_chooser_link_t() { delete link; }
};

//------------------------------------------------------------------------
// we do not use virtual subclasses so we use #define for common code
#define DEFINE_COMMON_CALLBACKS                                         \
  virtual void *get_chooser_obj() ida_override { return link; }         \
  virtual bool idaapi init() ida_override { return link->init(); }      \
  virtual size_t idaapi get_count() const ida_override                  \
  {                                                                     \
    return link->get_count();                                           \
  }                                                                     \
  virtual void idaapi get_row(                                          \
          qstrvec_t *cols,                                              \
          int *icon_,                                                   \
          chooser_item_attrs_t *attrs,                                  \
          size_t n) const ida_override                                  \
  {                                                                     \
    link->get_row(cols, icon_, attrs, n);                               \
  }                                                                     \
  virtual void idaapi closed() ida_override { link->closed(); }

//------------------------------------------------------------------------
// chooser class without multi-selection
class py_chooser_single_t
  : public py_chooser_link_t,
    public chooser_t
{
public:
  py_chooser_single_t(
          py_choose_t *pych,
          uint32 flags_ = 0,
          int columns_ = 0,
          const int *widths_ = NULL,
          const char *const *header_ = NULL,
          const char *title_ = NULL)
    : py_chooser_link_t(pych),
      chooser_t(flags_, columns_, widths_, header_, title_) {}

  DEFINE_COMMON_CALLBACKS

  virtual cbret_t idaapi ins(ssize_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_INS) == 0 )
      return chooser_t::ins(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_INSERT_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::ins(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi del(size_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_DEL) == 0 )
      return chooser_t::del(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_DELETE_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::del(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi edit(size_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_EDIT) == 0 )
      return chooser_t::edit(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_EDIT_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::edit(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi enter(size_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_ENTER) == 0 )
      return chooser_t::enter(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECT_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::enter(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi refresh(ssize_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_REFRESH) == 0 )
      return chooser_t::refresh(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_REFRESH,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::refresh(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual void idaapi select(ssize_t n) const ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_SELECT) == 0 )
    {
      chooser_t::select(n);
      return;
    }
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECTION_CHANGE,
                    "i", int(n)));
  }

protected:
  // [ changed, idx ]
  static cbret_t py_as_cbret(PyObject *py_ret)
  {
    cbret_t ret;
    if ( PySequence_Check(py_ret) )
    {
      {
        newref_t item(PySequence_GetItem(py_ret, 0));
        if ( item.o != NULL && IDAPyInt_Check(item.o) )
          ret.changed = cbres_t(IDAPyInt_AsLong(item.o));
      }
      if ( ret.changed != NOTHING_CHANGED )
      {
        newref_t item(PySequence_GetItem(py_ret, 1));
        if ( item.o != NULL && IDAPyInt_Check(item.o) )
          ret.idx = ssize_t(IDAPyInt_AsSsize_t(item.o));
      }
    }
    return ret;
  }
};

//------------------------------------------------------------------------
// chooser class with multi-selection
class py_chooser_multi_t
  : public py_chooser_link_t,
    public chooser_multi_t
{
public:
  py_chooser_multi_t(
          py_choose_t *pych,
          uint32 flags_ = 0,
          int columns_ = 0,
          const int *widths_ = NULL,
          const char *const *header_ = NULL,
          const char *title_ = NULL)
    : py_chooser_link_t(pych),
      chooser_multi_t(flags_, columns_, widths_, header_, title_) {}

  DEFINE_COMMON_CALLBACKS

  virtual cbres_t idaapi ins(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_INS) == 0 )
      return chooser_multi_t::ins(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_INSERT_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::ins(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi del(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_DEL) == 0 )
      return chooser_multi_t::del(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_DELETE_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::del(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi edit(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_EDIT) == 0 )
      return chooser_multi_t::edit(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_EDIT_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::edit(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi enter(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_ENTER) == 0 )
      return chooser_multi_t::enter(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECT_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::enter(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi refresh(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_REFRESH) == 0 )
      return chooser_multi_t::refresh(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_REFRESH,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::refresh(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual void idaapi select(const sizevec_t &sel) const ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_SELECT) == 0 )
    {
      chooser_multi_t::select(sel);
      return;
    }
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECTION_CHANGE,
                    "O", py_list.o));
  }

protected:
  // [ changed, idx, ... ]
  static cbres_t py_as_cbres_sel(sizevec_t *sel, PyObject *py_ret)
  {
    // this is an easy but not an optimal way of converting
    if ( !PySequence_Check(py_ret)
      || PyW_PyListToSizeVec(sel, py_ret) <= 0 )
    {
      sel->clear();
      return NOTHING_CHANGED;
    }
    cbres_t res = cbres_t(sel->front());
    sel->erase(sel->begin());
    return res;
  }
};

//------------------------------------------------------------------------
int py_choose_t::create()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Get flags
  uint32 flags;
  ref_t flags_attr(PyW_TryGetAttrString(self, S_FLAGS));
  if ( flags_attr == NULL )
    return chooser_base_t::NO_ATTR;
  if ( IDAPyInt_Check(flags_attr.o) )
    flags = uint32(IDAPyInt_AsLong(flags_attr.o));
  // instruct TChooser destructor to delete this chooser when window
  // closes
  flags &= ~CH_KEEP;

  // Get the title
  if ( !PyW_GetStringAttr(self, S_TITLE, &title) )
    return chooser_base_t::NO_ATTR;

  // Get columns
  ref_t cols_attr(PyW_TryGetAttrString(self, "cols"));
  if ( cols_attr == NULL )
    return chooser_base_t::NO_ATTR;

  // Get col count
  int columns = int(PyList_Size(cols_attr.o));
  if ( columns < 1 )
    return chooser_base_t::NO_ATTR;

  // Get columns caption and widthes
  header_strings.resize(columns);
  header.resize(columns);
  widths.resize(columns);
  for ( int i = 0; i < columns; ++i )
  {
    // get list item: [name, width]
    borref_t list(PyList_GetItem(cols_attr.o, i));
    borref_t v(PyList_GetItem(list.o, 0));

    // Extract string
    const char *str = v == NULL ? "" : IDAPyBytes_AsString(v.o);
    header_strings[i] = str;
    header[i] = header_strings[i].c_str();

    // Extract width
    int width;
    borref_t v2(PyList_GetItem(list.o, 1));
    // No width? Guess width from column title
    if ( v2 == NULL )
      width = strlen(str);
    else
      width = IDAPyInt_AsLong(v2.o);
    widths[i] = width;
  }

  // Check what callbacks we have
  static const struct
  {
    const char *name;
    unsigned int have; // 0 = mandatory callback
    int chooser_t_flags;
  } callbacks[] =
  {
    { S_ON_INIT,             CHOOSE_HAVE_INIT,    0 },
    { S_ON_GET_SIZE,         0 },
    { S_ON_GET_LINE,         0 },
    { S_ON_GET_ICON,         CHOOSE_HAVE_GETICON, 0 },
    { S_ON_GET_LINE_ATTR,    CHOOSE_HAVE_GETATTR, 0 },
    { S_ON_INSERT_LINE,      CHOOSE_HAVE_INS,     CH_CAN_INS },
    { S_ON_DELETE_LINE,      CHOOSE_HAVE_DEL,     CH_CAN_DEL },
    { S_ON_EDIT_LINE,        CHOOSE_HAVE_EDIT,    CH_CAN_EDIT },
    { S_ON_SELECT_LINE,      CHOOSE_HAVE_ENTER,   0 },
    { S_ON_REFRESH,          CHOOSE_HAVE_REFRESH, CH_CAN_REFRESH },
    { S_ON_SELECTION_CHANGE, CHOOSE_HAVE_SELECT,  0 },
    { S_ON_CLOSE,            CHOOSE_HAVE_ONCLOSE, 0 },
  };
  // we can forbid some callbacks explicitly
  uint32 forbidden_cb = 0;
  ref_t forbidden_cb_attr(PyW_TryGetAttrString(self, "forbidden_cb"));
  if ( forbidden_cb_attr != NULL && IDAPyInt_Check(forbidden_cb_attr.o) )
    forbidden_cb = uint32(IDAPyInt_AsLong(forbidden_cb_attr.o));
  cb_flags = 0;
  for ( int i = 0; i < qnumber(callbacks); ++i )
  {
    ref_t cb_attr(PyW_TryGetAttrString(self, callbacks[i].name));
    bool have_cb = cb_attr != NULL && PyCallable_Check(cb_attr.o);
    if ( have_cb && (forbidden_cb & callbacks[i].have) == 0 )
    {
      cb_flags |= callbacks[i].have;
      flags |= callbacks[i].chooser_t_flags;
    }
    else
    {
      // Mandatory field?
      if ( callbacks[i].have == 0 )
        return chooser_base_t::NO_ATTR;
    }
  }

  // create chooser object
  if ( (flags & CH_MULTI) == 0 )
  {
    chobj = new py_chooser_single_t(
                        this,
                        flags,
                        columns, widths.begin(), header.begin(),
                        title.c_str());
  }
  else
  {
    chobj = new py_chooser_multi_t(
                        this,
                        flags,
                        columns, widths.begin(), header.begin(),
                        title.c_str());
  }

  // Get *x1,y1,x2,y2
  py_get_int(self, &chobj->x0, "x1");
  py_get_int(self, &chobj->y0, "y1");
  py_get_int(self, &chobj->x1, "x2");
  py_get_int(self, &chobj->y1, "y2");

  // Get *icon
  py_get_int(self, &chobj->icon, "icon");

  // Get *popup names
  // An array of 4 strings: ("Insert", "Delete", "Edit", "Refresh")
  ref_t pn_attr(PyW_TryGetAttrString(self, S_POPUP_NAMES));
  if ( pn_attr != NULL && PyList_Check(pn_attr.o) )
  {
    int npopups = int(PyList_Size(pn_attr.o));
    if ( npopups > chooser_base_t::NSTDPOPUPS )
      npopups = chooser_base_t::NSTDPOPUPS;
    for ( int i = 0; i < npopups; ++i )
    {
      const char *str = IDAPyBytes_AsString(PyList_GetItem(pn_attr.o, i));
      chobj->popup_names[i] = str;
    }
  }

  // Check if *embedded
  ref_t emb_attr(PyW_TryGetAttrString(self, S_EMBEDDED));
  if ( emb_attr != NULL && PyObject_IsTrue(emb_attr.o) == 1 )
  {
    cb_flags |= CHOOSE_IS_EMBEDDED;
    py_get_int(self, &chobj->width, "width");
    py_get_int(self, &chobj->height, "height");
    return 0; // success
  }

  // run
  ssize_t res;
  if ( !chobj->is_multi() )
  {
    // Get *deflt
    ssize_t deflt = 0;
    py_get_int(self, &deflt, "deflt");
    res = ((chooser_t *)chobj)->choose(deflt);
  }
  else
  {
    // Get *deflt
    sizevec_t deflt;
    ref_t deflt_attr(PyW_TryGetAttrString(self, "deflt"));
    if ( deflt_attr != NULL
      && PyList_Check(deflt_attr.o)
      && PyW_PyListToSizeVec(&deflt, deflt_attr.o) < 0 )
    {
      deflt.clear();
    }
    res = ((chooser_multi_t *)chobj)->choose(deflt);
  }
  // assert: `this` is deleted in the case of the modal chooser

  return res;
}

//------------------------------------------------------------------------
int choose_create(PyObject *self)
{
  py_choose_t *pych;

  pych = choose_find_instance(self);
  if ( pych != NULL && pych->is_valid() )
  {
    if ( !pych->is_embedded() )
      pych->activate();
    return chooser_base_t::ALREADY_EXISTS;
  }

  if ( pych == NULL )
    pych = new py_choose_t(self);
  // assert: returned value != chooser_base_t::ALREADY_EXISTS
  return pych->create();
}

//------------------------------------------------------------------------
void choose_close(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych == NULL )
    return;

  if ( !pych->is_valid() )
  {
    // the chooser object is not created
    // so we delete Python's chooser ourself
    delete pych;
    return;
  }

  // embedded chooser is deleted by form
  if ( pych->is_embedded() )
    return;

  // modal chooser is closed and deleted in py_choose_t::create()
  // assert: !pych->is_modal()

  // close the non-modal chooser,
  // in turn this will lead to the deletion of the object
  pych->close();
}

//------------------------------------------------------------------------
void choose_refresh(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych != NULL && pych->is_valid() )
    pych->do_refresh();
}

//------------------------------------------------------------------------
void choose_activate(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych != NULL && pych->is_valid() )
    pych->activate();
}

//------------------------------------------------------------------------
// Return the C instance as 64bit number
uint64 _choose_get_embedded_chobj_pointer(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  uint64 ptr = 0;
  py_choose_t *pych = choose_find_instance(self);
  if ( pych != NULL && pych->is_valid() && pych->is_embedded() )
    ptr = uint64(pych->get_chobj());
  return ptr;
}

//------------------------------------------------------------------------
PyObject *choose_find(const char *title)
{
  py_choose_t *pych = py_choose_t::find_chooser(title);
  if ( pych == NULL || !pych->is_valid() )
    Py_RETURN_NONE;
  PyObject *self = pych->get_self();
  Py_INCREF(self);
  return self;
}
//</code(py_kernwin_choose)>
%}

%inline %{
//<inline(py_kernwin_choose)>
PyObject *choose_find(const char *title);
void choose_refresh(PyObject *self);
void choose_close(PyObject *self);
int choose_create(PyObject *self);
void choose_activate(PyObject *self);
uint64 _choose_get_embedded_chobj_pointer(PyObject *self);

PyObject *py_get_chooser_data(const char *chooser_caption, int n)
{
  qstrvec_t data;
  if ( !get_chooser_data(&data, chooser_caption, n) )
    Py_RETURN_NONE;
  PyObject *py_list = PyList_New(data.size());
  for ( size_t i = 0; i < data.size(); ++i )
    PyList_SetItem(py_list, i, IDAPyStr_FromUTF8(data[i].c_str()));
  return py_list;
}

//-------------------------------------------------------------------------
TWidget *choose_get_widget(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych == NULL || !pych->is_valid() )
    return NULL;
  return pych->get_widget();
}

//</inline(py_kernwin_choose)>
%}

%pythoncode %{
#<pycode(py_kernwin_choose)>
class Choose(object):
    """
    Chooser wrapper class.

    Some constants are defined in this class.
    Please refer to kernwin.hpp for more information.
    """

    CH_MODAL        = 0x01
    """Modal chooser"""

    CH_MULTI        = 0x04
    """
    Allow multi selection.
    Refer the description of the OnInsertLine(), OnDeleteLine(),
    OnEditLine(), OnSelectLine(), OnRefresh(), OnSelectionChange() to
    see a difference between single and multi selection callbacks.
    """

    CH_NOBTNS       = 0x10

    CH_ATTRS        = 0x20

    CH_NOIDB        = 0x40
    """use the chooser even without an open database, same as x0=-2"""

    CH_FORCE_DEFAULT = 0x80
    """
    If a non-modal chooser was already open, change selection to the given
    default one
    """

    CH_CAN_INS      = 0x000100
    """allow to insert new items"""

    CH_CAN_DEL      = 0x000200
    """allow to delete existing item(s)"""

    CH_CAN_EDIT     = 0x000400
    """allow to edit existing item(s)"""

    CH_CAN_REFRESH  = 0x000800
    """allow to refresh chooser"""

    CH_QFLT         =  0x1000
    """open with quick filter enabled and focused"""

    CH_QFTYP_SHIFT  = 13
    CH_QFTYP_DEFAULT     = 0 << CH_QFTYP_SHIFT
    CH_QFTYP_NORMAL      = 1 << CH_QFTYP_SHIFT
    CH_QFTYP_WHOLE_WORDS = 2 << CH_QFTYP_SHIFT
    CH_QFTYP_REGEX       = 3 << CH_QFTYP_SHIFT
    CH_QFTYP_FUZZY       = 4 << CH_QFTYP_SHIFT
    CH_QFTYP_MASK        = 0x7 << CH_QFTYP_SHIFT

    CH_NO_STATUS_BAR = 0x00010000
    """don't show a status bar"""
    CH_RESTORE       = 0x00020000
    """restore floating position if present (equivalent of WOPN_RESTORE) (GUI version only)"""

    CH_BUILTIN_SHIFT = 19
    CH_BUILTIN_MASK = 0x1F << CH_BUILTIN_SHIFT

    # column flags (are specified in the widths array)
    CHCOL_PLAIN  =  0x00000000
    CHCOL_PATH   =  0x00010000
    CHCOL_HEX    =  0x00020000
    CHCOL_DEC    =  0x00030000
    CHCOL_FORMAT =  0x00070000

    # special values of the chooser index
    NO_SELECTION   = -1
    """there is no selected item"""
    EMPTY_CHOOSER  = -4
    """the chooser is initialized"""
    ALREADY_EXISTS = -5
    """the non-modal chooser with the same data is already open"""
    NO_ATTR        = -6
    """some mandatory attribute is missing"""

    # return value of ins(), del(), edit(), enter(), refresh() callbacks
    NOTHING_CHANGED   = 0
    ALL_CHANGED       = 1
    SELECTION_CHANGED = 2

    # to construct `forbidden_cb`
    CHOOSE_HAVE_INIT    = 0x0001
    CHOOSE_HAVE_GETICON = 0x0002
    CHOOSE_HAVE_GETATTR = 0x0004
    CHOOSE_HAVE_INS     = 0x0008
    CHOOSE_HAVE_DEL     = 0x0010
    CHOOSE_HAVE_EDIT    = 0x0020
    CHOOSE_HAVE_ENTER   = 0x0040
    CHOOSE_HAVE_REFRESH = 0x0080
    CHOOSE_HAVE_SELECT  = 0x0100
    CHOOSE_HAVE_ONCLOSE = 0x0200

    class UI_Hooks_Trampoline(UI_Hooks):
        def __init__(self, v):
            UI_Hooks.__init__(self)
            self.hook()
            import weakref
            self.v = weakref.ref(v)

        def populating_widget_popup(self, form, popup_handle):
            chooser = self.v()
            if form == chooser.GetWidget() and \
               hasattr(chooser, "OnPopup") and \
               callable(getattr(chooser, "OnPopup")):
                chooser.OnPopup(form, popup_handle)

    def __init__(self, title, cols, flags = 0, popup_names = None,
                 icon=-1, x1=-1, y1=-1, x2=-1, y2=-1,
                 deflt = None,
                 embedded = False, width = None, height = None,
                 forbidden_cb = 0):
        """
        Constructs a chooser window.
        @param title: The chooser title
        @param cols: a list of colums; each list item is a list of two items
            example: [ ["Address", 10 | Choose.CHCOL_HEX],
                       ["Name",    30 | Choose.CHCOL_PLAIN] ]
        @param flags: One of CH_XXXX constants
        @param deflt: The index of the default item (0-based) for single
            selection choosers or the list of indexes for multi selection
            chooser
        @param popup_names: List of new captions to replace this list
            ["Insert", "Delete", "Edit", "Refresh"]
        @param icon: Icon index (the icon should exist in ida resources or
            an index to a custom loaded icon)
        @param x1, y1, x2, y2: The default location (for txt-version)
        @param embedded: Create as embedded chooser
        @param width: Embedded chooser width
        @param height: Embedded chooser height
        @param forbidden_cb: Explicitly forbidden callbacks
        """
        self.title = title
        self.flags = flags
        self.cols = cols
        if deflt == None:
          deflt = 0 if (flags & Choose.CH_MULTI) == 0 else [0]
        self.deflt = deflt
        self.popup_names = popup_names
        self.icon = icon
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2
        self.embedded = embedded
        self.width = width
        self.height = height
        self.forbidden_cb = forbidden_cb
        self.ui_hooks_trampoline = None # set on Show


    def Embedded(self):
        """
        Creates an embedded chooser (as opposed to Show())
        @return: Returns 0 on success or NO_ATTR
        """
        if not self.embedded:
          return Choose.NO_ATTR
        return _ida_kernwin.choose_create(self)


    def GetEmbSelection(self):
        """
        Deprecated. For embedded choosers, the selection is
        available through 'Form.EmbeddedChooserControl.selection'
        """
        return None


    def Show(self, modal=False):
        """
        Activates or creates a chooser window
        @param modal: Display as modal dialog
        @return: For all choosers it will return NO_ATTR if some mandatory
                 attribute is missing. The mandatory attributes are: flags,
                 title, cols, OnGetSize(), OnGetLine();
                 For modal choosers it will return the selected item index (0-based),
                 or NO_SELECTION if no selection,
                 or EMPTY_CHOOSER if the OnRefresh() callback returns EMPTY_CHOOSER;
                 For non-modal choosers it will return 0
                 or ALREADY_EXISTS if the chooser was already open and is active now;
        """
        if self.embedded:
          return Choose.NO_ATTR
        # it will be deleted and unhooked in py_choose_t::closed()
        self.ui_hooks_trampoline = self.UI_Hooks_Trampoline(self)
        if modal:
            self.flags |= Choose.CH_MODAL

            # Disable the timeout
            old = _ida_idaapi.set_script_timeout(0)
            n = _ida_kernwin.choose_create(self)
            _ida_idaapi.set_script_timeout(old)

            # Delete the modal chooser instance
            self.Close()

            return n
        else:
            self.flags &= ~Choose.CH_MODAL
            return _ida_kernwin.choose_create(self)


    def Activate(self):
        """Activates a visible chooser"""
        return _ida_kernwin.choose_activate(self)


    def Refresh(self):
        """Causes the refresh callback to trigger"""
        return _ida_kernwin.choose_refresh(self)


    def Close(self):
        """Closes the chooser"""
        _ida_kernwin.choose_close(self)

    def GetWidget(self):
        """
        Return the TWidget underlying this view.

        @return: The TWidget underlying this view, or None.
        """
        return _ida_kernwin.choose_get_widget(self)

    def adjust_last_item(self, n):
        """
        Helper for OnDeleteLine() and OnRefresh() callbacks.
        They can be finished by the following line:
        return [Choose.ALL_CHANGED] + self.adjust_last_item(n)
        @param: line number of the remaining select item
        @return: list of selected lines numbers (one element or empty)
        """
        cnt = self.OnGetSize();
        if cnt == 0:
            return []
        # take in account deleting of the last item(s)
        if n >= cnt:
            n = cnt - 1
        return [n]
#</pycode(py_kernwin_choose)>
%}

//-------------------------------------------------------------------------
//                               ask_form
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_askform)>
//</code(py_kernwin_askform)>
%}

%inline %{
//<inline(py_kernwin_askform)>
#define DECLARE_FORM_ACTIONS form_actions_t *fa = (form_actions_t *)p_fa;

//---------------------------------------------------------------------------
static bool textctrl_info_t_assign(PyObject *self, PyObject *other)
{
  textctrl_info_t *lhs = textctrl_info_t_get_clink(self);
  textctrl_info_t *rhs = textctrl_info_t_get_clink(other);
  if ( lhs == NULL || rhs == NULL )
    return false;

  *lhs = *rhs;
  return true;
}

//-------------------------------------------------------------------------
static bool textctrl_info_t_set_text(PyObject *self, const char *s)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  if ( ti == NULL )
    return false;
  ti->text = s;
  return true;
}

//-------------------------------------------------------------------------
static const char *textctrl_info_t_get_text(PyObject *self)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  return ti == NULL ? "" : ti->text.c_str();
}

//-------------------------------------------------------------------------
static bool textctrl_info_t_set_flags(PyObject *self, unsigned int flags)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  if ( ti == NULL )
    return false;
  ti->flags = flags;
  return true;
}

//-------------------------------------------------------------------------
static unsigned int textctrl_info_t_get_flags(
        PyObject *self,
        unsigned int flags)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  return ti == NULL ? 0 : ti->flags;
}

//-------------------------------------------------------------------------
static bool textctrl_info_t_set_tabsize(
        PyObject *self,
        unsigned int tabsize)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  if ( ti == NULL )
    return false;
  ti->tabsize = tabsize;
  return true;
}

//-------------------------------------------------------------------------
static unsigned int textctrl_info_t_get_tabsize(
        PyObject *self,
        unsigned int tabsize)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  return ti == NULL ? 0 : ti->tabsize;
}

//---------------------------------------------------------------------------
static bool formchgcbfa_enable_field(size_t p_fa, int fid, bool enable)
{
  DECLARE_FORM_ACTIONS;
  return fa->enable_field(fid, enable);
}

//---------------------------------------------------------------------------
static bool formchgcbfa_show_field(size_t p_fa, int fid, bool show)
{
  DECLARE_FORM_ACTIONS;
  return fa->show_field(fid, show);
}

//---------------------------------------------------------------------------
static bool formchgcbfa_move_field(
        size_t p_fa,
        int fid,
        int x,
        int y,
        int w,
        int h)
{
  DECLARE_FORM_ACTIONS;
  return fa->move_field(fid, x, y, w, h);
}

//---------------------------------------------------------------------------
static int formchgcbfa_get_focused_field(size_t p_fa)
{
  DECLARE_FORM_ACTIONS;
  return fa->get_focused_field();
}

//---------------------------------------------------------------------------
static bool formchgcbfa_set_focused_field(size_t p_fa, int fid)
{
  DECLARE_FORM_ACTIONS;
  return fa->set_focused_field(fid);
}

//---------------------------------------------------------------------------
static void formchgcbfa_refresh_field(size_t p_fa, int fid)
{
  DECLARE_FORM_ACTIONS;
  return fa->refresh_field(fid);
}

//---------------------------------------------------------------------------
static void formchgcbfa_close(size_t p_fa, int close_normally)
{
  DECLARE_FORM_ACTIONS;
  fa->close(close_normally);
}

//---------------------------------------------------------------------------
static PyObject *formchgcbfa_get_field_value(
        size_t p_fa,
        int fid,
        int ft,
        size_t sz)
{
  DECLARE_FORM_ACTIONS;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  switch ( ft )
  {
    // dropdown list
    case 8:
      // Readonly? Then return the selected index
      if ( sz == 1 )
      {
        int sel_idx;
        if ( fa->get_combobox_value(fid, &sel_idx) )
          return PyLong_FromLong(sel_idx);
      }
      // Not readonly? Then return the qstring
      else
      {
        qstring val;
        if ( fa->get_combobox_value(fid, &val) )
          return IDAPyStr_FromUTF8(val.c_str());
      }
      break;

    // multilinetext - tuple representing textctrl_info_t
    case 7:
      {
        textctrl_info_t ti;
        if ( fa->get_text_value(fid, &ti) )
          return Py_BuildValue("(sII)", ti.text.c_str(), ti.flags, ti.tabsize);
        break;
      }
    // button - uint32
    case 4:
      {
        uval_t val;
        if ( fa->get_unsigned_value(fid, &val) )
          return PyLong_FromUnsignedLong(val);
        break;
      }
    // ushort
    case 2:
      {
        ushort val;
        if ( fa->_get_field_value(fid, &val) )
          return PyLong_FromUnsignedLong(val);
        break;
      }
    // string label
    case 1:
      {
        char val[MAXSTR];
        if ( fa->get_string_value(fid, val, sizeof(val)) )
          return IDAPyStr_FromUTF8(val);
        break;
      }
    // string input
    case 3:
      {
        qstring val;
        val.resize(sz + 1);
        if ( fa->get_string_value(fid, val.begin(), val.size()) )
          return IDAPyStr_FromUTF8(val.begin());
        break;
      }
    case 5:
      {
        sizevec_t selection;
        if ( fa->get_chooser_value(fid, &selection) )
        {
          ref_t l(PyW_SizeVecToPyList(selection));
          l.incref();
          return l.o;
        }
        break;
      }
    // Numeric control
    case 6:
      {
        union
        {
          sel_t sel;
          sval_t sval;
          uval_t uval;
          ulonglong ull;
        } u;
        switch ( sz )
        {
          case 'S': // sel_t
            if ( fa->get_segment_value(fid, &u.sel) )
              return Py_BuildValue(PY_BV_SEL, bvsel_t(u.sel));
            break;
          // sval_t
          case 'n':
          case 'D':
          case 'O':
          case 'Y':
          case 'H':
            if ( fa->get_signed_value(fid, &u.sval) )
              return Py_BuildValue(PY_BV_SVAL, bvsval_t(u.sval));
            break;
          case 'L': // uint64
          case 'l': // int64
            if ( fa->_get_field_value(fid, &u.ull) )
              return Py_BuildValue("K", u.ull);
            break;
          case 'N':
          case 'M': // uval_t
            if ( fa->get_unsigned_value(fid, &u.uval) )
              return Py_BuildValue(PY_BV_UVAL, bvuval_t(u.uval));
            break;
          case '$': // ea_t
            if ( fa->get_ea_value(fid, &u.uval) )
              return Py_BuildValue(PY_BV_UVAL, bvuval_t(u.uval));
            break;
        }
        break;
      }
  }
  Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
static bool formchgcbfa_set_field_value(
        size_t p_fa,
        int fid,
        int ft,
        PyObject *py_val)
{
  DECLARE_FORM_ACTIONS;
  PYW_GIL_CHECK_LOCKED_SCOPE();

  switch ( ft )
  {
    // dropdown list
    case 8:
      // Editable dropdown list
      if ( IDAPyStr_Check(py_val) )
      {
        qstring val(IDAPyBytes_AsString(py_val));
        return fa->set_combobox_value(fid, &val);
      }
      // Readonly dropdown list
      else
      {
        int sel_idx = PyLong_AsLong(py_val);
        return fa->set_combobox_value(fid, &sel_idx);
      }
      break;

    // multilinetext - textctrl_info_t
    case 7:
      {
        textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(py_val);
        return ti == NULL ? false : fa->set_text_value(fid, ti);
      }
    // button - uint32
    case 4:
      {
        uval_t val = PyLong_AsUnsignedLong(py_val);
        return fa->set_unsigned_value(fid, &val);
      }
    // ushort
    case 2:
      {
        ushort val = PyLong_AsUnsignedLong(py_val) & 0xffff;
        return fa->_set_field_value(fid, &val);
      }
    // strings
    case 3:
    case 1:
      return fa->set_string_value(fid, IDAPyBytes_AsString(py_val));
    // intvec_t
    case 5:
      {
        sizevec_t selection;
        if ( !PySequence_Check(py_val)
          || PyW_PyListToSizeVec(&selection, py_val) < 0 )
        {
          break;
        }
        return fa->set_chooser_value(fid, &selection);
      }
    // Numeric
    case 6:
      {
        uint64 num;
        if ( PyW_GetNumber(py_val, &num) )
          return fa->_set_field_value(fid, &num);
      }
  }
  return false;
}

#undef DECLARE_FORM_ACTIONS

static size_t py_get_ask_form()
{
  // Return a pointer to the function. Note that, although
  // the C implementation of vask_form will do some
  // Qt/txt widgets generation, the Python's ctypes
  // implementation through which the call will go will first
  // unblock other threads. No need to do it ourselves.
  return (size_t)ask_form;
}

static size_t py_get_open_form()
{
  // See comments above.
  return (size_t)open_form;
}

static void py_register_compiled_form(PyObject *py_form)
{
  PyW_register_compiled_form(py_form);
}

static void py_unregister_compiled_form(PyObject *py_form)
{
  PyW_unregister_compiled_form(py_form);
}
//</inline(py_kernwin_askform)>
%}

%pythoncode %{
#<pycode(py_kernwin_askform)>
import ida_idaapi, _ida_idaapi
import ida_pro

#ICON WARNING|QUESTION|INFO|NONE
#AUTOHIDE NONE|DATABASE|REGISTRY|SESSION
#HIDECANCEL
#BUTTON YES|NO|CANCEL "Value|NONE"
#STARTITEM {id:ItemName}
#HELP / ENDHELP
try:
    import types
    import ctypes
    # On Windows, we use stdcall

    # Callback for buttons
    # typedef int (idaapi *buttoncb_t)(int button_code, form_actions_t &fa);

    _BUTTONCB_T = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)

    # Callback for form change
    # typedef int (idaapi *formchgcb_t)(int field_id, form_actions_t &fa);
    _FORMCHGCB_T = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
except:
    try:
        _BUTTONCB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        _FORMCHGCB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    except:
        _BUTTONCB_T = _FORMCHGCB_T = None


# -----------------------------------------------------------------------
# textctrl_info_t clinked object
class textctrl_info_t(ida_idaapi.py_clinked_object_t):
    """Class representing textctrl_info_t"""

    # Some constants
    TXTF_AUTOINDENT = 0x0001
    """Auto-indent on new line"""
    TXTF_ACCEPTTABS = 0x0002
    """Tab key inserts 'tabsize' spaces"""
    TXTF_READONLY   = 0x0004
    """Text cannot be edited (but can be selected and copied)"""
    TXTF_SELECTED   = 0x0008
    """Shows the field with its text selected"""
    TXTF_MODIFIED   = 0x0010
    """Gets/sets the modified status"""
    TXTF_FIXEDFONT  = 0x0020
    """The control uses IDA's fixed font"""

    def __init__(self, text="", flags=0, tabsize=0):
        ida_idaapi.py_clinked_object_t.__init__(self)
        if text:
            self.text = text
        if flags:
            self.flags = flags
        if tabsize:
            self.tabsize = tabsize

    def _create_clink(self):
        return _ida_kernwin.textctrl_info_t_create()

    def _del_clink(self, lnk):
        return _ida_kernwin.textctrl_info_t_destroy(lnk)

    def _get_clink_ptr(self):
        return _ida_kernwin.textctrl_info_t_get_clink_ptr(self)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _ida_kernwin.textctrl_info_t_assign(self, other)

    def __set_text(self, s):
        """Sets the text value"""
        return _ida_kernwin.textctrl_info_t_set_text(self, s)

    def __get_text(self):
        """Sets the text value"""
        return _ida_kernwin.textctrl_info_t_get_text(self)

    def __set_flags__(self, flags):
        """Sets the flags value"""
        return _ida_kernwin.textctrl_info_t_set_flags(self, flags)

    def __get_flags__(self):
        """Returns the flags value"""
        return _ida_kernwin.textctrl_info_t_get_flags(self)

    def __set_tabsize__(self, tabsize):
        """Sets the tabsize value"""
        return _ida_kernwin.textctrl_info_t_set_tabsize(self, tabsize)

    def __get_tabsize__(self):
        """Returns the tabsize value"""
        return _ida_kernwin.textctrl_info_t_get_tabsize(self)

    value   = property(__get_text, __set_text)
    """Alias for the text property"""
    text    = property(__get_text, __set_text)
    """Text value"""
    flags   = property(__get_flags__, __set_flags__)
    """Flags value"""
    tabsize = property(__get_tabsize__, __set_tabsize__)

# -----------------------------------------------------------------------
class Form(object):

    FT_ASCII = 'A'
    """Ascii string - char *"""
    FT_SEG = 'S'
    """Segment - sel_t *"""
    FT_HEX = 'N'
    """Hex number - uval_t *"""
    FT_SHEX = 'n'
    """Signed hex number - sval_t *"""
    FT_COLOR = 'K'
    """Color button - bgcolor_t *"""
    FT_ADDR = '$'
    """Address - ea_t *"""
    FT_UINT64 = 'L'
    """default base uint64 - uint64"""
    FT_INT64 = 'l'
    """default base int64 - int64"""
    FT_RAWHEX = 'M'
    """Hex number, no 0x prefix - uval_t *"""
    FT_FILE = 'f'
    """File browse - char * at least QMAXPATH"""
    FT_DEC = 'D'
    """Decimal number - sval_t *"""
    FT_OCT = 'O'
    """Octal number, C notation - sval_t *"""
    FT_BIN = 'Y'
    """Binary number, 0b prefix - sval_t *"""
    FT_CHAR = 'H'
    """Char value -- sval_t *"""
    FT_IDENT = 'I'
    """Identifier - char * at least MAXNAMELEN"""
    FT_BUTTON = 'B'
    """Button - def handler(code)"""
    FT_DIR = 'F'
    """Path to directory - char * at least QMAXPATH"""
    FT_TYPE = 'T'
    """Type declaration - char * at least MAXSTR"""
    _FT_USHORT = '_US'
    """Unsigned short"""
    FT_FORMCHG = '%/'
    """Form change callback - formchgcb_t"""
    FT_ECHOOSER = 'E'
    """Embedded chooser - idaapi.Choose"""
    FT_MULTI_LINE_TEXT = 't'
    """Multi text control - textctrl_info_t"""
    FT_DROPDOWN_LIST   = 'b'
    """Dropdown list control - Form.DropdownControl"""
    FT_HTML_LABEL = 'h'
    """HTML label to display (only for GUI version, and for dynamic labels; no input)"""

    FT_CHKGRP = 'C'
    FT_CHKGRP2= 'c'
    FT_RADGRP = 'R'
    FT_RADGRP2= 'r'

    @staticmethod
    def fieldtype_to_ctype(tp, i64 = False):
        """
        Factory method returning a ctype class corresponding to the field type string
        """
        if tp in (Form.FT_SEG, Form.FT_HEX, Form.FT_RAWHEX, Form.FT_ADDR):
            return ctypes.c_ulonglong if i64 else ctypes.c_ulong
        elif tp in (Form.FT_SHEX, Form.FT_DEC, Form.FT_OCT, Form.FT_BIN, Form.FT_CHAR):
            return ctypes.c_longlong if i64 else ctypes.c_long
        elif tp == Form.FT_UINT64:
            return ctypes.c_ulonglong
        elif tp == Form.FT_INT64:
            return ctypes.c_longlong
        elif tp == Form.FT_COLOR:
            return ctypes.c_ulong
        elif tp == Form._FT_USHORT:
            return ctypes.c_ushort
        elif tp in (Form.FT_FORMCHG, Form.FT_ECHOOSER):
            return ctypes.c_void_p
        else:
            return None


    #
    # Generic argument helper classes
    #
    class NumericArgument(object):
        """
        Argument representing various integer arguments (ushort, uint32, uint64, etc...)
        @param tp: One of Form.FT_XXX
        """
        DefI64 = False
        def __init__(self, tp, value):
            cls = Form.fieldtype_to_ctype(tp, self.DefI64)
            if cls is None:
                raise TypeError("Invalid numeric field type: %s" % tp)
            # Get a pointer type to the ctype type
            self.arg = ctypes.pointer(cls(value))

        def __set_value(self, v):
            self.arg.contents.value = v
        value = property(lambda self: self.arg.contents.value, __set_value)


    class StringArgument(object):
        """
        Argument representing a character buffer
        """
        def __init__(self, size=None, value=None):
            if size is None:
                raise SyntaxError("The string size must be passed")

            if value is None:
                self.arg = ctypes.create_string_buffer(size)
            else:
                self.arg = ctypes.create_string_buffer(value, size)
            self.size = size

        def __set_value(self, v):
            self.arg.value = v
        value = property(lambda self: self.arg.value, __set_value)


    #
    # Base control class
    #
    class Control(object):
        def __init__(self):
            self.id = 0
            """Automatically assigned control ID"""

            self.input_field_index = None
            """If this control is an input field, once Compile() returns this will hold its index. This is used only to compute the possible STARTITEM index"""

            self.arg = None
            """Control argument value. This could be one element or a list/tuple (for multiple args per control)"""

            self.form = None
            """Reference to the parent form. It is filled by Form.Add()"""

            self.form_hasattr = False

        def get_tag(self):
            """
            Control tag character. One of Form.FT_XXXX.
            The form class will expand the {} notation and replace them with the tags
            """
            pass

        def get_arg(self):
            """
            Control returns the parameter to be pushed on the stack
            (Of ask_form())
            """
            return self.arg

        def free(self):
            """
            Free the control
            """
            # Release the parent form reference
            self.form = None

        def is_input_field(self):
            """
            Return True if this field acts as an input
            """
            return False

    #
    # Label controls
    #
    class LabelControl(Control):
        """
        Base class for static label control
        """
        def __init__(self, tp):
            Form.Control.__init__(self)
            self.tp = tp

        def get_tag(self):
            return '%%%d%s' % (self.id, self.tp)


    class StringLabel(LabelControl):
        """
        String label control
        """
        def __init__(self, value, tp=None, sz=1024):
            """
            Type field can be one of:
            A - ascii string
            T - type declaration
            I - ident
            F - folder
            f - file
            X - command
            """
            if tp is None:
                tp = Form.FT_ASCII
            Form.LabelControl.__init__(self, tp)
            self.size  = sz
            self.arg = ctypes.create_string_buffer(value, sz)


    class NumericLabel(LabelControl, NumericArgument):
        """
        Numeric label control
        """
        def __init__(self, value, tp=None):
            if tp is None:
                tp = Form.FT_HEX
            Form.LabelControl.__init__(self, tp)
            Form.NumericArgument.__init__(self, tp, value)


    #
    # Group controls
    #
    class GroupItemControl(Control):
        """
        Base class for group control items
        """
        def __init__(self, tag, parent):
            Form.Control.__init__(self)
            self.tag = tag
            self.parent = parent
            # Item position (filled when form is compiled)
            self.pos = 0

        def assign_pos(self):
            self.pos = self.parent.next_child_pos()

        def get_tag(self):
            return "%s%d" % (self.tag, self.id)

        def is_input_field(self):
            return True


    class ChkGroupItemControl(GroupItemControl):
        """
        Checkbox group item control
        """
        def __init__(self, tag, parent):
            Form.GroupItemControl.__init__(self, tag, parent)

        def __get_value(self):
            return (self.parent.value & (1 << self.pos)) != 0

        def __set_value(self, v):
            pv = self.parent.value
            if v:
                pv = pv | (1 << self.pos)
            else:
                pv = pv & ~(1 << self.pos)

            self.parent.value = pv

        checked = property(__get_value, __set_value)
        """Get/Sets checkbox item check status"""


    class RadGroupItemControl(GroupItemControl):
        """
        Radiobox group item control
        """
        def __init__(self, tag, parent):
            Form.GroupItemControl.__init__(self, tag, parent)

        def __get_value(self):
            return self.parent.value == self.pos

        def __set_value(self, v):
            self.parent.value = self.pos

        selected = property(__get_value, __set_value)
        """Get/Sets radiobox item selection status"""


    class GroupControl(Control, NumericArgument):
        """
        Base class for group controls
        """
        def __init__(self, children_names, tag, value=0):
            Form.Control.__init__(self)
            self.children_names = children_names
            self.tag = tag
            self._reset()
            Form.NumericArgument.__init__(self, Form._FT_USHORT, value)

        def _reset(self):
            self.childpos = 0

        def next_child_pos(self):
            v = self.childpos
            self.childpos += 1
            return v

        def get_tag(self):
            return "%d" % self.id


    class ChkGroupControl(GroupControl):
        """
        Checkbox group control class.
        It holds a set of checkbox controls
        """
        ItemClass = None
        """
        Group control item factory class instance
        We need this because later we won't be treating ChkGroupControl or RadGroupControl
        individually, instead we will be working with GroupControl in general.
        """
        def __init__(self, children_names, value=0, secondary=False):
            # Assign group item factory class
            if Form.ChkGroupControl.ItemClass is None:
                Form.ChkGroupControl.ItemClass = Form.ChkGroupItemControl

            Form.GroupControl.__init__(
                self,
                children_names,
                Form.FT_CHKGRP2 if secondary else Form.FT_CHKGRP,
                value)


    class RadGroupControl(GroupControl):
        """
        Radiobox group control class.
        It holds a set of radiobox controls
        """
        ItemClass = None
        def __init__(self, children_names, value=0, secondary=False):
            """
            Creates a radiogroup control.
            @param children_names: A tuple containing group item names
            @param value: Initial selected radio item
            @param secondory: Allows rendering one the same line as the previous group control.
                              Use this if you have another group control on the same line.
            """
            # Assign group item factory class
            if Form.RadGroupControl.ItemClass is None:
                Form.RadGroupControl.ItemClass = Form.RadGroupItemControl

            Form.GroupControl.__init__(
                self,
                children_names,
                Form.FT_RADGRP2 if secondary else Form.FT_RADGRP,
                value)


    #
    # Input controls
    #
    class InputControl(Control):
        """
        Generic form input control.
        It could be numeric control, string control, directory/file browsing, etc...
        """
        def __init__(self, tp, width, swidth, hlp = None):
            """
            @param width: Display width
            @param swidth: String width
            """
            Form.Control.__init__(self)
            self.tp = tp
            self.width = width
            self.switdh = swidth
            self.hlp = hlp

        def get_tag(self):
            return "%s%d:%s:%s:%s" % (
                self.tp, self.id,
                self.width,
                self.switdh,
                ":" if self.hlp is None else self.hlp)

        def is_input_field(self):
            return True


    class NumericInput(InputControl, NumericArgument):
        """
        A composite class serving as a base numeric input control class
        """
        def __init__(self, tp=None, value=0, width=50, swidth=10, hlp=None):
            if tp is None:
                tp = Form.FT_HEX
            Form.InputControl.__init__(self, tp, width, swidth, hlp)
            Form.NumericArgument.__init__(self, self.tp, value)


    class ColorInput(NumericInput):
        """
        Color button input control
        """
        def __init__(self, value = 0):
            """
            @param value: Initial color value in RGB
            """
            Form.NumericInput.__init__(self, tp=Form.FT_COLOR, value=value)


    class StringInput(InputControl, StringArgument):
        """
        Base string input control class.
        This class also constructs a StringArgument
        """
        def __init__(self,
                     tp=None,
                     width=1024,
                     swidth=40,
                     hlp=None,
                     value=None,
                     size=None):
            """
            @param width: String size. But in some cases it has special meaning. For example in FileInput control.
                          If you want to define the string buffer size then pass the 'size' argument
            @param swidth: Control width
            @param value: Initial value
            @param size: String size
            """
            if tp is None:
                tp = Form.FT_ASCII
            if not size:
                size = width
            Form.InputControl.__init__(self, tp, width, swidth, hlp)
            Form.StringArgument.__init__(self, size=size, value=value)


    class FileInput(StringInput):
        """
        File Open/Save input control
        """
        def __init__(self,
                     width=512,
                     swidth=80,
                     save=False, open=False,
                     hlp=None, value=None):

            if save == open:
                raise ValueError("Invalid mode. Choose either open or save")
            if width < 512:
                raise ValueError("Invalid width. Must be greater than 512.")

            # The width field is overloaded in this control and is used
            # to denote the type of the FileInput dialog (save or load)
            # On the other hand it is passed as is to the StringArgument part
            Form.StringInput.__init__(
                self,
                tp=Form.FT_FILE,
                width="1" if save else "0",
                swidth=swidth,
                hlp=hlp,
                size=width,
                value=value)


    class DirInput(StringInput):
        """
        Directory browsing control
        """
        def __init__(self,
                     width=512,
                     swidth=80,
                     hlp=None,
                     value=None):

            if width < 512:
                raise ValueError("Invalid width. Must be greater than 512.")

            Form.StringInput.__init__(
                self,
                tp=Form.FT_DIR,
                width=width,
                swidth=swidth,
                hlp=hlp,
                size=width,
                value=value)


    class ButtonInput(InputControl):
        """
        Button control.
        A handler along with a 'code' (numeric value) can be associated with the button.
        This way one handler can handle many buttons based on the button code (or in other terms id or tag)
        """
        def __init__(self, handler, code="", swidth="", hlp=None):
            """
            @param handler: Button handler. A callback taking one argument which is the code.
            @param code: A code associated with the button and that is later passed to the handler.
            """
            Form.InputControl.__init__(
                self,
                Form.FT_BUTTON,
                code,
                swidth,
                hlp)
            self.handler = handler
            self.arg = _BUTTONCB_T(self.helper_cb)

        def helper_cb(self, button_code, p_fa):
            # Remember the pointer to the forms_action in the parent form
            self.form.p_fa = p_fa

            # Call user's handler
            r = self.handler(button_code)
            return 0 if r is None else r

        def is_input_field(self):
            return False


    class FormChangeCb(Control):
        """
        Form change handler.
        This can be thought of like a dialog procedure.
        Everytime a form action occurs, this handler will be called along with the control id.
        The programmer can then call various form actions accordingly:
          - EnableField
          - ShowField
          - MoveField
          - GetFieldValue
          - etc...

        Special control IDs: -1 (The form is initialized) and -2 (Ok has been clicked)

        """
        def __init__(self, handler):
            """
            Constructs the handler.
            @param handler: The handler (preferrably a member function of a class derived from the Form class).
            """
            Form.Control.__init__(self)

            # Save the handler
            self.handler = handler

            # Create a callback stub
            # We use this mechanism to create an intermediate step
            # where we can create an 'fa' adapter for use by Python
            self.arg = _FORMCHGCB_T(self.helper_cb)

        def helper_cb(self, fid, p_fa):
            # Remember the pointer to the forms_action in the parent form
            self.form.p_fa = p_fa

            # Call user's handler
            r = self.handler(fid)
            return 0 if r is None else r

        def get_tag(self):
            return Form.FT_FORMCHG

        def free(self):
            Form.Control.free(self)
            # Remove reference to the handler
            # (Normally the handler is a member function in the parent form)
            self.handler = None


    class EmbeddedChooserControl(InputControl):
        """
        Embedded chooser control.
        This control links to a Chooser2 control created with the 'embedded=True'
        """
        def __init__(self,
                     chooser=None,
                     swidth=40,
                     hlp=None):
            """
            Embedded chooser control

            @param chooser: A chooser2 instance (must be constructed with 'embedded=True')
            """

            # !! Make sure a chooser instance is passed !!
            if chooser is None or not isinstance(chooser, Choose):
                raise ValueError("Invalid chooser passed.")

            # Create an embedded chooser structure from the Choose instance
            if chooser.Embedded() != 0:
                raise ValueError("Failed to create embedded chooser instance.")

            # Construct input control
            Form.InputControl.__init__(self, Form.FT_ECHOOSER, "", swidth)

            self.selobj = ida_pro.sizevec_t()

            # Get a pointer to the chooser_info_t and the selection vector
            # (These two parameters are the needed arguments for the ask_form())
            emb = _ida_kernwin._choose_get_embedded_chobj_pointer(chooser)
            sel = self.selobj.this.__long__()

            # Get a pointer to a c_void_p constructed from an address
            p_embedded = ctypes.pointer(ctypes.c_void_p.from_address(emb))
            p_sel      = ctypes.pointer(ctypes.c_void_p.from_address(sel))

            # - Create the embedded chooser info on control creation
            # - Do not free the embeded chooser because after we get the args
            #   via Compile() the user can still call Execute() which relies
            #   on the already computed args
            self.arg   = (p_embedded, p_sel)

            # Save chooser instance
            self.chooser = chooser

            # Add a bogus 'size' attribute
            self.size = 0


        value = property(lambda self: self.chooser)
        """Returns the embedded chooser instance"""

        def __get_selection__(self):
            if len(self.selobj):
                out = []
                for item in self.selobj:
                    out.append(int(item))
                return out
        selection = property(__get_selection__)
        """Returns the selection"""

        def free(self):
            """
            Frees the embedded chooser data
            """
            self.chooser.Close()
            self.chooser = None
            Form.Control.free(self)


    class DropdownListControl(InputControl, ida_pro._qstrvec_t):
        """
        Dropdown control
        This control allows manipulating a dropdown control
        """
        def __init__(self, items=[], readonly=True, selval=0, width=50, swidth=50, hlp = None):
            """
            @param items: A string list of items used to prepopulate the control
            @param readonly: Specifies whether the dropdown list is editable or not
            @param selval: The preselected item index (when readonly) or text value (when editable)
            @param width: the control width (n/a if the dropdown list is readonly)
            @param swidth: string width
            """

            # Ignore the width if readonly was set
            if readonly:
                width = 0

            # Init the input control base class
            Form.InputControl.__init__(
                self,
                Form.FT_DROPDOWN_LIST,
                width,
                swidth,
                hlp)

            # Init the associated qstrvec
            ida_pro._qstrvec_t.__init__(self, items)

            # Remember if readonly or not
            self.readonly = readonly

            if readonly:
                # Create a C integer and remember it
                self.__selval = ctypes.c_int(selval)
                val_addr      = ctypes.addressof(self.__selval)
            else:
                # Create an strvec with one qstring
                self.__selval = ida_pro._qstrvec_t([selval])
                # Get address of the first element
                val_addr      = self.__selval.addressof(0)

            # Two arguments:
            # - argument #1: a pointer to the qstrvec containing the items
            # - argument #2: an integer to hold the selection
            #         or
            #            #2: a qstring to hold the dropdown text control value
            self.arg = (
                ctypes.pointer(ctypes.c_void_p.from_address(self.clink_ptr)),
                ctypes.pointer(ctypes.c_void_p.from_address(val_addr))
            )


        def __set_selval(self, val):
            if self.readonly:
                self.__selval.value = val
            else:
                self.__selval[0] = val

        def __get_selval(self):
            # Return the selection index
            # or the entered text value
            return self.__selval.value if self.readonly else self.__selval[0]

        value  = property(__get_selval, __set_selval)
        selval = property(__get_selval, __set_selval)
        """
        Read/write the selection value.
        The value is used as an item index in readonly mode or text value in editable mode
        This value can be used only after the form has been closed.
        """

        def free(self):
            self._free()


        def set_items(self, items):
            """Sets the dropdown list items"""
            self.from_list(items)


    class MultiLineTextControl(InputControl, textctrl_info_t):
        """
        Multi line text control.
        This class inherits from textctrl_info_t. Thus the attributes are also inherited
        This control allows manipulating a multilinetext control
        """
        def __init__(self, text="", flags=0, tabsize=0, width=50, swidth=50, hlp = None):
            """
            @param text: Initial text value
            @param flags: One of textctrl_info_t.TXTF_.... values
            @param tabsize: Tab size
            @param width: Display width
            @param swidth: String width
            """
            # Init the input control base class
            Form.InputControl.__init__(self, Form.FT_MULTI_LINE_TEXT, width, swidth, hlp)

            # Init the associated textctrl_info base class
            textctrl_info_t.__init__(self, text=text, flags=flags, tabsize=tabsize)

            # Get the argument as a pointer from the embedded ti
            self.arg = ctypes.pointer(ctypes.c_void_p.from_address(self.clink_ptr))


        def free(self):
            self._free()


    #
    # Form class
    #
    def __init__(self, form, controls):
        """
        Contruct a Form class.
        This class wraps around ask_form() or open_form() and provides an easier / alternative syntax for describing forms.
        The form control names are wrapped inside the opening and closing curly braces and the control themselves are
        defined and instantiated via various form controls (subclasses of Form).

        @param form: The form string
        @param controls: A dictionary containing the control name as a _key_ and control object as _value_
        """
        self._reset()
        self.form = form
        """Form string"""
        self.controls = controls
        """Dictionary of controls"""
        self.__args = None

        self.title = None
        """The Form title. It will be filled when the form is compiled"""

        self.modal = True
        """By default, forms are modal"""

        self.openform_flags = 0
        """
        If non-modal, these flags will be passed to open_form.
        This is an OR'ed combination of the PluginForm.FORM_* values.
        """


    def Free(self):
        """
        Frees all resources associated with a compiled form.
        Make sure you call this function when you finish using the form.
        """

        # Free all the controls
        for name, ctrl in self.__controls.items():
            if ctrl.parent_hasattr:
                delattr(self, name)
                ctrl.parent_hasattr = False
            ctrl.free()

        # Reset the controls
        # (Note that we are not removing the form control attributes, no need)
        self._reset()

        # Unregister, so we don't try and free it again at closing-time.
        _ida_kernwin.py_unregister_compiled_form(self)


    def _reset(self):
        """
        Resets the Form class state variables
        """
        self.__controls = {}
        self.__ctrl_id = 1


    def __getitem__(self, name):
        """Returns a control object by name"""
        return self.__controls[name]


    def Add(self, name, ctrl, mkattr = True):
        """
        Low level function. Prefer AddControls() to this function.
        This function adds one control to the form.

        @param name: Control name
        @param ctrl: Control object
        @param mkattr: Create control name / control object as a form attribute
        """
        # Assign a unique ID
        ctrl.id = self.__ctrl_id
        self.__ctrl_id += 1

        # Create attribute with control name
        if mkattr:
            setattr(self, name, ctrl)
            ctrl.parent_hasattr = True

        # Remember the control
        self.__controls[name] = ctrl

        # Link the form to the control via its form attribute
        ctrl.form = self

        # Is it a group? Add each child
        if isinstance(ctrl, Form.GroupControl):
            self._AddGroup(ctrl, mkattr)


    def FindControlById(self, id):
        """
        Finds a control instance given its id
        """
        for ctrl in self.__controls.values():
            if ctrl.id == id:
                return ctrl
        return None


    @staticmethod
    def _ParseFormTitle(form):
        """
        Parses the form's title from the form text
        """
        help_state = 0
        for i, line in enumerate(form.split("\n")):
            if line.startswith("STARTITEM ") or line.startswith("BUTTON "):
                continue
            # Skip "HELP" and remember state
            elif help_state == 0 and line == "HELP":
                help_state = 1 # Mark inside HELP
                continue
            elif help_state == 1 and line == "ENDHELP":
                help_state = 2 # Mark end of HELP
                continue
            return line.strip()

        return None


    def _AddGroup(self, Group, mkattr=True):
        """
        Internal function.
        This function expands the group item names and creates individual group item controls

        @param Group: The group class (checkbox or radio group class)
        """

        # Create group item controls for each child
        for child_name in Group.children_names:
            self.Add(
                child_name,
                # Use the class factory
                Group.ItemClass(Group.tag, Group),
                mkattr)


    def AddControls(self, controls, mkattr=True):
        """
        Adds controls from a dictionary.
        The dictionary key is the control name and the value is a Form.Control object
        @param controls: The control dictionary
        """
        for name, ctrl in controls.items():
            # Add the control
            self.Add(name, ctrl, mkattr)


    def CompileEx(self, form):
        """
        Low level function.
        Compiles (parses the form syntax and adds the control) the form string and
        returns the argument list to be passed the argument list to ask_form().

        The form controls are wrapped inside curly braces: {ControlName}.

        A special operator can be used to return the index of a given control by its name: {id:ControlName}.
        This is useful when you use the STARTITEM form keyword to set the initially focused control.
        (note that, technically, the index is not the same as the ID; that's because STARTITEM
        uses raw, 0-based indexes rather than control IDs to determine the focused widget.)

        @param form: Compiles the form and returns the arguments needed to be passed to ask_form()
        """
        # First argument is the form string
        args = [None]

        # Second argument, if form is not modal, is the set of flags
        if not self.modal:
            args.append(self.openform_flags | 0x80) # Add FORM_QWIDGET

        ctrlcnt = 1

        # Reset all group control internal flags
        for ctrl in self.__controls.values():
            if isinstance(ctrl, Form.GroupControl):
                ctrl._reset()

        def next_control(form, p, first_pass):
            i1 = form.find("{", p)
            if i1 < 0:
                return form, None, None, None
            if form[i1 - 1] == '\\' and i1 > 0:
                if first_pass:
                    return next_control(form, i1 + 1, first_pass)
                else:
                    # Remove escape sequence and restart search
                    form = form[:i1 - 1] + form[i1:]
                    return next_control(form, i1, first_pass)
            i2 = form.find("}", i1)
            if i2 < 0:
                raise SyntaxError("No matching closing brace '}'")
            ctrlname = form[i1 + 1:i2]
            if not ctrlname:
                raise ValueError("Control %d has an invalid name!" % ctrlcnt)
            return form, i1, i2, ctrlname


        last_input_field_index = 0
        # First pass: assign input_field_index values to controls
        p = 0
        while True:
            form, i1, i2, ctrlname = next_control(form, p, first_pass=True)
            if ctrlname is None:
                break
            p = i2

            if ctrlname.startswith("id:"):
                continue

            ctrl = self.__controls.get(ctrlname, None)
            if ctrl is None:
                raise ValueError("No matching control '%s'" % ctrlname)

            # If this control is an input, assign its index
            if ctrl.is_input_field():
                ctrl.input_field_index = last_input_field_index
                last_input_field_index += 1


        p = 0
        while True:
            form, i1, i2, ctrlname = next_control(form, p, first_pass=False)
            if ctrlname is None:
                break

            # Is it the IDOF operator?
            if ctrlname.startswith("id:"):
                idfunc = True
                # Take actual ctrlname
                ctrlname = ctrlname[3:]
            else:
                idfunc = False

            # Find the control
            ctrl = self.__controls.get(ctrlname, None)
            if ctrl is None:
                raise ValueError("No matching control '%s'" % ctrlname)

            # Replace control name by tag
            if idfunc:
                tag = str(ctrl.input_field_index if ctrl.input_field_index is not None else ctrl.id)
            else:
                tag = ctrl.get_tag()
            taglen = len(tag)
            form = form[:i1] + tag + form[i2+1:]

            # Set new position
            p = i1 + taglen

            # Was it an IDOF() ? No need to push parameters
            # Just ID substitution is fine
            if idfunc:
                continue


            # For GroupItem controls, there are no individual arguments
            # The argument is assigned for the group itself
            if isinstance(ctrl, Form.GroupItemControl):
                # GroupItem controls will have their position dynamically set
                ctrl.assign_pos()
            else:
                # Push argument(s)
                # (Some controls need more than one argument)
                arg = ctrl.get_arg()
                if isinstance(arg, (list, tuple)):
                    # Push all args
                    args.extend(arg)
                else:
                    # Push one arg
                    args.append(arg)

            ctrlcnt += 1

        # If no FormChangeCb instance was passed, and thus there's no '%/'
        # in the resulting form string, let's provide a minimal one, so that
        # we will retrieve 'p_fa', and thus actions that rely on it will work.
        if form.find(Form.FT_FORMCHG) < 0:
            form = form + Form.FT_FORMCHG
            fccb = Form.FormChangeCb(lambda *args: 1)
            self.Add("___dummyfchgcb", fccb)
            # Regardless of the actual position of '%/' in the form
            # string, a formchange callback _must_ be right after
            # the form string.
            if self.modal:
                inspos = 1
            else:
                inspos = 2
            args.insert(inspos, fccb.get_arg())

        # Patch in the final form string
        args[0] = form

        self.title = self._ParseFormTitle(form)
        return args


    def Compile(self):
        """
        Compiles a form and returns the form object (self) and the argument list.
        The form object will contain object names corresponding to the form elements

        @return: It will raise an exception on failure. Otherwise the return value is ignored
        """

        # Reset controls
        self._reset()

        # Insert controls
        self.AddControls(self.controls)

        # Compile form and get args
        self.__args = self.CompileEx(self.form)

        # Register this form, to make sure it will be freed at closing-time.
        _ida_kernwin.py_register_compiled_form(self)

        return (self, self.__args)


    def Compiled(self):
        """
        Checks if the form has already been compiled

        @return: Boolean
        """
        return self.__args is not None


    def _ChkCompiled(self):
        if not self.Compiled():
            raise SyntaxError("Form is not compiled")


    def Execute(self):
        """
        Displays a modal dialog containing the compiled form.
        @return: 1 - ok ; 0 - cancel
        """
        self._ChkCompiled()
        if not self.modal:
            raise SyntaxError("Form is not modal. Open() should be instead")

        return _call_ask_form(*self.__args)


    def Open(self):
        """
        Opens a widget containing the compiled form.
        """
        self._ChkCompiled()
        if self.modal:
            raise SyntaxError("Form is modal. Execute() should be instead")

        _call_open_form(*self.__args)


    def EnableField(self, ctrl, enable):
        """
        Enable or disable an input field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_enable_field(self.p_fa, ctrl.id, enable)


    def ShowField(self, ctrl, show):
        """
        Show or hide an input field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_show_field(self.p_fa, ctrl.id, show)


    def MoveField(self, ctrl, x, y, w, h):
        """
        Move/resize an input field

        @return: False - no such fiel
        """
        return _ida_kernwin.formchgcbfa_move_field(self.p_fa, ctrl.id, x, y, w, h)


    def GetFocusedField(self):
        """
        Get currently focused input field.
        @return: None if no field is selected otherwise the control ID
        """
        id = _ida_kernwin.formchgcbfa_get_focused_field(self.p_fa)
        return self.FindControlById(id)


    def SetFocusedField(self, ctrl):
        """
        Set currently focused input field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_set_focused_field(self.p_fa, ctrl.id)


    def RefreshField(self, ctrl):
        """
        Refresh a field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_refresh_field(self.p_fa, ctrl.id)


    def Close(self, close_normally):
        """
        Close the form
        @param close_normally:
                   1: form is closed normally as if the user pressed Enter
                   0: form is closed abnormally as if the user pressed Esc
        @return: None
        """
        return _ida_kernwin.formchgcbfa_close(self.p_fa, close_normally)


    def GetControlValue(self, ctrl):
        """
        Returns the control's value depending on its type
        @param ctrl: Form control instance
        @return:
            - color button, radio controls: integer
            - file/dir input, string input and string label: string
            - embedded chooser control (0-based indices of selected items): integer list
            - for multilinetext control: textctrl_info_t
            - dropdown list controls: string (when editable) or index (when readonly)
            - None: on failure
        """
        tid, sz = self.ControlToFieldTypeIdAndSize(ctrl)
        r = _ida_kernwin.formchgcbfa_get_field_value(
                    self.p_fa,
                    ctrl.id,
                    tid,
                    sz)
        # Multilinetext? Unpack the tuple into a new textctrl_info_t instance
        if r is not None and tid == 7:
            return textctrl_info_t(text=r[0], flags=r[1], tabsize=r[2])
        else:
            return r


    def SetControlValue(self, ctrl, value):
        """
        Set the control's value depending on its type
        @param ctrl: Form control instance
        @param value:
            - embedded chooser: a 0-base indices list to select embedded chooser items
            - multilinetext: a textctrl_info_t
            - dropdown list: an integer designating the selection index if readonly
                             a string designating the edit control value if not readonly
        @return: Boolean true on success
        """
        tid, _ = self.ControlToFieldTypeIdAndSize(ctrl)
        return _ida_kernwin.formchgcbfa_set_field_value(
                    self.p_fa,
                    ctrl.id,
                    tid,
                    value)


    @staticmethod
    def ControlToFieldTypeIdAndSize(ctrl):
        """
        Converts a control object to a tuple containing the field id
        and the associated buffer size
        """
        # Input control depend on the associated buffer size (supplied by the user)

        # Make sure you check instances types taking into account inheritance
        if isinstance(ctrl, Form.DropdownListControl):
            return (8, 1 if ctrl.readonly else 0)
        elif isinstance(ctrl, Form.MultiLineTextControl):
            return (7, 0)
        elif isinstance(ctrl, Form.EmbeddedChooserControl):
            return (5, 0)
        # Group items or controls
        elif isinstance(ctrl, (Form.GroupItemControl, Form.GroupControl)):
            return (2, 0)
        elif isinstance(ctrl, Form.StringLabel):
            return (3, min(_ida_kernwin.MAXSTR, ctrl.size))
        elif isinstance(ctrl, Form.ColorInput):
            return (4, 0)
        elif isinstance(ctrl, Form.NumericInput):
            # Pass the numeric control type
            return (6, ord(ctrl.tp[0]))
        elif isinstance(ctrl, Form.InputControl):
            return (1, ctrl.size)
        else:
            raise NotImplementedError("Not yet implemented")

# --------------------------------------------------------------------------
# Instantiate ask_form function pointer
try:
    import ctypes
    # Setup the numeric argument size
    Form.NumericArgument.DefI64 = _ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF
    __ask_form_callable = ctypes.CFUNCTYPE(ctypes.c_long)(_ida_kernwin.py_get_ask_form())
    __open_form_callable = ctypes.CFUNCTYPE(ctypes.c_long)(_ida_kernwin.py_get_open_form())
except:
    def __ask_form_callable(*args):
        warning("ask_form() needs ctypes library in order to work")
        return 0
    def __open_form_callable(*args):
        warning("open_form() needs ctypes library in order to work")


def _call_ask_form(*args):
    old = _ida_idaapi.set_script_timeout(0)
    r = __ask_form_callable(*args)
    _ida_idaapi.set_script_timeout(old)
    return r

def _call_open_form(*args):
    old = _ida_idaapi.set_script_timeout(0)
    r = __open_form_callable(*args)
    _ida_idaapi.set_script_timeout(old)
#</pycode(py_kernwin_askform)>
%}


//-------------------------------------------------------------------------
//                                    cli_t
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_cli)>
//--------------------------------------------------------------------------
#define MAX_PY_CLI 12

// Callbacks table
// This structure was devised because the cli callbacks have no user-data parameter
struct py_cli_cbs_t
{
  bool (idaapi *execute_line)(const char *line);
  bool (idaapi *complete_line)(
          qstring *completion,
          const char *prefix,
          int n,
          const char *line,
          int x);
  bool (idaapi *keydown)(
          qstring *line,
          int *p_x,
          int *p_sellen,
          int *vk_key,
          int shift);
  bool (idaapi *find_completions)(
          qstrvec_t *out_completions,
          int *out_match_start,
          int *out_match_end,
          const char *line,
          int x);
};

// CLI Python wrapper class
class py_cli_t
{
private:
  //--------------------------------------------------------------------------
  cli_t cli;
  PyObject *self;
  qstring cli_sname, cli_lname, cli_hint;

  //--------------------------------------------------------------------------
  static py_cli_t *py_clis[MAX_PY_CLI];
  static const py_cli_cbs_t py_cli_cbs[MAX_PY_CLI];
  //--------------------------------------------------------------------------
#define IMPL_PY_CLI_CB(CBN)                                             \
  static bool idaapi s_keydown##CBN(qstring *line, int *p_x, int *p_sellen, int *vk_key, int shift) \
  {                                                                     \
    return py_clis[CBN]->on_keydown(line, p_x, p_sellen, vk_key, shift); \
  }                                                                     \
  static bool idaapi s_execute_line##CBN(const char *line)              \
  {                                                                     \
    return py_clis[CBN]->on_execute_line(line);                         \
  }                                                                     \
  static bool idaapi s_complete_line##CBN(qstring *completion, const char *prefix, int n, const char *line, int x) \
  {                                                                     \
    return py_clis[CBN]->on_complete_line(completion, prefix, n, line, x); \
  }                                                                     \
  static bool idaapi s_find_completions##CBN(qstrvec_t *completions, int *out_start, int *out_end, const char *line, int x) \
  {                                                                     \
    return py_clis[CBN]->on_find_completions(completions, out_start, out_end, line, x); \
  }

  IMPL_PY_CLI_CB(0);    IMPL_PY_CLI_CB(1);   IMPL_PY_CLI_CB(2);   IMPL_PY_CLI_CB(3);
  IMPL_PY_CLI_CB(4);    IMPL_PY_CLI_CB(5);   IMPL_PY_CLI_CB(6);   IMPL_PY_CLI_CB(7);
  IMPL_PY_CLI_CB(8);    IMPL_PY_CLI_CB(9);   IMPL_PY_CLI_CB(10);  IMPL_PY_CLI_CB(11);
#undef IMPL_PY_CLI_CB

  //--------------------------------------------------------------------------
  // callback: the user pressed Enter
  // CLI is free to execute the line immediately or ask for more lines
  // Returns: true-executed line, false-ask for more lines
  bool on_execute_line(const char *line)
  {
    PYW_GIL_GET;
    newref_t result(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_EXECUTE_LINE,
                    "s",
                    line));
    PyW_ShowCbErr(S_ON_EXECUTE_LINE);
    return result != NULL && PyObject_IsTrue(result.o);
  }

  //--------------------------------------------------------------------------
  // callback: a keyboard key has been pressed
  // This is a generic callback and the CLI is free to do whatever
  // it wants.
  //    line - current input line (in/out argument)
  //    p_x  - pointer to current x coordinate of the cursor (in/out)
  //    p_sellen - pointer to current selection length (usually 0)
  //    p_vk_key - pointer to virtual key code (in/out)
  //           if the key has been handled, it should be reset to 0 by CLI
  //    shift - shift state
  // Returns: true-modified input line or x coordinate or selection length
  // This callback is optional
  bool on_keydown(
    qstring *line,
    int *p_x,
    int *p_sellen,
    int *vk_key,
    int shift)
  {
    PYW_GIL_GET;
    newref_t result(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_KEYDOWN,
                    "siiHi",
                    line->c_str(),
                    *p_x,
                    *p_sellen,
                    *vk_key,
                    shift));

    bool ok = result != NULL && PyTuple_Check(result.o);

    PyW_ShowCbErr(S_ON_KEYDOWN);

    if ( ok )
    {
      Py_ssize_t sz = PyTuple_Size(result.o);
      PyObject *item;

#define GET_TUPLE_ENTRY(col, PyThingy, AsThingy, out)                   \
      do                                                                \
      {                                                                 \
        if ( sz > col )                                                 \
        {                                                               \
          borref_t _r(PyTuple_GetItem(result.o, col));                  \
          if ( _r != NULL && PyThingy##_Check(_r.o) )                   \
            *out = PyThingy##_##AsThingy(_r.o);                         \
        }                                                               \
      } while ( false )

      GET_TUPLE_ENTRY(0, PyString, AsString, line);
      GET_TUPLE_ENTRY(1, PyInt, AsLong, p_x);
      GET_TUPLE_ENTRY(2, PyInt, AsLong, p_sellen);
      GET_TUPLE_ENTRY(3, PyInt, AsLong, vk_key);
      *vk_key &= 0xffff;
#undef GET_TUPLE_ENTRY
    }
    return ok;
  }

  // callback: the user pressed Tab
  // Find a completion number N for prefix PREFIX
  // LINE is given as context information. X is the index where PREFIX starts in LINE
  // New prefix should be stored in PREFIX.
  // Returns: true if generated a new completion
  // This callback is optional
  bool on_complete_line(
          qstring *completion,
          const char *prefix,
          int n,
          const char *line,
          int x)
  {
    PYW_GIL_GET;
    newref_t result(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_COMPLETE_LINE,
                    "sisi",
                    prefix,
                    n,
                    line,
                    x));

    bool ok = result != NULL && IDAPyStr_Check(result.o);
    PyW_ShowCbErr(S_ON_COMPLETE_LINE);
    if ( ok )
      *completion = IDAPyBytes_AsString(result.o);
    return ok;
  }

  // callback: the user pressed Tab
  // Find completions
  // This callback is optional
  bool on_find_completions(
          qstrvec_t *out_completions,
          int *out_match_start,
          int *out_match_end,
          const char *line,
          int x)
  {
    PYW_GIL_GET;
    newref_t py_res(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_FIND_COMPLETIONS,
                    "si",
                    line,
                    x));
    PyW_ShowCbErr(S_ON_FIND_COMPLETIONS);
    if ( PyErr_Occurred() != NULL )
      return false;
    return idapython_convert_cli_completions(
            out_completions, out_match_start, out_match_end, py_res);
  }

  // Private ctor (use bind())
  py_cli_t()
  {
  }

public:
  //---------------------------------------------------------------------------
  static int bind(PyObject *py_obj)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    int cli_idx;
    // Find an empty slot
    for ( cli_idx = 0; cli_idx < MAX_PY_CLI; ++cli_idx )
    {
      if ( py_clis[cli_idx] == NULL )
        break;
    }
    py_cli_t *py_cli = NULL;
    do
    {
      // No free slots?
      if ( cli_idx >= MAX_PY_CLI )
        break;

      // Create a new instance
      py_cli = new py_cli_t();
      PyObject *attr;

      // Start populating the 'cli' member
      py_cli->cli.size = sizeof(cli_t);

      // Store 'flags'
      {
        ref_t flags_attr(PyW_TryGetAttrString(py_obj, S_FLAGS));
        if ( flags_attr == NULL )
          py_cli->cli.flags = 0;
        else
          py_cli->cli.flags = PyLong_AsLong(flags_attr.o);
      }

      // Store 'sname'
      if ( !PyW_GetStringAttr(py_obj, "sname", &py_cli->cli_sname) )
        break;
      py_cli->cli.sname = py_cli->cli_sname.c_str();

      // Store 'lname'
      if ( !PyW_GetStringAttr(py_obj, "lname", &py_cli->cli_lname) )
        break;
      py_cli->cli.lname = py_cli->cli_lname.c_str();

      // Store 'hint'
      if ( !PyW_GetStringAttr(py_obj, "hint", &py_cli->cli_hint) )
        break;
      py_cli->cli.hint = py_cli->cli_hint.c_str();

      // Store callbacks
      if ( !PyObject_HasAttrString(py_obj, S_ON_EXECUTE_LINE) )
        break;
      py_cli->cli.execute_line = py_cli_cbs[cli_idx].execute_line;
      py_cli->cli.unused = (void *) (PyObject_HasAttrString(py_obj, S_ON_COMPLETE_LINE) ? py_cli_cbs[cli_idx].complete_line : NULL);
      py_cli->cli.keydown = PyObject_HasAttrString(py_obj, S_ON_KEYDOWN) ? py_cli_cbs[cli_idx].keydown : NULL;
      py_cli->cli.find_completions = PyObject_HasAttrString(py_obj, S_ON_FIND_COMPLETIONS) ? py_cli_cbs[cli_idx].find_completions : NULL;

      // install CLI
      install_command_interpreter(&py_cli->cli);

      // Take reference to this object
      py_cli->self = py_obj;
      Py_INCREF(py_obj);

      // Save the instance
      py_clis[cli_idx] = py_cli;

      return cli_idx;
    } while (false);

    delete py_cli;
    return -1;
  }

  //---------------------------------------------------------------------------
  static void unbind(int cli_idx)
  {
    // Out of bounds or not set?
    if ( cli_idx < 0 || cli_idx >= MAX_PY_CLI || py_clis[cli_idx] == NULL )
      return;

    py_cli_t *py_cli = py_clis[cli_idx];
    remove_command_interpreter(&py_cli->cli);

    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      Py_DECREF(py_cli->self);
      delete py_cli;
    }

    py_clis[cli_idx] = NULL;

    return;
  }
};
py_cli_t *py_cli_t::py_clis[MAX_PY_CLI] = { NULL };
#define DECL_PY_CLI_CB(CBN) { s_execute_line##CBN, s_complete_line##CBN, s_keydown##CBN }
const py_cli_cbs_t py_cli_t::py_cli_cbs[MAX_PY_CLI] =
{
  DECL_PY_CLI_CB(0),   DECL_PY_CLI_CB(1),  DECL_PY_CLI_CB(2),   DECL_PY_CLI_CB(3),
  DECL_PY_CLI_CB(4),   DECL_PY_CLI_CB(5),  DECL_PY_CLI_CB(6),   DECL_PY_CLI_CB(7),
  DECL_PY_CLI_CB(8),   DECL_PY_CLI_CB(9),  DECL_PY_CLI_CB(10),  DECL_PY_CLI_CB(11)
};
#undef DECL_PY_CLI_CB
//</code(py_kernwin_cli)>
%}

%inline %{
//<inline(py_kernwin_cli)>
static int py_install_command_interpreter(PyObject *py_obj)
{
  return py_cli_t::bind(py_obj);
}

static void py_remove_command_interpreter(int cli_idx)
{
  py_cli_t::unbind(cli_idx);
}
//</inline(py_kernwin_cli)>
%}

%pythoncode %{
#<pycode(py_kernwin_cli)>
import ida_idaapi

class cli_t(ida_idaapi.pyidc_opaque_object_t):
    """
    cli_t wrapper class.

    This class allows you to implement your own command line interface handlers.
    """

    def __init__(self):
        self.__cli_idx = -1
        self.__clink__ = None


    def register(self, flags = 0, sname = None, lname = None, hint = None):
        """
        Registers the CLI.

        @param flags: Feature bits. No bits are defined yet, must be 0
        @param sname: Short name (displayed on the button)
        @param lname: Long name (displayed in the menu)
        @param hint:  Hint for the input line

        @return Boolean: True-Success, False-Failed
        """

        # Already registered?
        if self.__cli_idx >= 0:
            return True

        if sname is not None: self.sname = sname
        if lname is not None: self.lname = lname
        if hint is not None:  self.hint  = hint

        # Register
        self.__cli_idx = _ida_kernwin.install_command_interpreter(self)
        return False if self.__cli_idx < 0 else True


    def unregister(self):
        """
        Unregisters the CLI (if it was registered)
        """
        if self.__cli_idx < 0:
            return False

        _ida_kernwin.remove_command_interpreter(self.__cli_idx)
        self.__cli_idx = -1
        return True


    def __del__(self):
        self.unregister()

    #
    # Implement these methods in the subclass:
    #
#<pydoc>
#    def OnExecuteLine(self, line):
#        """
#        The user pressed Enter. The CLI is free to execute the line immediately or ask for more lines.
#
#        This callback is mandatory.
#
#        @param line: typed line(s)
#        @return Boolean: True-executed line, False-ask for more lines
#        """
#        return True
#
#    def OnKeydown(self, line, x, sellen, vkey, shift):
#        """
#        A keyboard key has been pressed
#        This is a generic callback and the CLI is free to do whatever it wants.
#
#        This callback is optional.
#
#        @param line: current input line
#        @param x: current x coordinate of the cursor
#        @param sellen: current selection length (usually 0)
#        @param vkey: virtual key code. if the key has been handled, it should be returned as zero
#        @param shift: shift state
#
#        @return:
#            None - Nothing was changed
#            tuple(line, x, sellen, vkey): if either of the input line or the x coordinate or the selection length has been modified.
#            It is possible to return a tuple with None elements to preserve old values. Example: tuple(new_line, None, None, None) or tuple(new_line)
#        """
#        return None
#
#    def OnCompleteLine(self, prefix, n, line, prefix_start):
#        """
#        The user pressed Tab. Find a completion number N for prefix PREFIX
#
#        This callback is optional.
#
#        @param prefix: Line prefix at prefix_start (string)
#        @param n: completion number (int)
#        @param line: the current line (string)
#        @param prefix_start: the index where PREFIX starts in LINE (int)
#
#        @return: None if no completion could be generated otherwise a String with the completion suggestion
#        """
#        return None
#</pydoc>

#</pycode(py_kernwin_cli)>
%}

//-------------------------------------------------------------------------
%init %{
//<init(py_kernwin_askform)>
//</init(py_kernwin_askform)>
%}

//-------------------------------------------------------------------------
//                              CustomIDAMemo
//-------------------------------------------------------------------------
%ignore View_Callback;

%inline %{
//<inline(py_kernwin_viewhooks)>

//---------------------------------------------------------------------------
// View hooks
//---------------------------------------------------------------------------
ssize_t idaapi View_Callback(void *ud, int notification_code, va_list va);
class View_Hooks
{
public:
  virtual ~View_Hooks() { unhook(); }

  bool hook()
  {
    return idapython_hook_to_notification_point(HT_VIEW, View_Callback, this);
  }
  bool unhook()
  {
    return idapython_unhook_from_notification_point(HT_VIEW, View_Callback, this);
  }

  // hookgenVIEW:methods
virtual void view_activated(TWidget * view) {qnotused(view); }
virtual void view_deactivated(TWidget * view) {qnotused(view); }
virtual void view_keydown(TWidget * view, int key, view_event_state_t state) {qnotused(view); qnotused(key); qnotused(state); }
virtual void view_click(TWidget * view, const view_mouse_event_t * event) {qnotused(view); qnotused(event); }
virtual void view_dblclick(TWidget * view, const view_mouse_event_t * event) {qnotused(view); qnotused(event); }
virtual void view_curpos(TWidget * view) {qnotused(view); }
virtual void view_created(TWidget * view) {qnotused(view); }
virtual void view_close(TWidget * view) {qnotused(view); }
virtual void view_switched(TWidget * view, tcc_renderer_type_t rt) {qnotused(view); qnotused(rt); }
virtual void view_mouse_over(TWidget * view, const view_mouse_event_t * event) {qnotused(view); qnotused(event); }
virtual void view_loc_changed(TWidget * view, const lochist_entry_t * now, const lochist_entry_t * was) {qnotused(view); qnotused(now); qnotused(was); }
virtual void view_mouse_moved(TWidget * view, const view_mouse_event_t * event) {qnotused(view); qnotused(event); }
};
//</inline(py_kernwin_viewhooks)>
%}

%{
//<code(py_kernwin_viewhooks)>
//---------------------------------------------------------------------------
ssize_t idaapi View_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class View_Hooks *proxy = (class View_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( notification_code )
    {
      // hookgenVIEW:notifications
case view_activated:
{
  TWidget * view = va_arg(va, TWidget *);
  proxy->view_activated(view);
}
break;

case view_deactivated:
{
  TWidget * view = va_arg(va, TWidget *);
  proxy->view_deactivated(view);
}
break;

case view_keydown:
{
  TWidget * view = va_arg(va, TWidget *);
  int key = va_arg(va, int);
  view_event_state_t state = va_arg(va, view_event_state_t);
  proxy->view_keydown(view, key, state);
}
break;

case view_click:
{
  TWidget * view = va_arg(va, TWidget *);
  const view_mouse_event_t * event = va_arg(va, const view_mouse_event_t *);
  proxy->view_click(view, event);
}
break;

case view_dblclick:
{
  TWidget * view = va_arg(va, TWidget *);
  const view_mouse_event_t * event = va_arg(va, const view_mouse_event_t *);
  proxy->view_dblclick(view, event);
}
break;

case view_curpos:
{
  TWidget * view = va_arg(va, TWidget *);
  proxy->view_curpos(view);
}
break;

case view_created:
{
  TWidget * view = va_arg(va, TWidget *);
  proxy->view_created(view);
}
break;

case view_close:
{
  TWidget * view = va_arg(va, TWidget *);
  proxy->view_close(view);
}
break;

case view_switched:
{
  TWidget * view = va_arg(va, TWidget *);
  tcc_renderer_type_t rt = tcc_renderer_type_t(va_arg(va, int));
  proxy->view_switched(view, rt);
}
break;

case view_mouse_over:
{
  TWidget * view = va_arg(va, TWidget *);
  const view_mouse_event_t * event = va_arg(va, const view_mouse_event_t *);
  proxy->view_mouse_over(view, event);
}
break;

case view_loc_changed:
{
  TWidget * view = va_arg(va, TWidget *);
  const lochist_entry_t * now = va_arg(va, const lochist_entry_t *);
  const lochist_entry_t * was = va_arg(va, const lochist_entry_t *);
  proxy->view_loc_changed(view, now, was);
}
break;

case view_mouse_moved:
{
  TWidget * view = va_arg(va, TWidget *);
  const view_mouse_event_t * event = va_arg(va, const view_mouse_event_t *);
  proxy->view_mouse_moved(view, event);
}
break;

    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in View Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return 0;
}
//</code(py_kernwin_viewhooks)>
%}

%pythoncode %{
#<pycode(py_kernwin_viewhooks)>
# -----------------------------------------------------------------------
#                           CustomIDAMemo
# -----------------------------------------------------------------------
class CustomIDAMemo(View_Hooks):
    def __init__(self):
        View_Hooks.__init__(self)

    def _graph_item_tuple(self, ve):
        item = None
        if ve.rtype in [TCCRT_GRAPH, TCCRT_PROXIMITY]:
            item = ve.location.item
        if item is not None:
            if item.is_node:
                return (item.node,)
            else:
                return (item.elp.e.src, item.elp.e.dst)
        else:
            return ()

    @staticmethod
    def _dummy_cb(*args):
        pass

    def _get_cb(self, view, cb_name):
        cb = CustomIDAMemo._dummy_cb
        if view == self.GetWidget():
            cb = getattr(self, cb_name, cb)
        return cb

    def _get_cb_arity(self, cb):
        from inspect import getargspec
        return len(getargspec(cb).args)

    def view_activated(self, view):
        return self._get_cb(view, "OnViewActivated")()

    def view_deactivated(self, view):
        return self._get_cb(view, "OnViewDeactivated")()

    def view_keydown(self, view, key, state):
        return self._get_cb(view, "OnViewKeydown")(key, state)

    def view_click(self, view, ve):
        cb = self._get_cb(view, "OnViewClick")
        if cb != CustomIDAMemo._dummy_cb:
            arity = self._get_cb_arity(cb)
            args = [ve.x, ve.y, ve.state]
            if arity >= 5:
                args.append(ve.button)
                if arity >= 6:
                    args.append(ve.renderer_pos)
            return cb(*tuple(args))

    def view_dblclick(self, view, ve):
        cb = self._get_cb(view, "OnViewDblclick")
        if cb != CustomIDAMemo._dummy_cb:
            arity = self._get_cb_arity(cb)
            args = [ve.x, ve.y, ve.state]
            if arity >= 5:
                args.append(ve.renderer_pos)
            return cb(*tuple(args))

    def view_curpos(self, view, *args):
        return self._get_cb(view, "OnViewCurpos")()

    def view_close(self, view, *args):
        rc = self._get_cb(view, "OnClose")()
        if view == self.GetWidget():
            ida_idaapi.pycim_view_close(self)
        return rc

    def view_switched(self, view, rt):
        return self._get_cb(view, "OnViewSwitched")(rt)

    def view_mouse_over(self, view, ve):
        cb = self._get_cb(view, "OnViewMouseOver")
        if cb != CustomIDAMemo._dummy_cb:
            arity = self._get_cb_arity(cb)
            gitpl = self._graph_item_tuple(ve)
            args = [ve.x, ve.y, ve.state, len(gitpl), gitpl]
            if arity >= 7:
                args.append(ve.renderer_pos)
            return cb(*tuple(args))

    def view_loc_changed(self, view, now, was):
        return self._get_cb(view, "OnViewLocationChanged")(now, was)

    def view_mouse_moved(self, view, ve):
        cb = self._get_cb(view, "OnViewMouseMoved")
        if cb != CustomIDAMemo._dummy_cb:
            gitpl = self._graph_item_tuple(ve)
            return cb(ve.x, ve.y, ve.state, len(gitpl), gitpl, ve.renderer_pos)

    # End of hooks->wrapper trampolines


    def Refresh(self):
        """
        Refreshes the view. This causes the OnRefresh() to be called
        """
        ida_idaapi.pygc_refresh(self)

    def GetCurrentRendererType(self):
        return ida_idaapi.pygc_get_current_renderer_type(self)

    def SetCurrentRendererType(self, rtype):
        """
        Set the current view's renderer.

        @param rtype: The renderer type. Should be one of the idaapi.TCCRT_* values.
        """
        ida_idaapi.pygc_set_current_renderer_type(self, rtype)

    def SetNodeInfo(self, node_index, node_info, flags):
        """
        Set the properties for the given node.

        Example usage (set second nodes's bg color to red):
          inst = ...
          p = idaapi.node_info_t()
          p.bg_color = 0x00ff0000
          inst.SetNodeInfo(1, p, idaapi.NIF_BG_COLOR)

        @param node_index: The node index.
        @param node_info: An idaapi.node_info_t instance.
        @param flags: An OR'ed value of NIF_* values.
        """
        ida_idaapi.pygc_set_node_info(self, node_index, node_info, flags)

    def SetNodesInfos(self, values):
        """
        Set the properties for the given nodes.

        Example usage (set first three nodes's bg color to purple):
          inst = ...
          p = idaapi.node_info_t()
          p.bg_color = 0x00ff00ff
          inst.SetNodesInfos({0 : p, 1 : p, 2 : p})

        @param values: A dictionary of 'int -> node_info_t' objects.
        """
        ida_idaapi.pygc_set_nodes_infos(self, values)

    def GetNodeInfo(self, node):
        """
        Get the properties for the given node.

        @param node: The index of the node.
        @return: A tuple (bg_color, frame_color, ea, text), or None.
        """
        return ida_idaapi.pygc_get_node_info(self, node)

    def DelNodesInfos(self, *nodes):
        """
        Delete the properties for the given node(s).

        @param nodes: A list of node IDs
        """
        return ida_idaapi.pygc_del_nodes_infos(self, nodes)

    def CreateGroups(self, groups_infos):
        """
        Send a request to modify the graph by creating a
        (set of) group(s), and perform an animation.

        Each object in the 'groups_infos' list must be of the format:
        {
          "nodes" : [<int>, <int>, <int>, ...] # The list of nodes to group
          "text" : <string>                    # The synthetic text for that group
        }

        @param groups_infos: A list of objects that describe those groups.
        @return: A [<int>, <int>, ...] list of group nodes, or None (failure).
        """
        return ida_idaapi.pygc_create_groups(self, groups_infos)

    def DeleteGroups(self, groups, new_current = -1):
        """
        Send a request to delete the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param new_current: A node to focus on after the groups have been deleted
        @return: True on success, False otherwise.
        """
        return ida_idaapi.pygc_delete_groups(self, groups, new_current)

    def SetGroupsVisibility(self, groups, expand, new_current = -1):
        """
        Send a request to expand/collapse the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param expand: True to expand the group, False otherwise.
        @param new_current: A node to focus on after the groups have been expanded/collapsed.
        @return: True on success, False otherwise.
        """
        return ida_idaapi.pygc_set_groups_visibility(self, groups, expand, new_current)

    def GetWidget(self):
        """
        Return the TWidget underlying this view.

        @return: The TWidget underlying this view, or None.
        """
        return ida_idaapi.pycim_get_widget(self)

# ----------------------------------------------------------------------
# bw-compat/deprecated. You shouldn't rely on this in new code
import ida_idaapi
ida_idaapi.CustomIDAMemo = CustomIDAMemo

#</pycode(py_kernwin_viewhooks)>
%}


//-------------------------------------------------------------------------
//                               IDAView
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_idaview)>
//-------------------------------------------------------------------------
//                                py_idaview_t
//-------------------------------------------------------------------------
class py_idaview_t : public py_customidamemo_t
{
  typedef py_customidamemo_t inherited;

public:
  static bool Bind(PyObject *self);
  static bool Unbind(PyObject *self);
};

//-------------------------------------------------------------------------
bool py_idaview_t::Bind(PyObject *self)
{
  // Already a py_idaview_t associated to this object?
  py_idaview_t *_this = view_extract_this<py_idaview_t>(self);
  if ( _this != NULL )
    return false;

  qstring title;
  if ( !PyW_GetStringAttr(self, S_M_TITLE, &title) )
    return false;

  // Get the IDAView associated to this TWidget
  TWidget *widget = find_widget(title.c_str());
  if ( widget == NULL )
    return false;

  // Get unique py_idaview_t associated to that TWidget
  py_idaview_t *py_view;
  if ( !pycim_lookup_info.find_by_view((py_customidamemo_t**) &py_view, widget) )
  {
    py_view = new py_idaview_t();
    lookup_entry_t &e = pycim_lookup_info.new_entry(py_view);
    pycim_lookup_info.commit(e, widget);
  }

  // Finally, bind:
  //  py_idaview_t <=> IDAViewWrapper
  //  py_idaview_t  => TWidget
  bool ok = py_view->bind(self, widget);
  if ( ok )
  {
    ok = py_view->collect_pyobject_callbacks(self);
    if ( !ok )
      delete py_view;
  }
  return ok;
}

//-------------------------------------------------------------------------
bool py_idaview_t::Unbind(PyObject *self)
{
  py_idaview_t *_this = view_extract_this<py_idaview_t>(self);
  if ( _this == NULL )
    return false;
  _this->unbind(true);
  return true;
}

//-------------------------------------------------------------------------
bool pyidag_bind(PyObject *self)
{
  return py_idaview_t::Bind(self);
}

//-------------------------------------------------------------------------
bool pyidag_unbind(PyObject *self)
{
  return py_idaview_t::Unbind(self);
}
//</code(py_kernwin_idaview)>

%}

%inline %{
//<inline(py_kernwin_idaview)>
bool pyidag_bind(PyObject *self);
bool pyidag_unbind(PyObject *self);
//</inline(py_kernwin_idaview)>
%}

%pythoncode %{
#<pycode(py_kernwin_idaview)>
#-------------------------------------------------------------------------
#                             IDAViewWrapper
#-------------------------------------------------------------------------
import _ida_kernwin
class IDAViewWrapper(CustomIDAMemo):
    """
    Deprecated. Use View_Hooks instead.

    Because the lifecycle of an IDAView is not trivial to track (e.g., a user
    might close, then re-open the same disassembly view), this wrapper doesn't
    bring anything superior to the View_Hooks: quite the contrary, as the
    latter is much more generic (and better maps IDA's internal model.)
    """
    def __init__(self, title):
        CustomIDAMemo.__init__(self)
        self._title = title

    def Bind(self):
        rc = _ida_kernwin.pyidag_bind(self)
        if rc:
            self.hook()
        return rc

    def Unbind(self):
        rc = _ida_kernwin.pyidag_unbind(self)
        if rc:
            self.unhook()
        return rc

#</pycode(py_kernwin_idaview)>
%}

//-------------------------------------------------------------------------
//                          simplecustviewer_t
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_custview)>
//---------------------------------------------------------------------------
// Base class for all custviewer place_t providers
class custviewer_data_t
{
public:
  virtual void    *get_ud() = 0;
  virtual place_t *get_min() = 0;
  virtual place_t *get_max() = 0;
};

//---------------------------------------------------------------------------
class cvdata_simpleline_t: public custviewer_data_t
{
private:
  strvec_t lines;
  simpleline_place_t pl_min, pl_max;
public:

  void *get_ud()
  {
    return &lines;
  }

  place_t *get_min()
  {
    return &pl_min;
  }

  place_t *get_max()
  {
    return &pl_max;
  }

  strvec_t &get_lines()
  {
    return lines;
  }

  void set_minmax(size_t start=0, size_t end=size_t(-1))
  {
    if ( start == 0 && end == size_t(-1) )
    {
      end = lines.size();
      pl_min.n = 0;
      pl_max.n = end == 0 ? 0 : end - 1;
    }
    else
    {
      pl_min.n = start;
      pl_max.n = end;
    }
  }

  bool set_line(size_t nline, simpleline_t &sl)
  {
    if ( nline >= lines.size() )
      return false;
    lines[nline] = sl;
    return true;
  }

  bool del_line(size_t nline)
  {
    if ( nline >= lines.size() )
      return false;
    lines.erase(lines.begin()+nline);
    return true;
  }

  void add_line(simpleline_t &line)
  {
    lines.push_back(line);
  }

  void add_line(const char *str)
  {
    lines.push_back(simpleline_t(str));
  }

  bool insert_line(size_t nline, simpleline_t &line)
  {
    if ( nline >= lines.size() )
      return false;
    lines.insert(lines.begin()+nline, line);
    return true;
  }

  bool patch_line(size_t nline, size_t offs, int value)
  {
    if ( nline >= lines.size() )
      return false;
    qstring &L = lines[nline].line;
    L[offs] = (uchar) value & 0xFF;
    return true;
  }

  const size_t to_lineno(place_t *pl) const
  {
    return ((simpleline_place_t *)pl)->n;
  }

  bool curline(place_t *pl, size_t *n)
  {
    if ( pl == NULL )
      return false;

    *n = to_lineno(pl);
    return true;
  }

  simpleline_t *get_line(size_t nline)
  {
    return nline >= lines.size() ? NULL : &lines[nline];
  }

  simpleline_t *get_line(place_t *pl)
  {
    return pl == NULL ? NULL : get_line(((simpleline_place_t *)pl)->n);
  }

  const size_t count() const
  {
    return lines.size();
  }

  void clear_lines()
  {
    lines.clear();
    set_minmax();
  }
};

//---------------------------------------------------------------------------
// FIXME: This should inherit py_view_base.hpp's py_customidamemo_t,
// just like py_graph.hpp's py_graph_t does.
// There should be a way to "merge" the two mechanisms; they are similar.
class customviewer_t
{
protected:
  qstring _title;
  TWidget *_cv;
  custviewer_data_t *_data;
  int _features;
  custom_viewer_handlers_t handlers;

  enum
  {
    HAVE_HINT     = 0x0001,
    HAVE_KEYDOWN  = 0x0002,
    HAVE_DBLCLICK = 0x0004,
    HAVE_CURPOS   = 0x0008,
    HAVE_CLICK    = 0x0010,
    HAVE_CLOSE    = 0x0020
  };
private:
  struct cvw_popupctx_t
  {
    size_t menu_id;
    customviewer_t *cv;
    cvw_popupctx_t(): menu_id(0), cv(NULL) {}
    cvw_popupctx_t(size_t mid, customviewer_t *v): menu_id(mid), cv(v) {}
  };
  typedef std::map<unsigned int, cvw_popupctx_t> cvw_popupmap_t;
  static size_t _global_popup_id;
  qstring _curline;

  static bool idaapi s_cv_keydown(
          TWidget * /*cv*/,
          int vk_key,
          int shift,
          void *ud)
  {
    PYW_GIL_GET;
    customviewer_t *_this = (customviewer_t *)ud;
    return _this->on_keydown(vk_key, shift);
  }

  // The user clicked
  static bool idaapi s_cv_click(TWidget * /*cv*/, int shift, void *ud)
  {
    PYW_GIL_GET;
    customviewer_t *_this = (customviewer_t *)ud;
    return _this->on_click(shift);
  }

  // The user double clicked
  static bool idaapi s_cv_dblclick(TWidget * /*cv*/, int shift, void *ud)
  {
    PYW_GIL_GET;
    customviewer_t *_this = (customviewer_t *)ud;
    return _this->on_dblclick(shift);
  }

  // Cursor position has been changed
  static void idaapi s_cv_curpos(TWidget * /*cv*/, void *ud)
  {
    PYW_GIL_GET;
    customviewer_t *_this = (customviewer_t *)ud;
    _this->on_curpos_changed();
  }

  //--------------------------------------------------------------------------
  static ssize_t idaapi s_ui_cb(void *ud, int code, va_list va)
  {
    // This hook gets called from the kernel. Ensure we hold the GIL.
    PYW_GIL_GET;
    customviewer_t *_this = (customviewer_t *)ud;
    switch ( code )
    {
      case ui_get_custom_viewer_hint:
        {
          qstring &hint = *va_arg(va, qstring *);
          TWidget *viewer = va_arg(va, TWidget *);
          place_t *place = va_arg(va, place_t *);
          int *important_lines = va_arg(va, int *);
          if ( (_this->_features & HAVE_HINT) == 0
            || place == NULL
            || _this->_cv != viewer )
          {
            return 0;
          }
          return _this->on_hint(place, important_lines, hint) ? 1 : 0;
        }

      case ui_widget_invisible:
        {
          TWidget *widget = va_arg(va, TWidget *);
          if ( _this->_cv != widget )
            break;
        }
        // fallthrough...
      case ui_term:
        idapython_unhook_from_notification_point(HT_UI, s_ui_cb, _this);
        _this->on_close();
        _this->on_post_close();
        break;
    }

    return 0;
  }

  void on_post_close()
  {
    init_vars();
  }

public:

  inline TWidget *get_widget() { return _cv; }

  //
  // All the overridable callbacks
  //

  // OnClick
  virtual bool on_click(int /*shift*/) { return false; }

  // OnDblClick
  virtual bool on_dblclick(int /*shift*/) { return false; }

  // OnCurorPositionChanged
  virtual void on_curpos_changed() {}

  // OnHostFormClose
  virtual void on_close() {}

  // OnKeyDown
  virtual bool on_keydown(int /*vk_key*/, int /*shift*/) { return false; }

  // OnHint
  virtual bool on_hint(place_t * /*place*/, int * /*important_lines*/, qstring &/*hint*/) { return false; }

  // OnPopupMenuClick
  virtual bool on_popup_menu(size_t menu_id) { return false; }

  void init_vars()
  {
    _data = NULL;
    _features = 0;
    _curline.clear();
    _cv = NULL;
  }

  customviewer_t()
  {
    init_vars();
  }

  ~customviewer_t()
  {
  }

  //--------------------------------------------------------------------------
  void close()
  {
    if ( _cv != NULL )
      close_widget(_cv, WCLS_SAVE | WCLS_CLOSE_LATER);
  }

  //--------------------------------------------------------------------------
  bool set_range(
    const place_t *minplace = NULL,
    const place_t *maxplace = NULL)
  {
    if ( _cv == NULL )
      return false;

    set_custom_viewer_range(
      _cv,
      minplace == NULL ? _data->get_min() : minplace,
      maxplace == NULL ? _data->get_max() : maxplace);
    return true;
  }

  place_t *get_place(
    bool mouse = false,
    int *x = 0,
    int *y = 0)
  {
    return _cv == NULL ? NULL : get_custom_viewer_place(_cv, mouse, x, y);
  }

  //--------------------------------------------------------------------------
  bool refresh()
  {
    if ( _cv == NULL )
      return false;

    refresh_custom_viewer(_cv);
    return true;
  }

  //--------------------------------------------------------------------------
  bool refresh_current()
  {
    return refresh();
  }

  //--------------------------------------------------------------------------
  bool get_current_word(bool mouse, qstring &word)
  {
    // query the cursor position
    int x, y;
    if ( get_place(mouse, &x, &y) == NULL )
      return false;

    // query the line at the cursor
    const char *line = get_current_line(mouse, true);
    if ( line == NULL )
      return false;

    if ( x >= (int)strlen(line) )
      return false;

    // find the beginning of the word
    const char *ptr = line + x;
    while ( ptr > line && !qisspace(ptr[-1]) )
      ptr--;

    // find the end of the word
    const char *begin = ptr;
    ptr = line + x;
    while ( !qisspace(*ptr) && *ptr != '\0' )
      ptr++;

    word.qclear();
    word.append(begin, ptr-begin);
    return true;
  }

  //--------------------------------------------------------------------------
  const char *get_current_line(bool mouse, bool notags)
  {
    const char *r = get_custom_viewer_curline(_cv, mouse);
    if ( r == NULL || !notags )
      return r;

    _curline = r;
    tag_remove(&_curline);
    return _curline.c_str();
  }

  //--------------------------------------------------------------------------
  bool is_focused()
  {
    return get_current_viewer() == _cv;
  }

  //--------------------------------------------------------------------------
  bool jumpto(place_t *place, int x, int y)
  {
    return ::jumpto(_cv, place, x, y);
  }

  bool create(const char *title, int features, custviewer_data_t *data)
  {
    // Already created? (in the instance)
    if ( _cv != NULL )
      return true;

    // Already created? (in IDA windows list)
    TWidget *found = find_widget(title);
    if ( found != NULL )
      return false;

    _title    = title;
    _data     = data;
    _features = features;

    //
    // Prepare handlers
    //
    if ( (features & HAVE_KEYDOWN) != 0 )
      handlers.keyboard = s_cv_keydown;

    if ( (features & HAVE_CLICK) != 0 )
      handlers.click = s_cv_click;

    if ( (features & HAVE_DBLCLICK) != 0 )
      handlers.dblclick = s_cv_dblclick;

    if ( (features & HAVE_CURPOS) != 0 )
      handlers.curpos = s_cv_curpos;

    // Create the viewer
    _cv = create_custom_viewer(
      title,
      _data->get_min(),
      _data->get_max(),
      _data->get_min(),
      (const renderer_info_t *) NULL,
      _data->get_ud(),
      &handlers,
      this);

    // Hook to UI notifications (for TWidget close event)
    idapython_hook_to_notification_point(HT_UI, s_ui_cb, this);

    return true;
  }

  //--------------------------------------------------------------------------
  bool show()
  {
    // Closed already?
    if ( _cv == NULL )
      return false;

    display_widget(_cv, WOPN_TAB|WOPN_RESTORE);
    return true;
  }
};

size_t customviewer_t::_global_popup_id = 0;
//---------------------------------------------------------------------------
class py_simplecustview_t: public customviewer_t
{
private:
  cvdata_simpleline_t data;
  PyObject *py_self, *py_this, *py_last_link;
  int features;

  //-------------------------------------------------------------------------
  static bool get_color(uint32 *out, ref_t obj)
  {
    bool ok = PyLong_Check(obj.o);
    if ( ok )
    {
      *out = uint32(PyLong_AsUnsignedLong(obj.o));
    }
    else
    {
      ok = IDAPyInt_Check(obj.o);
      if ( ok )
        *out = uint32(IDAPyInt_AsLong(obj.o));
    }
    return ok;
  }

  //--------------------------------------------------------------------------
  // Convert a tuple (String, [color, [bgcolor]]) to a simpleline_t
  static bool py_to_simpleline(PyObject *py, simpleline_t &sl)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    if ( IDAPyStr_Check(py) )
    {
      sl.line = IDAPyBytes_AsString(py);
      return true;
    }
    Py_ssize_t sz;
    if ( !PyTuple_Check(py) || (sz = PyTuple_Size(py)) <= 0 )
      return false;

    PyObject *py_val = PyTuple_GetItem(py, 0);
    if ( !IDAPyStr_Check(py_val) )
      return false;

    sl.line = IDAPyBytes_AsString(py_val);
    uint32 col;
    if ( sz > 1 && get_color(&col, borref_t(PyTuple_GetItem(py, 1))) )
      sl.color = color_t(col);
    if ( sz > 2 && get_color(&col, borref_t(PyTuple_GetItem(py, 2))) )
      sl.bgcolor = bgcolor_t(col);
    return true;
  }

  //
  // Callbacks
  //
  virtual bool on_click(int shift)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_CLICK, "i", shift));
    PyW_ShowCbErr(S_ON_CLICK);
    return py_result != NULL && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  // OnDblClick
  virtual bool on_dblclick(int shift)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_DBL_CLICK, "i", shift));
    PyW_ShowCbErr(S_ON_DBL_CLICK);
    return py_result != NULL && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  // OnCurorPositionChanged
  virtual void on_curpos_changed()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_CURSOR_POS_CHANGED, NULL));
    PyW_ShowCbErr(S_ON_CURSOR_POS_CHANGED);
  }

  //--------------------------------------------------------------------------
  // OnHostFormClose
  virtual void on_close()
  {
    if ( py_self != NULL )
    {
      // Call the close method if it is there and the object is still bound
      if ( (features & HAVE_CLOSE) != 0 )
      {
        PYW_GIL_CHECK_LOCKED_SCOPE();
        newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_CLOSE, NULL));
        PyW_ShowCbErr(S_ON_CLOSE);
      }

      // Cleanup
      Py_DECREF(py_self);
      py_self = NULL;
    }
  }

  //--------------------------------------------------------------------------
  // OnKeyDown
  virtual bool on_keydown(int vk_key, int shift)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(
            PyObject_CallMethod(
                    py_self,
                    (char *)S_ON_KEYDOWN,
                    "ii",
                    vk_key,
                    shift));

    PyW_ShowCbErr(S_ON_KEYDOWN);
    return py_result != NULL && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  // OnHint
  virtual bool on_hint(place_t *place, int *important_lines, qstring &hint)
  {
    size_t ln = data.to_lineno(place);
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(
            PyObject_CallMethod(
                    py_self,
                    (char *)S_ON_HINT,
                    PY_BV_SZ,
                    bvsz_t(ln)));

    PyW_ShowCbErr(S_ON_HINT);
    bool ok = py_result != NULL && PyTuple_Check(py_result.o) && PyTuple_Size(py_result.o) == 2;
    if ( ok )
    {
      if ( important_lines != NULL )
        *important_lines = IDAPyInt_AsLong(PyTuple_GetItem(py_result.o, 0));
      hint = IDAPyBytes_AsString(PyTuple_GetItem(py_result.o, 1));
    }
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnPopupMenuClick
  virtual bool on_popup_menu(size_t menu_id)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(
            PyObject_CallMethod(
                    py_self,
                    (char *)S_ON_POPUP_MENU,
                    PY_BV_SZ,
                    bvsz_t(menu_id)));
    PyW_ShowCbErr(S_ON_POPUP_MENU);
    return py_result != NULL && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  void refresh_range()
  {
    data.set_minmax();
    set_range();
  }

public:
  py_simplecustview_t()
  {
    py_this = py_self = py_last_link = NULL;
  }
  ~py_simplecustview_t()
  {
  }

  //--------------------------------------------------------------------------
  // Edits an existing line
  bool edit_line(size_t nline, PyObject *py_sl)
  {
    simpleline_t sl;
    if ( !py_to_simpleline(py_sl, sl) )
      return false;

    return data.set_line(nline, sl);
  }

  // Low level: patches a line string directly
  bool patch_line(size_t nline, size_t offs, int value)
  {
    return data.patch_line(nline, offs, value);
  }

  // Insert a line
  bool insert_line(size_t nline, PyObject *py_sl)
  {
    simpleline_t sl;
    if ( !py_to_simpleline(py_sl, sl) )
      return false;
    return data.insert_line(nline, sl);
  }

  // Adds a line tuple
  bool add_line(PyObject *py_sl)
  {
    simpleline_t sl;
    if ( !py_to_simpleline(py_sl, sl) )
      return false;
    data.add_line(sl);
    refresh_range();
    return true;
  }

  //--------------------------------------------------------------------------
  bool del_line(size_t nline)
  {
    bool ok = data.del_line(nline);
    if ( ok )
      refresh_range();
    return ok;
  }

  //--------------------------------------------------------------------------
  // Gets the position and returns a tuple (lineno, x, y)
  PyObject *get_pos(bool mouse)
  {
    place_t *pl;
    int x, y;
    pl = get_place(mouse, &x, &y);
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( pl == NULL )
      Py_RETURN_NONE;
    return Py_BuildValue("(" PY_BV_SZ "ii)", bvsz_t(data.to_lineno(pl)), x, y);
  }

  //--------------------------------------------------------------------------
  // Returns the line tuple
  PyObject *get_line(size_t nline)
  {
    simpleline_t *r = data.get_line(nline);
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( r == NULL )
      Py_RETURN_NONE;
    return Py_BuildValue("(sII)", r->line.c_str(), (unsigned int)r->color, (unsigned int)r->bgcolor);
  }

  // Returns the count of lines
  const size_t count() const
  {
    return data.count();
  }

  // Clears lines
  void clear()
  {
    data.clear_lines();
    refresh_range();
  }

  //--------------------------------------------------------------------------
  bool jumpto(size_t ln, int x, int y)
  {
    simpleline_place_t l(ln);
    return customviewer_t::jumpto(&l, x, y);
  }

  //--------------------------------------------------------------------------
  // Initializes and links the Python object to this class
  bool init(PyObject *py_link, const char *title)
  {
    // Already created?
    if ( _cv != NULL )
      return true;

    // Probe callbacks
    features = 0;
    static struct
    {
      const char *cb_name;
      int feature;
    } const cbtable[] =
    {
      { S_ON_CLICK,              HAVE_CLICK },
      { S_ON_CLOSE,              HAVE_CLOSE },
      { S_ON_HINT,               HAVE_HINT },
      { S_ON_KEYDOWN,            HAVE_KEYDOWN },
      { S_ON_DBL_CLICK,          HAVE_DBLCLICK },
      { S_ON_CURSOR_POS_CHANGED, HAVE_CURPOS }
    };

    PYW_GIL_CHECK_LOCKED_SCOPE();
    for ( size_t i=0; i < qnumber(cbtable); i++ )
    {
      if ( PyObject_HasAttrString(py_link, cbtable[i].cb_name) )
        features |= cbtable[i].feature;
    }

    if ( !create(title, features, &data) )
      return false;

    // Hold a reference to this object
    py_last_link = py_self = py_link;
    Py_INCREF(py_self);

    // Return a reference to the C++ instance (only once)
    if ( py_this == NULL )
      py_this = PyCapsule_New(this,VALID_CAPSULE_NAME, NULL);

    return true;
  }

  //--------------------------------------------------------------------------
  bool show()
  {
    if ( _cv == NULL && py_last_link != NULL )
    {
      // Re-create the view (with same previous parameters)
      if ( !init(py_last_link, _title.c_str()) )
        return false;
    }
    return customviewer_t::show();
  }

  //--------------------------------------------------------------------------
  bool get_selection(size_t *x1, size_t *y1, size_t *x2, size_t *y2)
  {
    if ( _cv == NULL )
      return false;

    twinpos_t p1, p2;
    if ( !::read_selection(_cv, &p1, &p2) )
      return false;

    if ( y1 != NULL )
      *y1 = data.to_lineno(p1.at);
    if ( y2 != NULL )
      *y2 = data.to_lineno(p2.at);
    if ( x1 != NULL )
      *x1 = size_t(p1.x);
    if ( x2 != NULL )
      *x2 = p2.x;
    return true;
  }

  PyObject *py_get_selection()
  {
    size_t x1, y1, x2, y2;
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( !get_selection(&x1, &y1, &x2, &y2) )
      Py_RETURN_NONE;
    return Py_BuildValue(
            "(" PY_BV_SZ PY_BV_SZ PY_BV_SZ PY_BV_SZ ")",
            bvsz_t(x1), bvsz_t(y1), bvsz_t(x2), bvsz_t(y2));
  }

  static py_simplecustview_t *get_this(PyObject *py_this)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    return PyCapsule_IsValid(py_this, VALID_CAPSULE_NAME) ? (py_simplecustview_t *) PyCapsule_GetPointer(py_this, VALID_CAPSULE_NAME) : NULL;
  }

  PyObject *get_pythis()
  {
    return py_this;
  }
};

//</code(py_kernwin_custview)>
%}

%inline %{
//<inline(py_kernwin_custview)>
//
// Pywraps Simple Custom Viewer functions
//
PyObject *pyscv_init(PyObject *py_link, const char *title)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  py_simplecustview_t *_this = new py_simplecustview_t();
  bool ok = _this->init(py_link, title);
  if ( !ok )
  {
    delete _this;
    Py_RETURN_NONE;
  }
  return _this->get_pythis();
}
#define DECL_THIS py_simplecustview_t *_this = py_simplecustview_t::get_this(py_this)

//--------------------------------------------------------------------------
bool pyscv_refresh(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  return _this->refresh();
}

//--------------------------------------------------------------------------
bool pyscv_delete(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  _this->close();
  delete _this;
  return true;
}

//--------------------------------------------------------------------------
bool pyscv_refresh_current(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  return _this->refresh_current();
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_current_line(PyObject *py_this, bool mouse, bool notags)
{
  DECL_THIS;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  const char *line;
  if ( _this == NULL || (line = _this->get_current_line(mouse, notags)) == NULL )
    Py_RETURN_NONE;
  return IDAPyStr_FromUTF8(line);
}

//--------------------------------------------------------------------------
bool pyscv_is_focused(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  return _this->is_focused();
}

size_t pyscv_count(PyObject *py_this)
{
  DECL_THIS;
  return _this == NULL ? 0 : _this->count();
}

bool pyscv_show(PyObject *py_this)
{
  DECL_THIS;
  return _this == NULL ? false : _this->show();
}

void pyscv_close(PyObject *py_this)
{
  DECL_THIS;
  if ( _this != NULL )
    _this->close();
}

bool pyscv_jumpto(PyObject *py_this, size_t ln, int x, int y)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  return _this->jumpto(ln, x, y);
}

// Returns the line tuple
PyObject *pyscv_get_line(PyObject *py_this, size_t nline)
{
  DECL_THIS;
  if ( _this == NULL )
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  }
  return _this->get_line(nline);
}

//--------------------------------------------------------------------------
// Gets the position and returns a tuple (lineno, x, y)
PyObject *pyscv_get_pos(PyObject *py_this, bool mouse)
{
  DECL_THIS;
  if ( _this == NULL )
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  }
  return _this->get_pos(mouse);
}

//--------------------------------------------------------------------------
PyObject *pyscv_clear_lines(PyObject *py_this)
{
  DECL_THIS;
  if ( _this != NULL )
    _this->clear();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_RETURN_NONE;
}

//--------------------------------------------------------------------------
// Adds a line tuple
bool pyscv_add_line(PyObject *py_this, PyObject *py_sl)
{
  DECL_THIS;
  return _this == NULL ? false : _this->add_line(py_sl);
}

//--------------------------------------------------------------------------
bool pyscv_insert_line(PyObject *py_this, size_t nline, PyObject *py_sl)
{
  DECL_THIS;
  return _this == NULL ? false : _this->insert_line(nline, py_sl);
}

//--------------------------------------------------------------------------
bool pyscv_patch_line(PyObject *py_this, size_t nline, size_t offs, int value)
{
  DECL_THIS;
  return _this == NULL ? false : _this->patch_line(nline, offs, value);
}

//--------------------------------------------------------------------------
bool pyscv_del_line(PyObject *py_this, size_t nline)
{
  DECL_THIS;
  return _this == NULL ? false : _this->del_line(nline);
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_selection(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  }
  return _this->py_get_selection();
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_current_word(PyObject *py_this, bool mouse)
{
  DECL_THIS;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( _this != NULL )
  {
    qstring word;
    if ( _this->get_current_word(mouse, word) )
      return IDAPyStr_FromUTF8(word.c_str());
  }
  Py_RETURN_NONE;
}

//--------------------------------------------------------------------------
// Edits an existing line
bool pyscv_edit_line(PyObject *py_this, size_t nline, PyObject *py_sl)
{
  DECL_THIS;
  return _this == NULL ? false : _this->edit_line(nline, py_sl);
}

//-------------------------------------------------------------------------
TWidget *pyscv_get_widget(PyObject *py_this)
{
  DECL_THIS;
  return _this == NULL ? NULL : _this->get_widget();
}


#undef DECL_THIS
//</inline(py_kernwin_custview)>
%}

%pythoncode %{
#<pycode(py_kernwin_custview)>
class simplecustviewer_t(object):
    """The base class for implementing simple custom viewers"""

    class UI_Hooks_Trampoline(UI_Hooks):
        def __init__(self, v):
            UI_Hooks.__init__(self)
            self.hook()
            import weakref
            self.v = weakref.ref(v)

        def populating_widget_popup(self, form, popup_handle):
            my_form = self.v().GetWidget()
            if form == my_form:
                cb = self.v().OnPopup
                from inspect import getargspec
                if len(getargspec(cb).args) == 3:
                    cb(my_form, popup_handle)
                else:
                    cb() # bw-compat

    def __init__(self):
        self.__this = None
        self.ui_hooks_trampoline = self.UI_Hooks_Trampoline(self)

    def __del__(self):
        """Destructor. It also frees the associated C++ object"""
        try:
            _ida_kernwin.pyscv_delete(self.__this)
        except:
            pass

    @staticmethod
    def __make_sl_arg(line, fgcolor=None, bgcolor=None):
        return line if (fgcolor is None and bgcolor is None) else (line, fgcolor, bgcolor)

    def OnPopup(self, form, popup_handle):
        """
        Context menu popup is about to be shown. Create items dynamically if you wish
        @return: Boolean. True if you handled the event
        """
        pass

    def Create(self, title):
        """
        Creates the custom view. This should be the first method called after instantiation

        @param title: The title of the view
        @return: Boolean whether it succeeds or fails. It may fail if a window with the same title is already open.
                 In this case better close existing windows
        """
        self.title = title
        self.__this = _ida_kernwin.pyscv_init(self, title)
        return True if self.__this else False

    def Close(self):
        """
        Destroys the view.
        One has to call Create() afterwards.
        Show() can be called and it will call Create() internally.
        @return: Boolean
        """
        return _ida_kernwin.pyscv_close(self.__this)

    def Show(self):
        """
        Shows an already created view. It the view was close, then it will call Create() for you
        @return: Boolean
        """
        return _ida_kernwin.pyscv_show(self.__this)

    def Refresh(self):
        return _ida_kernwin.pyscv_refresh(self.__this)

    def RefreshCurrent(self):
        """Refreshes the current line only"""
        return _ida_kernwin.pyscv_refresh_current(self.__this)

    def Count(self):
        """Returns the number of lines in the view"""
        return _ida_kernwin.pyscv_count(self.__this)

    def GetSelection(self):
        """
        Returns the selected range or None
        @return:
            - tuple(x1, y1, x2, y2)
            - None if no selection
        """
        return _ida_kernwin.pyscv_get_selection(self.__this)

    def ClearLines(self):
        """Clears all the lines"""
        _ida_kernwin.pyscv_clear_lines(self.__this)

    def AddLine(self, line, fgcolor=None, bgcolor=None):
        """
        Adds a colored line to the view
        @return: Boolean
        """
        return _ida_kernwin.pyscv_add_line(self.__this, self.__make_sl_arg(line, fgcolor, bgcolor))

    def InsertLine(self, lineno, line, fgcolor=None, bgcolor=None):
        """
        Inserts a line in the given position
        @return: Boolean
        """
        return _ida_kernwin.pyscv_insert_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def EditLine(self, lineno, line, fgcolor=None, bgcolor=None):
        """
        Edits an existing line.
        @return: Boolean
        """
        return _ida_kernwin.pyscv_edit_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def PatchLine(self, lineno, offs, value):
        """Patches an existing line character at the given offset. This is a low level function. You must know what you're doing"""
        return _ida_kernwin.pyscv_patch_line(self.__this, lineno, offs, value)

    def DelLine(self, lineno):
        """
        Deletes an existing line
        @return: Boolean
        """
        return _ida_kernwin.pyscv_del_line(self.__this, lineno)

    def GetLine(self, lineno):
        """
        Returns a line
        @param lineno: The line number
        @return:
            Returns a tuple (colored_line, fgcolor, bgcolor) or None
        """
        return _ida_kernwin.pyscv_get_line(self.__this, lineno)

    def GetCurrentWord(self, mouse = 0):
        """
        Returns the current word
        @param mouse: Use mouse position or cursor position
        @return: None if failed or a String containing the current word at mouse or cursor
        """
        return _ida_kernwin.pyscv_get_current_word(self.__this, mouse)

    def GetCurrentLine(self, mouse = 0, notags = 0):
        """
        Returns the current line.
        @param mouse: Current line at mouse pos
        @param notags: If True then tag_remove() will be called before returning the line
        @return: Returns the current line (colored or uncolored) or None on failure
        """
        return _ida_kernwin.pyscv_get_current_line(self.__this, mouse, notags)

    def GetPos(self, mouse = 0):
        """
        Returns the current cursor or mouse position.
        @param mouse: return mouse position
        @return: Returns a tuple (lineno, x, y)
        """
        return _ida_kernwin.pyscv_get_pos(self.__this, mouse)

    def GetLineNo(self, mouse = 0):
        """Calls GetPos() and returns the current line number or -1 on failure"""
        r = self.GetPos(mouse)
        return -1 if not r else r[0]

    def Jump(self, lineno, x=0, y=0):
        return _ida_kernwin.pyscv_jumpto(self.__this, lineno, x, y)

    def IsFocused(self):
        """Returns True if the current view is the focused view"""
        return _ida_kernwin.pyscv_is_focused(self.__this)

    def GetWidget(self):
        """
        Return the TWidget underlying this view.

        @return: The TWidget underlying this view, or None.
        """
        return _ida_kernwin.pyscv_get_widget(self.__this)



    # Here are all the supported events
#<pydoc>
#    def OnClick(self, shift):
#        """
#        User clicked in the view
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnClick, shift=%d" % shift
#        return True
#
#    def OnDblClick(self, shift):
#        """
#        User dbl-clicked in the view
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnDblClick, shift=%d" % shift
#        return True
#
#    def OnCursorPosChanged(self):
#        """
#        Cursor position changed.
#        @return: Nothing
#        """
#        print "OnCurposChanged"
#
#    def OnClose(self):
#        """
#        The view is closing. Use this event to cleanup.
#        @return: Nothing
#        """
#        print "OnClose"
#
#    def OnKeydown(self, vkey, shift):
#        """
#        User pressed a key
#        @param vkey: Virtual key code
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnKeydown, vk=%d shift=%d" % (vkey, shift)
#        return False
#
#    def OnHint(self, lineno):
#        """
#        Hint requested for the given line number.
#        @param lineno: The line number (zero based)
#        @return:
#            - tuple(number of important lines, hint string)
#            - None: if no hint available
#        """
#        return (1, "OnHint, line=%d" % lineno)
#
#    def OnPopupMenu(self, menu_id):
#        """
#        A context (or popup) menu item was executed.
#        @param menu_id: ID previously registered with add_popup_menu()
#        @return: Boolean
#        """
#        print "OnPopupMenu, menu_id=" % menu_id
#        return True
#</pydoc>
#</pycode(py_kernwin_custview)>
%}

//-------------------------------------------------------------------------
//                              PluginForm
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_plgform)>
//---------------------------------------------------------------------------
class plgform_t
{
  ref_t py_obj;
  TWidget *widget;

  static ssize_t idaapi s_callback(void *ud, int notification_code, va_list va)
  {
    // This hook gets called from the kernel. Ensure we hold the GIL.
    PYW_GIL_GET;

    plgform_t *_this = (plgform_t *)ud;
    if ( notification_code == ui_widget_invisible )
    {
      TWidget *widget = va_arg(va, TWidget *);
      if ( widget == _this->widget )
      {
        {
          newref_t py_result(
                  PyObject_CallMethod(
                          _this->py_obj.o,
                          (char *)S_ON_CLOSE, "O",
                          PyCapsule_New(widget, VALID_CAPSULE_NAME, NULL)));
          PyW_ShowCbErr(S_ON_CLOSE);
        }
        _this->unhook();
      }
    }
    return 0;
  }

  void unhook()
  {
    idapython_unhook_from_notification_point(HT_UI, s_callback, this);
    widget = NULL;

    // Call DECREF at last, since it may trigger __del__
    PYW_GIL_CHECK_LOCKED_SCOPE();
    py_obj = ref_t();
  }

public:
  plgform_t() : widget(NULL) {}

  bool show(
          PyObject *obj,
          const char *caption,
          int options)
  {
    const bool create_only = options == -1;

    // Already displayed?
    TWidget *f = find_widget(caption);
    if ( f != NULL )
    {
      // Our form?
      if ( f == widget )
      {
        // Switch to it
        if ( !create_only )
          activate_widget(widget, true);
        return true;
      }
      // Fail to create
      return false;
    }

    // Create a form
    widget = create_empty_widget(caption);
    if ( widget == NULL )
      return false;

    if ( !idapython_hook_to_notification_point(HT_UI, s_callback, this) )
    {
      widget = NULL;
      return false;
    }

    py_obj = borref_t(obj);

    this->widget = widget;

    // Qt: QWidget*
    // G: HWND
    // We wrap and pass as a CObject in the hope that a Python UI framework
    // can unwrap a CObject and get the hwnd/widget back
    newref_t py_result(
            PyObject_CallMethod(
                    py_obj.o,
                    (char *)S_ON_CREATE, "O",
                    PyCapsule_New(widget, VALID_CAPSULE_NAME, NULL)));
    PyW_ShowCbErr(S_ON_CREATE);

    if ( !create_only )
      display_widget(widget, options);
    return true;
  }

  void close(int options = 0)
  {
    if ( widget != NULL )
      close_widget(widget, options);
  }

  TWidget *get_widget() { return widget; }

  static PyObject *create()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    return PyCapsule_New(new plgform_t(),VALID_CAPSULE_NAME, destroy);
  }

static void destroy(PyObject *py_obj)
  {
    if ( PyCapsule_IsValid(py_obj, VALID_CAPSULE_NAME) )
    {
      plgform_t *obj = (plgform_t *) PyCapsule_GetPointer(py_obj, VALID_CAPSULE_NAME);
      delete (plgform_t *) obj;
    }
  }
};
//</code(py_kernwin_plgform)>
%}

%inline %{
//<inline(py_kernwin_plgform)>
//---------------------------------------------------------------------------
#define DECL_PLGFORM PYW_GIL_CHECK_LOCKED_SCOPE(); plgform_t *plgform = (plgform_t *) PyCapsule_GetPointer(py_link, VALID_CAPSULE_NAME);
static PyObject *plgform_new()
{
  return plgform_t::create();
}

static bool plgform_show(
        PyObject *py_link,
        PyObject *py_obj,
        const char *caption,
        int options = WOPN_TAB|WOPN_RESTORE)
{
  DECL_PLGFORM;
  return plgform->show(py_obj, caption, options);
}

static void plgform_close(
        PyObject *py_link,
        int options)
{
  DECL_PLGFORM;
  plgform->close(options);
}

static TWidget *plgform_get_widget(
        PyObject *py_link)
{
  DECL_PLGFORM;
  return plgform->get_widget();
}

#undef DECL_PLGFORM
//</inline(py_kernwin_plgform)>
%}

%pythoncode %{
#<pycode(py_kernwin_plgform)>
import sys
class PluginForm(object):
    """
    PluginForm class.

    This form can be used to host additional controls. Please check the PyQt example.
    """

    WOPN_MDI      = 0x01 # no-op
    WOPN_TAB      = 0x02
    """attached by default to a tab"""
    WOPN_RESTORE  = 0x04
    """
    if the widget is the only widget in a floating area when
    it is closed, remember that area's geometry. The next
    time that widget is created as floating (i.e., no WOPN_TAB)
    its geometry will be restored (e.g., "Execute script"
    """
    WOPN_ONTOP    = 0x08 # no-op
    WOPN_MENU     = 0x10 # no-op
    WOPN_CENTERED = 0x20 # no-op
    WOPN_PERSIST  = 0x40
    """form will persist until explicitly closed with Close()"""


    WOPN_CREATE_ONLY = {}


    def __init__(self):
        """
        """
        self.__clink__ = _ida_kernwin.plgform_new()


    def Show(self, caption, options=0):
        """
        Creates the form if not was not created or brings to front if it was already created

        @param caption: The form caption
        @param options: One of PluginForm.WOPN_ constants
        """
        if options == self.WOPN_CREATE_ONLY:
            options = -1
        else:
            options |= PluginForm.WOPN_TAB|PluginForm.WOPN_RESTORE
        return _ida_kernwin.plgform_show(self.__clink__, self, caption, options)


    @staticmethod
    def _ensure_widget_deps(ctx):
        for key, modname in [("sip", "sip"), ("QtWidgets", "PyQt5.QtWidgets")]:
            if not hasattr(ctx, key):
                print("Note: importing '%s' module into %s" % (key, ctx))
                import importlib
                setattr(ctx, key, importlib.import_module(modname))


    @staticmethod
    def TWidgetToPyQtWidget(form, ctx = sys.modules['__main__']):
        """
        Convert a TWidget* to a QWidget to be used by PyQt

        @param ctx: Context. Reference to a module that already imported SIP and QtWidgets modules
        """
        if type(form).__name__ == "SwigPyObject":
            ptr_l = long(form)
        else:
            ptr_l = form
        PluginForm._ensure_widget_deps(ctx)
        vptr = ctx.sip.voidptr(ptr_l)
        return ctx.sip.wrapinstance(vptr.__int__(), ctx.QtWidgets.QWidget)
    FormToPyQtWidget = TWidgetToPyQtWidget


    @staticmethod
    def QtWidgetToTWidget(w, ctx = sys.modules['__main__']):
        """
        Convert a QWidget to a TWidget* to be used by IDA

        @param ctx: Context. Reference to a module that already imported SIP and QtWidgets modules
        """
        PluginForm._ensure_widget_deps(ctx)
        as_long = long(ctx.sip.unwrapinstance(w))
        return TWidget__from_ptrval__(as_long)


    @staticmethod
    def TWidgetToPySideWidget(tw, ctx = sys.modules['__main__']):
        """
        Use this method to convert a TWidget* to a QWidget to be used by PySide
        @param ctx: Context. Reference to a module that already imported QtWidgets module
        """
        if tw is None:
            return None
        if type(tw).__name__ == "SwigPyObject":
            # Since 'tw' is a SwigPyObject, we first need to convert it to a PyCapsule.
            # However, there's no easy way of doing it, so we'll use a rather brutal approach:
            # converting the SwigPyObject to a 'long' (will go through 'SwigPyObject_long',
            # that will return the pointer's value as a long), and then convert that value
            # back to a pointer into a PyCapsule.
            ptr_l = ida_idaapi.long_type(tw)
            # Warning: this is untested
            import ctypes
            ctypes.pythonapi.PyCapsule_New.restype = ctypes.py_object
            ctypes.pythonapi.PyCapsule_New.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
            tw = ctypes.pythonapi.PyCapsule_New(ptr_l, PluginForm.VALID_CAPSULE_NAME, 0)
        return ctx.QtGui.QWidget.FromCapsule(tw)
    FormToPySideWidget = TWidgetToPySideWidget

    def OnCreate(self, form):
        """
        This event is called when the plugin form is created.
        The programmer should populate the form when this event is triggered.

        @return: None
        """
        pass


    def OnClose(self, form):
        """
        Called when the plugin form is closed

        @return: None
        """
        pass


    def Close(self, options):
        """
        Closes the form.

        @param options: Close options (WCLS_SAVE, WCLS_NO_CONTEXT, ...)

        @return: None
        """
        return _ida_kernwin.plgform_close(self.__clink__, options)


    def GetWidget(self):
        """
        Return the TWidget underlying this view.

        @return: The TWidget underlying this view, or None.
        """
        return _ida_kernwin.plgform_get_widget(self.__clink__)


    WCLS_SAVE           = 0x1
    """Save state in desktop config"""

    WCLS_NO_CONTEXT     = 0x2
    """Don't change the current context (useful for toolbars)"""

    WCLS_DONT_SAVE_SIZE = 0x4
    """Don't save size of the window"""

    WCLS_CLOSE_LATER    = 0x8
    """This flag should be used when Close() is called from an event handler"""
#</pycode(py_kernwin_plgform)>
%}
%pythoncode %{
if _BC695:
    AST_DISABLE_FOR_FORM=AST_DISABLE_FOR_WIDGET
    AST_ENABLE_FOR_FORM=AST_ENABLE_FOR_WIDGET
    CB_CLOSE_IDB=CB_INVISIBLE
    chtype_generic2=chtype_generic
    chtype_segreg=chtype_srcp
    close_tform=close_widget
    find_tform=find_widget
    get_current_tform=get_current_widget
    def get_highlighted_identifier():
        thing = get_highlight(get_current_viewer())
        if thing and thing[1]:
            return thing[0]
    get_tform_title=get_widget_title
    get_tform_type=get_widget_type
    is_chooser_tform=is_chooser_widget
    open_tform=display_widget
    pyscv_get_tcustom_control=pyscv_get_widget
    pyscv_get_tform=pyscv_get_widget
    __read_selection70 = read_selection
    def read_selection(*args):
        if len(args) == 0:
            # bw-compat
            t0, t1, view = twinpos_t(), twinpos_t(), get_current_viewer()
            sel = __read_selection70(view, t0, t1)
            import ida_idaapi
            a0, a1 = ida_idaapi.BADADDR, ida_idaapi.BADADDR
            if sel:
                a0, a1 = t0.place(view).toea(), t1.place(view).toea()
            return sel, a0, a1
        else:
            return __read_selection70(*args)
    readsel2=read_selection
    switchto_tform=activate_widget
    umsg=msg
    import ida_ida
    def __wrap_uihooks_callback(name, do_call):
        return ida_ida.__wrap_hooks_callback(UI_Hooks, name, name.replace("widget", "tform"), do_call)
    __wrap_uihooks_callback("widget_visible", lambda cb, *args: cb(args[0], args[0]))
    __wrap_uihooks_callback("widget_invisible", lambda cb, *args: cb(args[0], args[0]))
    __wrap_uihooks_callback("populating_widget_popup", lambda cb, *args: cb(*args))
    __wrap_uihooks_callback("finish_populating_widget_popup", lambda cb, *args: cb(*args))
    __wrap_uihooks_callback("current_widget_changed", lambda cb, *args: cb(*args))
    AskUsingForm=_call_ask_form
    HIST_ADDR=0
    HIST_NUM=0
    KERNEL_VERSION_MAGIC1=0
    KERNEL_VERSION_MAGIC2=0
    OpenForm=_call_open_form
    _askaddr=_ida_kernwin._ask_addr
    _asklong=_ida_kernwin._ask_long
    _askseg=_ida_kernwin._ask_seg
    askaddr=ask_addr
    askbuttons_c=ask_buttons
    askfile_c=ask_file
    def askfile2_c(forsave, defdir, filters, fmt):
        if filters:
            fmt = "FILTER %s\n%s" % (filters, fmt)
        return ask_file(forsave, defdir, fmt)
    askident=ask_ident
    asklong=ask_long
    def askqstr(defval, fmt):
        return ask_str(defval, 0, fmt)
    askseg=ask_seg
    def askstr(hist, defval, fmt):
        return ask_str(defval, hist, fmt)
    asktext=ask_text
    askyn_c=ask_yn
    choose2_activate=choose_activate
    choose2_close=choose_close
    choose2_create=choose_create
    choose2_find=choose_find
    choose2_get_embedded=_choose_get_embedded_chobj_pointer
    choose2_get_embedded_selection=lambda *args: None
    choose2_refresh=choose_refresh
    clearBreak=clr_cancelled
    py_get_AskUsingForm=py_get_ask_form
    py_get_OpenForm=py_get_open_form
    setBreak=set_cancelled
    wasBreak=user_cancelled
    refresh_lists=refresh_choosers
    #--------------------------------------------------------------------------
    class BC695_control_cmd:
        def __init__(self, cmd_id, caption, flags, menu_index, icon, emb, shortcut, is_chooser):
            self.cmd_id = cmd_id
            self.caption = caption
            self.flags = flags
            self.menu_index = menu_index
            self.icon = icon
            self.emb = emb
            self.shortcut = shortcut
            self.is_chooser = is_chooser
        @staticmethod
        def add_to_control(control, caption, flags, menu_index, icon, emb, shortcut, is_chooser):
            if getattr(control, "commands", None) is None:
                setattr(control, "commands", [])
            found = filter(lambda x: x.caption == caption, control.commands)
            if len(found) == 1:
                cmd_id = found[0].cmd_id
            else:
                cmd_id = len(control.commands)
                cmd = BC695_control_cmd(cmd_id, caption, flags, menu_index, icon, emb, shortcut, is_chooser)
                control.commands.append(cmd)
            return cmd_id
        @staticmethod
        def populate_popup(control, widget, popup):
            cmds = getattr(control, "commands", [])
            for cmd in cmds:
                if (cmd.flags & CHOOSER_POPUP_MENU) != 0:
                    desc = action_desc_t(None, cmd.caption, BC695_control_cmd_ah_t(control, cmd), cmd.shortcut, None, cmd.icon)
                    attach_dynamic_action_to_popup(widget, popup, desc)
    class BC695_control_cmd_ah_t(action_handler_t):
        def __init__(self, control, cmd):
            action_handler_t.__init__(self)
            self.control = control
            self.cmd = cmd
        def activate(self, ctx):
            if self.cmd.is_chooser:
                idx = ctx.chooser_selection[0]
                self.control.OnCommand(idx, self.cmd.cmd_id)
            else:
                self.control.OnCommand(self.cmd.cmd_id)
        def update(self, ctx):
            return AST_ENABLE_ALWAYS
    class Choose2(object):
        """v.6.95 compatible chooser wrapper class."""
        CH_MODAL        = 0x01
        CH_MULTI        = 0x04
        CH_MULTI_EDIT   = 0x08
        """
        The OnEditLine() callback will be called for all
        selected items using the START_SEL/END_SEL
        protocol.
        This bit implies #CH_MULTI.
        """
        CH_NOBTNS       = 0x10
        CH_ATTRS        = 0x20
        CH_NOIDB        = 0x40
        CH_BUILTIN_SHIFT = 19
        CH_BUILTIN_MASK = 0x1F << CH_BUILTIN_SHIFT
        # column flags (are specified in the widths array)
        CHCOL_PLAIN  =  0x00000000
        CHCOL_PATH   =  0x00010000
        CHCOL_HEX    =  0x00020000
        CHCOL_DEC    =  0x00030000
        CHCOL_FORMAT =  0x00070000
        # special values of the chooser index
        NO_SELECTION   = -1
        """there is no selected item"""
        START_SEL      = -2
        """before calling the first selected item"""
        END_SEL        = -3
        """after calling the last selected item"""
        # the v.7.0 chooser object implementing the v.6.95 chooser
        class ChooseWrapper(Choose):
            def __init__(self, v695_chooser):
                self.link = v695_chooser
                # check what non-base callbacks we have
                forbidden_cb = 0
                for cb in [("OnInsertLine", Choose.CHOOSE_HAVE_INS    ),
                           ("OnDeleteLine", Choose.CHOOSE_HAVE_DEL    ),
                           ("OnEditLine",   Choose.CHOOSE_HAVE_EDIT   ),
                           ("OnSelectLine", Choose.CHOOSE_HAVE_ENTER  ),
                           ("OnRefresh",    Choose.CHOOSE_HAVE_REFRESH),
                           ("OnSelectionChange", Choose.CHOOSE_HAVE_SELECT)]:
                    if not hasattr(self.link, cb[0]) or \
                       not callable(getattr(self.link, cb[0])):
                        forbidden_cb |= cb[1]
                Choose.__init__(
                        self, self.link.title, self.link.cols,
                        forbidden_cb = forbidden_cb)
            # redirect base callbacks to the v.6.95 chooser
            def __getattr__(self, attr):
                if attr in ["OnGetSize",
                            "OnGetLine",
                            "OnGetIcon",
                            "OnGetLineAttr",
                            "OnClose"]:
                    return getattr(self.link, attr)
                return getattr(self.link, attr)
            def Show(self, modal = False):
                # set `flags` and `deflt`
                self.flags = self.link.flags
                if self.link.deflt == -1:
                    self.deflt = 0
                else:
                    self.deflt = self.link.deflt - 1
                    self.flags |= Choose.CH_FORCE_DEFAULT
                if (self.flags & Choose.CH_MULTI) != 0:
                    self.deflt = [self.deflt]
                # copy simple attributes from v.6.95
                for attr in ["title", "cols", "popup_names", "icon",
                             "x1", "y1", "x2", "y2",
                             "embedded", "width", "height"]:
                    if hasattr(self.link, attr):
                        setattr(self, attr, getattr(self.link, attr))
                    else:
                        delattr(self, attr)
                return Choose.Show(self, modal)
            def OnInsertLine(self, n):
                # assert: hasattr(self.link, "OnInsertLine")
                self.link.OnInsertLine()
                # we preserve the selection
                return (Choose.ALL_CHANGED, n)
                if (self.link.flags & Choose2.CH_MULTI) == 0:
                    return (Choose.ALL_CHANGED, n)
                else:
                    return [Choose.ALL_CHANGED] + n
            def OnDeleteLine(self, n):
                # assert: hasattr(self.link, "OnDeleteLine")
                res = None
                if (self.link.flags & Choose2.CH_MULTI) == 0:
                    res = self.link.OnDeleteLine(n)
                else:
                  # assert: n is iterable and n
                  # call the callback multiple times
                  self.link.OnDeleteLine(Choose2.START_SEL)
                  res = None
                  for idx in n:
                      new_idx = self.link.OnDeleteLine(idx)
                      if res == None:
                          res = new_idx
                  self.link.OnDeleteLine(Choose2.END_SEL)
                return [Choose.ALL_CHANGED] + self.adjust_last_item(res)
            def OnEditLine(self, n):
                # assert: hasattr(self.link, "OnEditLine")
                if (self.link.flags & Choose2.CH_MULTI) == 0:
                    self.link.OnEditLine(n)
                    return (Choose.ALL_CHANGED, n) # preserve the selection
                # assert: n is iterable and n
                if (self.link.flags & Choose2.CH_MULTI_EDIT) == 0:
                    self.link.OnEditLine(n[0])
                    return [Choose.ALL_CHANGED] + n # preserve the selection
                # call the callback multiple times
                self.link.OnEditLine(Choose2.START_SEL)
                for idx in n:
                    self.link.OnEditLine(idx)
                self.link.OnEditLine(Choose2.END_SEL)
                return [Choose.ALL_CHANGED] + n # preserve the selection
            def OnSelectLine(self, n):
                # assert: hasattr(self.link, "OnSelectLine")
                if (self.link.flags & Choose2.CH_MULTI) == 0:
                    self.link.OnSelectLine(n)
                    return (Choose.ALL_CHANGED, n)
                # assert: n is iterable and n
                self.link.OnSelectLine(n[0])
                return [Choose.ALL_CHANGED] + n # preserve the selection
            def OnRefresh(self, n):
                # assert: hasattr(self.link, "OnRefresh")
                if (self.link.flags & Choose2.CH_MULTI) != 0:
                  # ignore all but the first item
                  n = n[0] if n else Choose.NO_SELECTION
                res = self.link.OnRefresh(n)
                return (Choose.ALL_CHANGED, res)
            def OnSelectionChange(self, n):
                # assert: hasattr(self.link, "OnSelectionChange")
                if (self.link.flags & Choose2.CH_MULTI) == 0:
                  n = [n] if n != Choose.NO_SELECTION else []
                self.link.OnSelectionChange(n)
            def OnPopup(self, widget, popup_handle):
                BC695_control_cmd.populate_popup(
                    self.link,
                    widget,
                    popup_handle)
        def __init__(self, title, cols, flags=0, popup_names=None,
                     icon=-1, x1=-1, y1=-1, x2=-1, y2=-1, deflt=-1,
                     embedded=False, width=None, height=None):
            """
            Constructs a chooser window.
            @param title: The chooser title
            @param cols: a list of colums; each list item is a list of two items
                example: [ ["Address", 10 | Choose2.CHCOL_HEX],
                           ["Name", 30 | Choose2.CHCOL_PLAIN] ]
            @param flags: One of CH_XXXX constants
            @param deflt: Default starting item (1-based).
                0 means that no item is selected,
                -1 means that the first item selected for a new window and
                that the selection is not updated for an existing window
            @param popup_names: list of new captions to replace this list
                ["Insert", "Delete", "Edit", "Refresh"]
            @param icon: Icon index (the icon should exist in ida resources or
                an index to a custom loaded icon)
            @param x1, y1, x2, y2: The default location (for txt-version)
            @param embedded: Create as embedded chooser
            @param width: Embedded chooser width
            @param height: Embedded chooser height
            """
            # remember attributes
            self.title = title
            self.flags = flags
            self.cols = cols
            self.deflt = deflt
            self.popup_names = popup_names
            self.icon = icon
            self.x1 = x1
            self.y1 = y1
            self.x2 = x2
            self.y2 = y2
            self.embedded = embedded
            self.width = width
            self.height = height
            # construct the v.7.0 chooser object
            self.chobj = Choose2.ChooseWrapper(self)
        # redirect methods to the v.7.0 chooser
        def __getattr__(self, attr):
            if attr not in ["GetEmbSelection",
                            "Activate",
                            "Refresh",
                            "Close",
                            "GetWidget"]:
                raise AttributeError(attr)
            return getattr(self.chobj, attr)
        def Embedded(self):
            """
            Creates an embedded chooser (as opposed to Show())
            @return: Returns 1 on success
            """
            return 1 if self.chobj.Embedded() == 0 else 0
        def Show(self, modal=False):
            """
            Activates or creates a chooser window
            @param modal: Display as modal dialog
            @return: For modal choosers it will return the selected item index (0-based)
                     or -1 in the case of error,
                     For non-modal choosers it will return 0
                     or -1 if the chooser was already open and is active now
            """
            ret = self.chobj.Show(modal)
            return -1 if ret < 0 else ret
        def AddCommand(self,
                       caption,
                       flags = _ida_kernwin.CHOOSER_POPUP_MENU,
                       menu_index = -1,
                       icon = -1,
                       emb=None,
                       shortcut=None):
            # Use the 'emb' as a sentinel. It will be passed the correct value
            # from the EmbeddedChooserControl
            if self.embedded and ((emb is None) or (emb != 2002)):
                raise RuntimeError("Please add a command through "
                                   "EmbeddedChooserControl.AddCommand()")
            return BC695_control_cmd.add_to_control(
                       self, caption, flags, menu_index, icon, emb, None,
                       is_chooser=True)
        # callbacks
        # def OnGetSize(self):
        # def OnGetLine(self, n):
        # def OnGetIcon(self, n):
        # def OnGetLineAttr(self, n):
        # def OnInsertLine(self):
        # def OnDeleteLine(self, n):
        # def OnEditLine(self, n):
        # def OnSelectLine(self, n):
        # def OnRefresh(self, n):
        # def OnSelectionChange(self, sel_list):
        # def OnClose(self):
        # def OnCommand(self, n, cmd_id):

%}%pythoncode %{
if _BC695:
    PluginForm.FORM_MDI = PluginForm.WOPN_MDI
    PluginForm.FORM_TAB = PluginForm.WOPN_TAB
    PluginForm.FORM_RESTORE = PluginForm.WOPN_RESTORE
    PluginForm.FORM_ONTOP = PluginForm.WOPN_ONTOP
    PluginForm.FORM_MENU = PluginForm.WOPN_MENU
    PluginForm.FORM_CENTERED = PluginForm.WOPN_CENTERED
    PluginForm.FORM_PERSIST = PluginForm.WOPN_PERSIST
    PluginForm.FORM_SAVE = PluginForm.WCLS_SAVE
    PluginForm.FORM_NO_CONTEXT = PluginForm.WCLS_NO_CONTEXT
    PluginForm.FORM_DONT_SAVE_SIZE = PluginForm.WCLS_DONT_SAVE_SIZE
    PluginForm.FORM_CLOSE_LATER = PluginForm.WCLS_CLOSE_LATER

%}