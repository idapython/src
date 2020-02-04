#ifndef __PY_KERNWIN__
#define __PY_KERNWIN__


//------------------------------------------------------------------------
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
//------------------------------------------------------------------------


//------------------------------------------------------------------------
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
  PyCObject_SetVoidPtr(py_timerctx, NULL);
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
  PyCObject_SetVoidPtr(pyctx, NULL);

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
  PyObject *func = PyTuple_GET_ITEM(userdata, 0);
  PyObject *args = PyTuple_GET_ITEM(userdata, 1);

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

//---------------------------------------------------------------------------
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
  PyObject *func = PyTuple_GET_ITEM(userdata, 0);
  PyObject *args = PyTuple_GET_ITEM(userdata, 1);

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

#endif
