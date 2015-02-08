#ifndef __PY_KERNWIN__
#define __PY_KERNWIN__

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
      int ret = py_result == NULL ? -1 : PyLong_AsLong(py_result.o);

      // Timer has been unregistered?
      if ( ret == -1 )
      {
        // Free the context
        Py_DECREF(ctx->pycallback);
        delete ctx;
      }
      return ret;
    };
  };

  py_timer_ctx_t *ctx = new py_timer_ctx_t();
  ctx->pycallback = py_callback;
  Py_INCREF(py_callback);
  ctx->timer_id = register_timer(
    interval,
    tmr_t::callback,
    ctx);

  if ( ctx->timer_id == NULL )
  {
    Py_DECREF(py_callback);
    delete ctx;
    Py_RETURN_NONE;
  }
  return PyCObject_FromVoidPtr(ctx, NULL);
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

  if ( py_timerctx == NULL || !PyCObject_Check(py_timerctx) )
    Py_RETURN_FALSE;

  py_timer_ctx_t *ctx = (py_timer_ctx_t *) PyCObject_AsVoidPtr(py_timerctx);
  if ( !unregister_timer(ctx->timer_id) )
    Py_RETURN_FALSE;

  Py_DECREF(ctx->pycallback);
  delete ctx;

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
    PyObject *py_str = PyString_FromString(name);
    qfree(name);
    return py_str;
  }
}

//------------------------------------------------------------------------
/*
#<pydoc>
def get_highlighted_identifier(flags = 0):
    """
    Returns the currently highlighted identifier

    @param flags: reserved (pass 0)
    @return: None or the highlighted identifier
    """
    pass
#</pydoc>
*/
static PyObject *py_get_highlighted_identifier(int flags = 0)
{
  char buf[MAXSTR];
  bool ok = get_highlighted_identifier(buf, sizeof(buf), flags);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !ok )
    Py_RETURN_NONE;
  else
    return PyString_FromString(buf);
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
  if ( PyString_AsStringAndSize(data, &s, &len) == -1 )
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
def readsel2(view, p0, p1):
    """
    Read the user selection, and store its information in p0 (from) and p1 (to).

    This can be used as follows:


    >>> p0 = idaapi.twinpos_t()
    p1 = idaapi.twinpos_t()
    view = idaapi.get_current_viewer()
    idaapi.readsel2(view, p0, p1)


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
def umsg(text):
    """
    Prints text into IDA's Output window

    @param text: text to print
                 Can be Unicode, or string in UTF-8 encoding
    @return: number of bytes printed
    """
    pass
#</pydoc>
*/
static PyObject* py_umsg(PyObject *o)
{
  PyObject* utf8 = NULL;
  if ( PyUnicode_Check(o) )
  {
    utf8 = PyUnicode_AsUTF8String(o);
    o = utf8;
  }
  else if ( !PyString_Check(o) )
  {
    PyErr_SetString(PyExc_TypeError, "A unicode or UTF-8 string expected");
    return NULL;
  }
  int rc;
  Py_BEGIN_ALLOW_THREADS;
  rc = umsg("%s", PyString_AsString(o));
  Py_END_ALLOW_THREADS;
  Py_XDECREF(utf8);
  return PyInt_FromLong(rc);
}

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
static PyObject* py_msg(PyObject *o)
{
  if ( PyUnicode_Check(o) )
    return py_umsg(o);

  if ( !PyString_Check(o) )
  {
    PyErr_SetString(PyExc_TypeError, "A string expected");
    return NULL;
  }
  int rc;
  Py_BEGIN_ALLOW_THREADS;
  rc = msg("%s", PyString_AsString(o));
  Py_END_ALLOW_THREADS;
  return PyInt_FromLong(rc);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def asktext(max_text, defval, prompt):
    """
    Asks for a long text

    @param max_text: Maximum text length
    @param defval: The default value
    @param prompt: The prompt value
    @return: None or the entered string
    """
    pass
#</pydoc>
*/
PyObject *py_asktext(int max_text, const char *defval, const char *prompt)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( max_text <= 0 )
    Py_RETURN_NONE;

  char *buf = new char[max_text];
  if ( buf == NULL )
    Py_RETURN_NONE;

  PyObject *py_ret;
  if ( asktext(size_t(max_text), buf, defval, "%s", prompt) != NULL )
  {
    py_ret = PyString_FromString(buf);
  }
  else
  {
    py_ret = Py_None;
    Py_INCREF(py_ret);
  }
  delete [] buf;
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
  bool ok = str2ea(str, &ea, screenEA);
  return ok ? ea : BADADDR;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def str2user(str):
    """
    Insert C-style escape characters to string

    @return: new string with escape characters inserted
    """
    pass
#</pydoc>
*/
PyObject *py_str2user(const char *str)
{
  qstring qstr(str);
  qstring retstr;
  qstr2user(&retstr, qstr);
  return PyString_FromString(retstr.c_str());
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
def del_menu_item(menu_ctx):
    """Deprecated. Use detach_menu_item()/unregister_action() instead."""
    pass
#</pydoc>
*/
static bool py_del_menu_item(PyObject *py_ctx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCObject_Check(py_ctx) )
    return false;

  py_add_del_menu_item_ctx *ctx = (py_add_del_menu_item_ctx *)PyCObject_AsVoidPtr(py_ctx);

  bool ok = del_menu_item(ctx->menupath.c_str());
  if ( ok )
  {
    Py_DECREF(ctx->cb_data);
    delete ctx;
  }

  return ok;
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
  if ( !PyCObject_Check(pyctx) )
    return false;

  py_idchotkey_ctx_t *ctx = (py_idchotkey_ctx_t *) PyCObject_AsVoidPtr(pyctx);
  if ( !del_idc_hotkey(ctx->hotkey.c_str()) )
    return false;

  Py_DECREF(ctx->pyfunc);
  delete ctx;
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
  if ( add_idc_hotkey(hotkey, idc_func_name.c_str()) == IDCHK_OK ) do
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
    char errbuf[MAXSTR];
    if ( !CompileLineEx(idc_func.c_str(), errbuf, sizeof(errbuf)) )
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
    return PyCObject_FromVoidPtr(ctx, NULL);
  } while (false);

  // Cleanup
  del_idc_hotkey(hotkey);
  Py_RETURN_NONE;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def add_menu_item(menupath, name, hotkey, flags, callback, args):
    """Deprecated. Use register_action()/attach_menu_item() instead."""
    pass
#</pydoc>
*/
bool idaapi py_menu_item_callback(void *userdata);
static PyObject *py_add_menu_item(
  const char *menupath,
  const char *name,
  const char *hotkey,
  int flags,
  PyObject *pyfunc,
  PyObject *args)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool no_args;

  // No slash in the menu path?
  const char *p = strrchr(menupath, '/');
  if ( p == NULL )
    Py_RETURN_NONE;

  if ( args == Py_None )
  {
    no_args = true;
    args = PyTuple_New(0);
    if ( args == NULL )
      return NULL;
  }
  else if ( !PyTuple_Check(args) )
  {
    PyErr_SetString(PyExc_TypeError, "args must be a tuple or None");
    return NULL;
  }
  else
  {
    no_args = false;
  }

  // Form a tuple holding the function to be called and its arguments
  PyObject *cb_data = Py_BuildValue("(OO)", pyfunc, args);

  // If we created an empty tuple, then we must free it
  if ( no_args )
    Py_DECREF(args);

  // Add the menu item
  bool b = add_menu_item(menupath, name, hotkey, flags, py_menu_item_callback, (void *)cb_data);

  if ( !b )
  {
    Py_XDECREF(cb_data);
    Py_RETURN_NONE;
  }
  // Create a context (for the delete_menu_item())
  py_add_del_menu_item_ctx *ctx = new py_add_del_menu_item_ctx();

  // Form the complete menu path
  ctx->menupath.append(menupath, p - menupath + 1);
  ctx->menupath.append(name);
  // Save callback data
  ctx->cb_data = cb_data;

  // Return context to user
  return PyCObject_FromVoidPtr(ctx, NULL);
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

    @note: The Python version of execute_sync() cannot be called from a different thread
           for the time being.
    @param callable: A python callable object
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
        int ret = py_result == NULL || !PyInt_Check(py_result.o)
                ? -1
                : PyInt_AsLong(py_result.o);
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

//---------------------------------------------------------------------------
// UI hooks
//---------------------------------------------------------------------------
int idaapi UI_Callback(void *ud, int notification_code, va_list va);
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

    def preprocess(self, name):
        """
        IDA ui is about to handle a user command

        @param name: ui command name
                     (these names can be looked up in ida[tg]ui.cfg)
        @return: 0-ok, nonzero - a plugin has handled the command
        """
        pass

    def postprocess(self):
        """
        An ida ui command has been handled

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

    def populating_tform_popup(self, form, popup):
        """
        The UI is populating the TForm's popup menu.
        Now is a good time to call idaapi.attach_action_to_popup()

        @param form: The form
        @param popup: The popup menu.
        @return: Ignored
        """
        pass

    def finish_populating_tform_popup(self, form, popup):
        """
        The UI is about to be done populating the TForm's popup menu.
        Now is a good time to call idaapi.attach_action_to_popup()

        @param form: The form
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
    return hook_to_notification_point(HT_UI, UI_Callback, this);
  }

  bool unhook()
  {
    return unhook_from_notification_point(HT_UI, UI_Callback, this);
  }

  virtual int preprocess(const char * /*name*/)
  {
    return 0;
  }

  virtual void postprocess()
  {
  }

  virtual void saving()
  {
  }

  virtual void saved()
  {
  }

  virtual void term()
  {
  }

  virtual PyObject *get_ea_hint(ea_t /*ea*/)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  };

  virtual void current_tform_changed(TForm * /*form*/, TForm * /*previous_form*/)
  {
  }

  virtual void updating_actions(action_update_ctx_t *ctx)
  {
  }

  virtual void updated_actions()
  {
  }

  virtual void populating_tform_popup(TForm * /*form*/, TPopupMenu * /*popup*/)
  {
  }

  virtual void finish_populating_tform_popup(TForm * /*form*/, TPopupMenu * /*popup*/)
  {
  }
};

//-------------------------------------------------------------------------
bool py_register_action(action_desc_t *desc)
{
  bool ok = register_action(*desc);
  if ( ok )
  {
    // Success. We are managing this handler from now on,
    // and must prevent it from being destroyed.
    py_action_handlers[desc->name] = desc->handler;
    // Let's set this to NULL, so when the wrapping Python action_desc_t
    // instance is deleted, it doesn't try to delete the handler (See
    // kernwin.i's action_desc_t::~action_desc_t()).
    desc->handler = NULL;
  }
  return ok;
}

//-------------------------------------------------------------------------
bool py_unregister_action(const char *name)
{
  bool ok = unregister_action(name);
  if ( ok )
  {
    py_action_handler_t *handler =
      (py_action_handler_t *) py_action_handlers[name];
    delete handler;
    py_action_handlers.erase(name);
  }
  return ok;
}

//-------------------------------------------------------------------------
bool py_attach_dynamic_action_to_popup(
        TForm *form,
        TPopupMenu *popup_handle,
        action_desc_t *desc,
        const char *popuppath = NULL,
        int flags = 0)
{
  bool ok = attach_dynamic_action_to_popup(
          form, popup_handle, *desc, popuppath, flags);
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
void py_gen_disasm_text(ea_t ea1, ea_t ea2, disasm_text_t &text, bool truncate_lines)
{
  text_t _text;
  gen_disasm_text(ea1, ea2, _text, truncate_lines);
  for ( size_t i = 0, n = _text.size(); i < n; ++i )
  {
    const twinline_t &tl = _text[i];
    disasm_line_t &dl = text.push_back();
    dl.at = tl.at;           // Transfer ownership
    dl.line.inject(tl.line); // Transfer ownership
  }
}

//-------------------------------------------------------------------------
// Although 'TCustomControl*' and 'TForm*' instances can both be used
// for attach_action_to_popup() at a binary-level, IDAPython SWIG bindings
// require that a 'TForm *' wrapper be passed to wrap_attach_action_to_popup().
// Thus, we provide another attach_action_to_popup() version, that
// accepts a 'TCustomControl' as first argument.
//
// Since user-created GraphViewer are created like so:
// +-------- PluginForm ----------+
// |+----- TCustomControl -------+|
// ||                            ||
// ||                            ||
// ||                            ||
// ||                            ||
// ||                            ||
// |+----------------------------+|
// +------------------------------+
// The user cannot use GetTForm(), and use that to attach
// an action to, because that'll attach the action to the PluginForm
// instance.
// Instead, the user must use GetTCustomControl(), and call
// this function below with it.
bool attach_action_to_popup(
        TCustomControl *tcc,
        TPopupMenu *popup_handle,
        const char *name,
        const char *popuppath = NULL,
        int flags = 0)
{
  return attach_action_to_popup((TForm*) tcc, popup_handle, name, popuppath, flags);
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

  bool need_install = py_colorizer == NULL;
  py_colorizer = borref_t(new_py_colorizer);
  return need_install
    ? set_nav_colorizer(lambda_t::call_py_colorizer)
    : NULL;
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

//</inline(py_kernwin)>

//---------------------------------------------------------------------------
//<code(py_kernwin)>
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
int idaapi UI_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  UI_Hooks *proxy = (UI_Hooks *)ud;
  int ret = 0;
  try
  {
    switch (notification_code)
    {
      case ui_preprocess:
      {
        const char *name = va_arg(va, const char *);
        return proxy->preprocess(name);
      }

      case ui_postprocess:
        proxy->postprocess();
        break;

      case ui_saving:
        proxy->saving();
        break;

      case ui_saved:
        proxy->saved();
        break;

      case ui_term:
        proxy->term();
        break;

      case ui_get_ea_hint:
      {
        ea_t ea = va_arg(va, ea_t);
        char *buf = va_arg(va, char *);
        size_t sz = va_arg(va, size_t);
        char *_buf;
        Py_ssize_t _len;

        PYW_GIL_CHECK_LOCKED_SCOPE();
        PyObject *py_str = proxy->get_ea_hint(ea);
        if ( py_str != NULL
          && PyString_Check(py_str)
          && PyString_AsStringAndSize(py_str, &_buf, &_len) != - 1 )
        {
          qstrncpy(buf, _buf, qmin(_len, sz));
          ret = 1;
        }
        break;
      }

      case ui_current_tform_changed:
        {
          TForm *form = va_arg(va, TForm *);
          TForm *prev_form = va_arg(va, TForm *);
          proxy->current_tform_changed(form, prev_form);
        }
        break;

      case ui_updating_actions:
        {
          action_update_ctx_t *ctx = va_arg(va, action_update_ctx_t *);
          proxy->updating_actions(ctx);
        }
        break;


      case ui_updated_actions:
        {
          proxy->updated_actions();
        }
        break;

      case ui_populating_tform_popup:
        {
          TForm *form = va_arg(va, TForm *);
          TPopupMenu *popup = va_arg(va, TPopupMenu *);
          proxy->populating_tform_popup(form, popup);
        }
        break;

      case ui_finish_populating_tform_popup:
        {
          TForm *form = va_arg(va, TForm *);
          TPopupMenu *popup = va_arg(va, TPopupMenu *);
          proxy->finish_populating_tform_popup(form, popup);
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
//</code(py_kernwin)>

#endif
