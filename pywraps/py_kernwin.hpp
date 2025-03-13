#ifndef __PY_KERNWIN__
#define __PY_KERNWIN__


//------------------------------------------------------------------------
//<decls(py_kernwin)>
//------------------------------------------------------------------------

//-------------------------------------------------------------------------
// Context structure used by add|del_idc_hotkey()
struct py_idchotkey_ctx_t
{
  qstring action_name;
  ref_t pyfunc;

  py_idchotkey_ctx_t(
          const char *_action_name,
          PyObject *_pyfunc)
    : action_name(_action_name),
      pyfunc(borref_t(_pyfunc)) {}
};

static ref_t py_colorizer;

static void py_snapshot_restore_callback(const char *err_msg, void *userdata);

//------------------------------------------------------------------------
//</decls(py_kernwin)>
//------------------------------------------------------------------------

//------------------------------------------------------------------------
//<inline(py_kernwin)>
//------------------------------------------------------------------------

//------------------------------------------------------------------------
static PyObject *py_register_timer(int interval, PyObject *callback)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( callback == nullptr || !PyCallable_Check(callback) )
    Py_RETURN_NONE;

  // An inner class hosting the callback method
  struct tmr_t
  {
    static int idaapi callback(void *ud)
    {
      PYW_GIL_GET;
      py_timer_ctx_t *ctx = (py_timer_ctx_t *)ud;
      newref_t py_result(PyObject_CallFunctionObjArgs(ctx->pyfunc.o, nullptr));
      int ret = -1;
      if ( PyErr_Occurred() != nullptr )
      {
        msg("Exception in timer callback. This timer will be unregistered.\n");
        PyErr_Print();
      }
      else if ( py_result )
      {
        ret = PyLong_AsLong(py_result.o);
      }

      // Timer has been unregistered?
      if ( ret == -1 )
        python_timer_del(ctx);
      return ret;
    };
  };

  py_timer_ctx_t *ctx = python_timer_new(callback);
  ctx->timer_id = register_timer(
          interval,
          tmr_t::callback,
          ctx);

  if ( ctx->timer_id != nullptr )
  {
    return PyCapsule_New(ctx, VALID_CAPSULE_NAME, nullptr);
  }
  else
  {
    python_timer_del(ctx);
    Py_RETURN_NONE;
  }
}

//------------------------------------------------------------------------
static bool py_unregister_timer(PyObject *timer_obj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( timer_obj == nullptr || !PyCapsule_IsValid(timer_obj, VALID_CAPSULE_NAME) )
    return false;

  py_timer_ctx_t *ctx = (py_timer_ctx_t *) PyCapsule_GetPointer(timer_obj, VALID_CAPSULE_NAME);
  if ( ctx == nullptr || !unregister_timer(ctx->timer_id) )
    return false;

  python_timer_del(ctx);
  // invalidate capsule; make sure we don't try and delete twice
  PyCapsule_SetName(timer_obj, INVALID_CAPSULE_NAME);
  return true;
}

//------------------------------------------------------------------------
static PyObject *py_choose_idasgn()
{
  char *name = choose_idasgn();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( name == nullptr )
  {
    Py_RETURN_NONE;
  }
  else
  {
    PyObject *py_str = PyUnicode_FromString(name);
    qfree(name);
    return py_str;
  }
}

//------------------------------------------------------------------------
static PyObject *py_get_highlight(TWidget *v, uint32 flags=0)
{
  qstring buf;
  uint32 lflags;
  bool ok = get_highlight(&buf, v, &lflags, flags);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !ok )
    Py_RETURN_NONE;
  return Py_BuildValue("(sk)", buf.c_str(), lflags);
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
  if ( PyBytes_AsStringAndSize(data, &s, &len) == -1 )
    return 0;
  else
    return load_custom_icon(s, len, format);
}

//------------------------------------------------------------------------
static int py_msg(const char *message)
{
  int rc = 0;
  if ( message != nullptr )
  {
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = msg("%s", message);
    SWIG_PYTHON_THREAD_END_ALLOW;
  }
  return rc;
}

//------------------------------------------------------------------------
static int py_warning(const char *message)
{
  int rc;
  if ( message != nullptr )
  {
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = warning("%s", message);
    SWIG_PYTHON_THREAD_END_ALLOW;
  }
  return rc;
}

//------------------------------------------------------------------------
static void py_error(const char *message)
{
  if ( message != nullptr )
  {
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    error("%s", message);
  }
}

//------------------------------------------------------------------------
PyObject *py_ask_text(size_t max_size, const char *defval, const char *prompt)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstring qbuf;

  PyObject *py_ret;
  if ( ask_text(&qbuf, max_size, defval, "%s", prompt) )
  {
    py_ret = PyUnicode_FromStringAndSize(qbuf.begin(), qbuf.length());
  }
  else
  {
    py_ret = Py_None;
    Py_INCREF(py_ret);
  }
  return py_ret;
}

//------------------------------------------------------------------------
PyObject *py_ask_str(qstring *defval, int hist, const char *prompt)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  PyObject *py_ret;
  if ( ask_str(defval, hist, "%s", prompt) )
  {
    py_ret = PyUnicode_FromStringAndSize(defval->begin(), defval->length());
  }
  else
  {
    py_ret = Py_None;
    Py_INCREF(py_ret);
  }
  return py_ret;
}

//------------------------------------------------------------------------
static bool py_process_ui_action(const char *name, int flags = 0)
{
  return process_ui_action(name, flags, nullptr);
}

//------------------------------------------------------------------------
bool py_del_hotkey(PyObject *ctx)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCapsule_IsValid(ctx, VALID_CAPSULE_NAME) )
    return false;

  py_idchotkey_ctx_t *_ctx = (py_idchotkey_ctx_t *) PyCapsule_GetPointer(ctx, VALID_CAPSULE_NAME);
  if ( _ctx == nullptr || !unregister_action(_ctx->action_name.c_str()) )
    return false;

  delete _ctx;

  // invalidate capsule; make sure we don't try and delete twice
  PyCapsule_SetName(ctx, INVALID_CAPSULE_NAME);
  return true;
}

//------------------------------------------------------------------------
PyObject *py_add_hotkey(const char *hotkey, PyObject *callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  // Make sure a callable was passed
  if ( !PyCallable_Check(callable) )
    return nullptr;

  // Form the function name
  qstring idc_func_name;
  idc_func_name.sprnt("py_hotkeycb_%p", callable);

  // Can add the hotkey?
  if ( add_idc_hotkey(hotkey, idc_func_name.c_str()) == IDCHK_OK )
  {
    do
    {
      // Generate global variable name
      qstring idc_gvarname;
      idc_gvarname.sprnt("_g_pyhotkey_ref_%p", callable);

      // Now add the global variable
      idc_value_t *gvar = add_idc_gvar(idc_gvarname.c_str());
      if ( gvar == nullptr )
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
      py_idchotkey_ctx_t *ctx = new py_idchotkey_ctx_t(idc_func_name.c_str(), callable);

      // Bind IDC variable w/ the PyCallable
      gvar->set_pvoid(callable);

      // Return the context
      return PyCapsule_New(ctx, VALID_CAPSULE_NAME, nullptr);
    } while (false);
  }
  // Cleanup
  unregister_action(idc_func_name.c_str());
  Py_RETURN_NONE;
}

//------------------------------------------------------------------------
static PyObject *py_take_database_snapshot(snapshot_t *snapshot)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstring err_msg;

  bool b = take_database_snapshot(snapshot, &err_msg);

  // Return (b, err_msg)
  return Py_BuildValue("(Ns)", PyBool_FromLong(b), err_msg.empty() ? nullptr : err_msg.c_str());
}

//-------------------------------------------------------------------------
static PyObject *py_restore_database_snapshot(
        const snapshot_t *snapshot,
        PyObject *callback,
        PyObject *userdata)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // If there is no callback, just call the function directly
  if ( callback == Py_None )
    return PyBool_FromLong(restore_database_snapshot(snapshot, nullptr, nullptr));

  // Create a new tuple or increase reference to userdata
  if ( userdata == Py_None )
  {
    userdata = PyTuple_New(0);
    if ( userdata == nullptr )
      return nullptr;
  }
  else
  {
    Py_INCREF(userdata);
  }

  // Create callback data tuple (use 'N' for userdata, since its
  // reference has already been incremented)
  PyObject *cb_data = Py_BuildValue("(ON)", callback, userdata);

  bool b = restore_database_snapshot(snapshot, py_snapshot_restore_callback, (void *) cb_data);

  if ( !b )
    Py_DECREF(cb_data);

  return PyBool_FromLong(b);
}

//------------------------------------------------------------------------
static ssize_t py_execute_sync(PyObject *callable, int reqf)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ssize_t rc = -1;
  // Callable?
  if ( PyCallable_Check(callable) )
  {
    struct py_exec_request_t : exec_request_t
    {
      ref_t py_callable;
      virtual ssize_t idaapi execute() override
      {
        PYW_GIL_GET;
        newref_t py_result(PyObject_CallFunctionObjArgs(py_callable.o, nullptr));
        ssize_t ret = !py_result || !PyLong_Check(py_result.o)
                    ? -1
                    : PyLong_AsLong(py_result.o);
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
    py_exec_request_t *req = new py_exec_request_t(callable);

    // Release GIL before executing, or if this is running in the
    // non-main thread, this will wait on the req.sem, while the main
    // thread might be waiting for the GIL to be available.
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = execute_sync(*req, reqf);
    SWIG_PYTHON_THREAD_END_ALLOW;
    // destroy the request once it is finished. exception: NOWAIT requests
    // will be handled in the future, so do not destroy them yet!
    if ( (reqf & MFF_NOWAIT) == 0 )
      delete req;
  }
  return rc;
}

//------------------------------------------------------------------------
static bool py_execute_ui_requests(PyObject *callable_list)
{
  struct py_ui_request_t: public ui_request_t
  {
  private:
    ref_vec_t py_callables;
    size_t py_callable_idx;

    static int idaapi s_callable_list_walk_cb(
        const ref_t &py_item,
        Py_ssize_t /*index*/,
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

    virtual bool idaapi run() override
    {
      PYW_GIL_GET;

      // Get callable
      ref_t py_callable = py_callables.at(py_callable_idx);
      bool reschedule;
      newref_t py_result(PyObject_CallFunctionObjArgs(py_callable.o, nullptr));
      // execute_ui_requests() will cause this run() code to be executed
      // asynchronously. This means that, should an exception have been raised
      // in the Python code we just executed, it won't have the possibility of
      // trickling all the way up to the Python runtime.
      // Since it would interfere with subsequent Python code execution, we
      // want to report it right away.
      if ( PyErr_Occurred() != nullptr )
      {
        PyErr_Print();
        return false;
      }
      reschedule = py_result != nullptr && PyObject_IsTrue(py_result.o);

      // No rescheduling? Then advance to the next callable
      if ( !reschedule )
        ++py_callable_idx;

      // Reschedule this C callback only if there are more callables
      return py_callable_idx < py_callables.size();
    }

    // Walk the list and extract all callables
    bool init(PyObject *callable_list)
    {
      Py_ssize_t count = pyvar_walk_seq(
              callable_list,
              s_callable_list_walk_cb,
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
  if ( !req->init(callable_list) )
  {
    delete req;
    return false;
  }
  execute_ui_requests(req, nullptr);
  return true;
}

//------------------------------------------------------------------------
struct jobj_wrapper_t
{
private:
  const jobj_t *o;

public:
  jobj_wrapper_t(const jobj_t *_o) : o(_o) {}

  PyObject *get_dict()
  {
    return PyW_from_jobj_t(*o);
  }

  static bool fill_jobj_from_dict(jobj_t *out, PyObject *dict)
  {
    return PyW_to_jobj_t(out, dict);
  }
};

//---------------------------------------------------------------------------
// UI hooks
//---------------------------------------------------------------------------
ssize_t idaapi UI_Callback(void *ud, int notification_code, va_list va);
struct UI_Hooks : public hooks_base_t
{
  // hookgenUI:methodsinfo_decl

  UI_Hooks(uint32 _flags=0, uint32 _hkcb_flags=HKCB_GLOBAL)
    : hooks_base_t("ida_kernwin.UI_Hooks", UI_Callback, HT_UI, _flags, _hkcb_flags) {}

  bool hook() { return hooks_base_t::hook(); }
  bool unhook() { return hooks_base_t::unhook(); }
#ifdef TESTABLE_BUILD
  PyObject *dump_state(bool assert_all_reimplemented=false) { return hooks_base_t::dump_state(mappings, mappings_size, assert_all_reimplemented); }
#endif

  // hookgenUI:methods

  ssize_t dispatch(int code, va_list va)
  {
    ssize_t ret = 0;
    switch ( code )
    {
      // hookgenUI:notifications
    }
    return ret;
  }

private:
  static ssize_t handle_get_ea_hint_output(PyObject *o, qstring *buf, ea_t)
  {
    ssize_t rc = 0;
    if ( o != nullptr && PyUnicode_Check(o) && PyUnicode_as_qstring(buf, o) )
      rc = 1;
    Py_XDECREF(o);
    return rc;
  }

  static ssize_t handle_hint_output(PyObject *o, qstring *hint, int *important_lines)
  {
    if ( o != nullptr && PyTuple_Check(o) && PyTuple_Size(o) == 2 )
    {
      borref_t el0(PyTuple_GetItem(o, 0));
      qstring plug_hint;
      if ( el0
        && PyUnicode_Check(el0.o)
        && PyUnicode_as_qstring(&plug_hint, el0.o)
        && !plug_hint.empty() )
      {
        borref_t el1(PyTuple_GetItem(o, 1));
        if ( el1 && PyLong_Check(el1.o) )
        {
          long lns = PyLong_AsLong(el1.o);
          if ( lns > 0 )
          {
            if ( !hint->empty() && hint->last() != '\n' )
              hint->append('\n');
            hint->append(plug_hint);
            *important_lines += lns;
          }
        }
      }
    }
    return 0;
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
    TWidget *widget = nullptr;
    int cvt = SWIG_ConvertPtr(o, (void **) &widget, SWIGTYPE_p_TWidget, 0);
    if ( !SWIG_IsOK(cvt) || widget == nullptr )
      return 0;
    return ssize_t(widget);
  }

  static ssize_t handle_widget_cfg_output(PyObject *o, const TWidget *, jobj_t *cfg)
  {
    return jobj_wrapper_t::fill_jobj_from_dict(cfg, o);
  }
};

//-------------------------------------------------------------------------
bool py_register_action(action_desc_t *desc)
{
  bool ok = desc != nullptr;
  if ( ok )
  {
    desc->flags |= ADF_OWN_HANDLER;
    ok = register_action(*desc);
    if ( ok )
    {
      // Let's set this to nullptr, so when the wrapping Python action_desc_t
      // instance is deleted, it doesn't try to delete the handler (See
      // kernwin.i's action_desc_t::~action_desc_t()).
      desc->handler = nullptr;
    }
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
bool py_attach_dynamic_action_to_popup(
        TWidget *unused,
        TPopupMenu *popup_handle,
        action_desc_t *desc,
        const char *popuppath = nullptr,
        int flags = 0)
{
  qnotused(unused);
  if ( popup_handle == nullptr || desc == nullptr )
    return false;
  bool ok = attach_dynamic_action_to_popup(
          nullptr, popup_handle, *desc, popuppath, flags);
  // If attaching
  //  * succeeded: the action (and its handler) will be deleted after
  //    the popup is dismissed,
  //  * fails: the action (and its handler) will be deleted right away
  // Therefore, we must always drop ownership.
  desc->handler = nullptr;
  return ok;
}

// This is similar to a twinline_t, with improved memory management:
// twinline_t has a dummy destructor, that performs no cleanup.
struct disasm_line_t
{
  disasm_line_t() : at(nullptr) {}
  ~disasm_line_t() { qfree(at); }
  disasm_line_t(const disasm_line_t &other) { *this = other; }
  disasm_line_t &operator=(const disasm_line_t &other)
  {
    qfree(at);
    at = other.at == nullptr ? nullptr : other.at->clone();
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
// tuple(fields, icon, attr)
static PyObject *py_chooser_base_t_get_row(
        const chooser_base_t *chobj,
        size_t n)
{
  if ( chobj == nullptr )
  {
    PyErr_SetString(PyExc_ValueError, "A valid chooser_base_t pointer is expected as first argument");
    return nullptr;
  }
  qstrvec_t fields;
  fields.resize(chobj->columns);
  chooser_item_attrs_t *attrs = new chooser_item_attrs_t;
  int icon;
  chobj->get_row(&fields, &icon, attrs, n);

  PyObject *tuple = PyTuple_New(3);
  PyTuple_SetItem(tuple, 0, qstrvec2pylist(fields));
  PyTuple_SetItem(tuple, 1, PyLong_FromLong(icon));
  PyObject *py_attrs = SWIG_NewPointerObj(
          SWIG_as_voidptr(attrs),
          SWIGTYPE_p_chooser_item_attrs_t,
          SWIG_POINTER_OWN);
  PyTuple_SetItem(tuple, 2, py_attrs);
  return tuple;
}

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
PyObject *py_set_nav_colorizer(PyObject *callback)
{
  struct ida_local lambda_t
  {
    static uint32 idaapi call_py_colorizer(ea_t ea, asize_t nbytes, void *)
    {
      PYW_GIL_GET;

      if ( !py_colorizer ) // Shouldn't happen.
        return 0;
      newref_t pyres(PyObject_CallFunction(
                             py_colorizer.o, "KK",
                             (unsigned long long) ea,
                             (unsigned long long) nbytes));
      PyW_ShowCbErr("nav_colorizer");
      uint32 rc = 0;
      bool ok = pyres && PyLong_Check(pyres.o);
      if ( ok )
      {
        int overflow = 0;
        const long l = PyLong_AsLongAndOverflow(pyres.o, &overflow);
        ok = PyErr_Occurred() == nullptr;
        if ( ok )
        {
          if ( l == -1 && overflow != 0 )
            ok = false;
          else
            rc = uint32(l);
        }
        else
        {
          PyErr_Print();
        }
      }

      if ( !ok )
      {
        static bool warned = false;
        if ( !warned )
        {
          msg("WARNING: set_nav_colorizer() callback must return an "
              "unsigned 'long', that can be converted into a 32-bit "
              "unsigned integer.\n");
          warned = true;
        }
      }
      return rc;
    }
  };

  // Always perform the call to set_nav_colorizer(): that has side-effects
  // (e.g., updating the legend.)
  bool first_install = py_colorizer == nullptr;
  py_colorizer = borref_t(callback);
  nav_colorizer_t *was_fun = nullptr;
  void *was_ud = nullptr;
  set_nav_colorizer(&was_fun, &was_ud, lambda_t::call_py_colorizer, nullptr);
  if ( !first_install )
    Py_RETURN_NONE;
  PyObject *was_fun_ptr = PyCapsule_New((void *) was_fun, VALID_CAPSULE_NAME, nullptr);
  PyObject *was_ud_ptr = PyCapsule_New(was_ud, VALID_CAPSULE_NAME, nullptr);
  PyObject *dict = PyDict_New();
  PyDict_SetItemString(dict, "fun", was_fun_ptr);
  PyDict_SetItemString(dict, "ud", was_ud_ptr);
  return dict;
}

//-------------------------------------------------------------------------
uint32 py_call_nav_colorizer(
        PyObject *colorizer,
        ea_t ea,
        asize_t nbytes)
{
  if ( !PyDict_Check(colorizer) )
    return 0;
  borref_t py_fun(PyDict_GetItemString(colorizer, "fun"));
  borref_t py_ud(PyDict_GetItemString(colorizer, "ud"));
  if ( !py_fun
    || !PyCapsule_IsValid(py_fun.o, VALID_CAPSULE_NAME)
    || !PyCapsule_IsValid(py_ud.o, VALID_CAPSULE_NAME) )
  {
    return 0;
  }
  nav_colorizer_t *fun = (nav_colorizer_t *) PyCapsule_GetPointer(py_fun.o, VALID_CAPSULE_NAME);
  void *ud = PyCapsule_GetPointer(py_ud.o, VALID_CAPSULE_NAME);
  if ( fun == nullptr )
    return 0;
  return fun(ea, nbytes, ud);
}

//-------------------------------------------------------------------------
PyObject *py_msg_get_lines(int count=-1)
{
  qstrvec_t lines;
  msg_get_lines(&lines, count);
  return qstrvec2pylist(lines);
}

//-------------------------------------------------------------------------
static TWidget *TWidget__from_ptrval__(size_t ptrval)
{
  return (TWidget *) ptrval;
}

// we limit the the number of spaces that can be added to 512k
#define MAX_SPACES_ADDED 524288
//-------------------------------------------------------------------------
static qstring py_add_spaces(const char *s, size_t len)
{
  qstring qbuf(s);
  const size_t slen = tag_strlen(qbuf.c_str());
  const size_t nlen = qbuf.length() - slen + len;
  if ( len > slen && nlen < MAX_SPACES_ADDED )
  {
    qbuf.resize(nlen);
  }
  else
  {
    if ( s == nullptr )
      qbuf.resize(1);
  }
  // we use the actual 'size' because we know that
  // 'add_spaces()' will add a terminating zero anyway
  add_spaces(qbuf.begin(), qbuf.size(), len);
  return qbuf;
}

//-------------------------------------------------------------------------
THREAD_SAFE void py_show_wait_box(const char *message)
{
  idapython_show_wait_box(/*internal=*/ false, message);
}

//-------------------------------------------------------------------------
void py_hide_wait_box()
{
  idapython_hide_wait_box();
}

//</inline(py_kernwin)>

//---------------------------------------------------------------------------
//<code(py_kernwin)>

// hookgenUI:methodsinfo_def

//---------------------------------------------------------------------------
ssize_t idaapi UI_Callback(void *ud, int code, va_list va)
{
  // hookgenUI:safecall=UI_Hooks
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
  newref_t result(PyObject_Call(func, args, nullptr));

  // We cannot raise an exception in the callback, just print it.
  if ( result == nullptr )
  {
    PyErr_Print();
    return false;
  }

  return PyObject_IsTrue(result.o) != 0;
}

//-------------------------------------------------------------------------
static void ida_kernwin_init(void) {}

//-------------------------------------------------------------------------
static void ida_kernwin_term(void)
{
  py_colorizer = ref_t();
}

//-------------------------------------------------------------------------
static void ida_kernwin_closebase(void) {}

//------------------------------------------------------------------------
static void py_snapshot_restore_callback(const char *err_msg, void *userdata)
{
  PYW_GIL_GET;

  // userdata is a tuple of ( func, args )
  // func and args are borrowed references from userdata

  PyObject *o = (PyObject *) userdata;
  if ( o == nullptr || !PyTuple_Check(o) )
    return;

  PyObject *func = PyTuple_GetItem(o, 0);
  PyObject *args = PyTuple_GetItem(o, 1);

  // Create arguments tuple for python function
  PyObject *cb_args = Py_BuildValue("(sO)", err_msg, args);

  // Call the python function
  newref_t result(PyObject_Call(func, cb_args, nullptr));

  // Free cb_args and userdata
  Py_DECREF(cb_args);
  Py_DECREF(o);

  // We cannot raise an exception in the callback, just print it.
  if ( !result )
    PyErr_Print();
}
//</code(py_kernwin)>

#endif
