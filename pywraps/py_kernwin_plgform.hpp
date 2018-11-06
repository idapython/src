#ifndef __PY_KERNWIN_PLGFORM__
#define __PY_KERNWIN_PLGFORM__

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
                          PyCObject_FromVoidPtr(widget, NULL)));
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
                    PyCObject_FromVoidPtr(widget, NULL)));
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
    return PyCObject_FromVoidPtr(new plgform_t(), destroy);
  }

  static void destroy(void *obj)
  {
    delete (plgform_t *)obj;
  }
};
//</code(py_kernwin_plgform)>

//<inline(py_kernwin_plgform)>
//---------------------------------------------------------------------------
#define DECL_PLGFORM PYW_GIL_CHECK_LOCKED_SCOPE(); plgform_t *plgform = (plgform_t *) PyCObject_AsVoidPtr(py_link);
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

#endif // __PY_KERNWIN_PLGFORM__
