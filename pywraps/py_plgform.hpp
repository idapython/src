#ifndef __PY_PLGFORM__
#define __PY_PLGFORM__

//<code(py_plgform)>
//---------------------------------------------------------------------------
class plgform_t
{
private:
  ref_t py_obj;
  TForm *form;

  static int idaapi s_callback(void *ud, int notification_code, va_list va)
  {
    // This hook gets called from the kernel. Ensure we hold the GIL.
    PYW_GIL_GET;

    plgform_t *_this = (plgform_t *)ud;
    if ( notification_code == ui_tform_visible )
    {
      TForm *form = va_arg(va, TForm *);
      if ( form == _this->form )
      {
        // Qt: QWidget*
        // G: HWND
        // We wrap and pass as a CObject in the hope that a Python UI framework
        // can unwrap a CObject and get the hwnd/widget back
        newref_t py_result(
                PyObject_CallMethod(
                        _this->py_obj.o,
                        (char *)S_ON_CREATE, "O",
                        PyCObject_FromVoidPtr(form, NULL)));
        PyW_ShowCbErr(S_ON_CREATE);
      }
    }
    else if ( notification_code == ui_tform_invisible )
    {
      TForm *form = va_arg(va, TForm *);
      if ( form == _this->form )
      {
        {
          newref_t py_result(
                  PyObject_CallMethod(
                          _this->py_obj.o,
                          (char *)S_ON_CLOSE, "O",
                          PyCObject_FromVoidPtr(form, NULL)));
          PyW_ShowCbErr(S_ON_CLOSE);
        }
        _this->unhook();
      }
    }
    return 0;
  }

  void unhook()
  {
    unhook_from_notification_point(HT_UI, s_callback, this);
    form = NULL;

    // Call DECREF at last, since it may trigger __del__
    PYW_GIL_CHECK_LOCKED_SCOPE();
    py_obj = ref_t();
  }

public:
  plgform_t(): form(NULL)
  {
  }

  bool show(
    PyObject *obj,
    const char *caption,
    int options)
  {
    // Already displayed?
    TForm *f = find_tform(caption);
    if ( f != NULL )
    {
      // Our form?
      if ( f == form )
      {
        // Switch to it
        switchto_tform(form, true);
        return true;
      }
      // Fail to create
      return false;
    }

    // Create a form
    form = create_tform(caption, NULL);
    if ( form == NULL )
      return false;

    if ( !hook_to_notification_point(HT_UI, s_callback, this) )
    {
      form = NULL;
      return false;
    }

    py_obj = borref_t(obj);

    if ( is_idaq() )
      options |= FORM_QWIDGET;

    this->form = form;
    open_tform(form, options);
    return true;
  }

  void close(int options = 0)
  {
    if ( form != NULL )
      close_tform(form, options);
  }

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
//</code(py_plgform)>

//<inline(py_plgform)>
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
  int options = FORM_TAB|FORM_MENU|FORM_RESTORE)
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
#undef DECL_PLGFORM
//</inline(py_plgform)>

#endif // __PY_PLGFORM__
