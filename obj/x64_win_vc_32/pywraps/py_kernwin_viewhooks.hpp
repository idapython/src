
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
