
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
  py_idaview_t *_this = (py_idaview_t *) view_extract_this(self);
  if ( _this != nullptr )
    return false;

  qstring title;
  if ( !PyW_GetStringAttr(self, S_M_TITLE, &title) )
    return false;

  // Get the IDAView associated to this TWidget
  TWidget *widget = find_widget(title.c_str());
  if ( widget == nullptr )
    return false;

  // Get unique py_idaview_t associated to that TWidget
  py_idaview_t *py_view;
  if ( !get_plugin_instance()->pycim_lookup_info.find_by_view((py_customidamemo_t**) &py_view, widget) )
  {
    py_view = new py_idaview_t();
    lookup_entry_t &e = get_plugin_instance()->pycim_lookup_info.new_entry(py_view);
    get_plugin_instance()->pycim_lookup_info.commit(e, widget);
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
  py_idaview_t *_this = (py_idaview_t *) view_extract_this(self);
  if ( _this == nullptr )
    return false;
  _this->unbind();
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

//<inline(py_kernwin_idaview)>
bool pyidag_bind(PyObject *self);
bool pyidag_unbind(PyObject *self);
//</inline(py_kernwin_idaview)>
