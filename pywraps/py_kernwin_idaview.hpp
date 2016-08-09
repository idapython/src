
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

  // Get the IDAView associated to this TForm
  TForm *tform = find_tform(title.c_str());
  if ( tform == NULL )
    return false;
  TCustomControl *v = get_tform_idaview(tform);
  if ( v == NULL )
    return false;

  // Get unique py_idaview_t associated to that tform
  py_idaview_t *py_view;
  TCustomControl *found_view;
  if ( pycim_lookup_info.find_by_form(&found_view, (py_customidamemo_t**) &py_view, tform) )
  {
    // If we have a py_idaview_t for that form, ensure it has
    // the expected view.
    QASSERT(30451, found_view == v);
  }
  else
  {
    py_view = new py_idaview_t();
    lookup_entry_t &e = pycim_lookup_info.new_entry(py_view);
    pycim_lookup_info.commit(e, tform, v);
  }

  // Finally, bind:
  //  py_idaview_t <=> IDAViewWrapper
  //  py_idaview_t  => TCustomControl
  bool ok = py_view->bind(self, v);
  if ( ok )
  {
    ok = py_view->collect_pyobject_callbacks(self);
    if ( ok )
      py_view->install_custom_viewer_handlers();
    else
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

//<inline(py_kernwin_idaview)>
bool pyidag_bind(PyObject *self);
bool pyidag_unbind(PyObject *self);
//</inline(py_kernwin_idaview)>
