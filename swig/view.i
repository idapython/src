
%{
//<code(py_view_base)>

//#define PYGDBG_ENABLED
#ifdef PYGDBG_ENABLED
#define PYGLOG(...) msg(__VA_ARGS__)
#else
#define PYGLOG(...)
#endif

//-------------------------------------------------------------------------
class py_customidamemo_t;
class lookup_info_t
{
public:
  struct entry_t
  {
    entry_t() : form(NULL), view(NULL), py_view(NULL) {}
  private:
    TForm *form;
    TCustomControl *view;
    py_customidamemo_t *py_view;
    friend class lookup_info_t;
  };

  entry_t &new_entry(py_customidamemo_t *py_view)
  {
    QASSERT(30454, py_view != NULL && !find_by_py_view(NULL, NULL, py_view));
    entry_t &e = entries.push_back();
    e.py_view = py_view;
    return e;
  }

  void commit(entry_t &e, TForm *form, TCustomControl *view)
  {
    QASSERT(30455, &e >= entries.begin() && &e < entries.end());
    QASSERT(30456, form != NULL && view != NULL && e.py_view != NULL
                && !find_by_form(NULL, NULL, form)
                && !find_by_view(NULL, NULL, view)
                && find_by_py_view(NULL, NULL, e.py_view));
    e.form = form;
    e.view = view;
  }

#define FIND_BY__BODY(crit, res1, res2)                                 \
  {                                                                     \
    for ( entries_t::const_iterator it = entries.begin(); it != entries.end(); ++it ) \
    {                                                                   \
      const entry_t &e = *it;                                           \
      if ( e.crit == crit )                                             \
      {                                                                 \
        if ( out_##res1 != NULL )                                       \
          *out_##res1 = e.res1;                                         \
        if ( out_##res2 != NULL )                                       \
          *out_##res2 = e.res2;                                         \
        return true;                                                    \
      }                                                                 \
    }                                                                   \
    return false;                                                       \
  }
  bool find_by_form(TCustomControl **out_view, py_customidamemo_t **out_py_view, const TForm *form) const FIND_BY__BODY(form, view, py_view);
  bool find_by_view(TForm **out_form, py_customidamemo_t **out_py_view, const TCustomControl *view) const FIND_BY__BODY(view, form, py_view);
  bool find_by_py_view(TForm **out_form, TCustomControl **out_view, const py_customidamemo_t *py_view) const FIND_BY__BODY(py_view, view, form);
#undef FIND_BY__BODY

  bool del_by_py_view(const py_customidamemo_t *py_view)
  {
    for ( entries_t::iterator it = entries.begin(); it != entries.end(); ++it )
    {
      if ( it->py_view == py_view )
      {
        entries.erase(it);
        return true;
      }
    }
    return false;
  }

private:
  typedef qvector<entry_t> entries_t;
  entries_t entries;
};

//-------------------------------------------------------------------------
template <typename T>
T *view_extract_this(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_this(PyW_TryGetAttrString(self, S_M_THIS));
  if ( py_this == NULL || !PyCObject_Check(py_this.o) )
    return NULL;
  return (T*) PyCObject_AsVoidPtr(py_this.o);
}

//-------------------------------------------------------------------------
class py_customidamemo_t
{
  void convert_node_info(
          node_info_t *out,
          uint32 *out_flags,
          ref_t py_nodeinfo)
  {
    if ( out_flags != NULL )
      *out_flags = 0;
#define COPY_PROP(checker, converter, pname, flag)                      \
    do                                                                  \
    {                                                                   \
      newref_t pname(PyObject_GetAttrString(py_nodeinfo.o, #pname));    \
      if ( pname != NULL && checker(pname.o) )                          \
      {                                                                 \
        out->pname = converter(pname.o);                                \
        if ( out_flags != NULL )                                        \
          *out_flags |= flag;                                           \
      }                                                                 \
    } while ( false )
#define COPY_ULONG_PROP(pname, flag) COPY_PROP(PyNumber_Check, PyLong_AsUnsignedLong, pname, flag)
#define COPY_STRING_PROP(pname, flag) COPY_PROP(PyString_Check, PyString_AsString, pname, flag)
    COPY_ULONG_PROP(bg_color, NIF_BG_COLOR);
    COPY_ULONG_PROP(frame_color, NIF_FRAME_COLOR);
    COPY_ULONG_PROP(ea, NIF_EA);
    COPY_STRING_PROP(text, NIF_TEXT);
#undef COPY_STRING_PROP
#undef COPY_ULONG_PROP
#undef COPY_PROP
  }

  enum
  {
    GRBASE_HAVE_VIEW_ACTIVATED   = 0x001,
    GRBASE_HAVE_VIEW_DEACTIVATED = 0x002,
    GRBASE_HAVE_KEYDOWN          = 0x004,
    GRBASE_HAVE_POPUP            = 0x008,
    GRBASE_HAVE_VIEW_CLICK       = 0x010,
    GRBASE_HAVE_VIEW_DBLCLICK    = 0x020,
    GRBASE_HAVE_VIEW_CURPOS      = 0x040,
    GRBASE_HAVE_CLOSE            = 0x080,
    GRBASE_HAVE_VIEW_SWITCHED    = 0x100,
    GRBASE_HAVE_VIEW_MOUSE_OVER  = 0x200,
    GRBASE_HAVE_VIEW_MOUSE_MOVED = 0x400,
  };

  static void ensure_view_callbacks_installed();
  int cb_flags;
  // number of arguments for:
  int ovc_num_args;   // OnViewClick implementation
  int ovdc_num_args;  // OnViewDblclick implementation
  int ovmo_num_args;  // OnViewMouseOver implementation
  int ovmm_num_args;  // OnViewMouseMoved implementation

protected:
  ref_t self;
  TCustomControl *view;
  // This is called after having modified the
  // node properties in the IDB. In case an
  // implementation is performing some caching,
  // this is a chance to update that cache.
  // If 'ni' is NULL, then the node info was deleted.
  virtual void node_info_modified(
          int /*n*/,
          const node_info_t * /*ni*/,
          uint32 /*flags*/) {}

  struct callback_id_t
  {
    qstring name;
    int have;
  };
  struct callbacks_ids_t : public qvector<callback_id_t>
  {
    void add(const char *_n, int _h)
    {
      callback_id_t &o = push_back();
      o.name = _n;
      o.have = _h;
    }
  };
  callbacks_ids_t cbids;

  bool collect_pyobject_callbacks(PyObject *self);
  virtual void collect_class_callbacks_ids(callbacks_ids_t *out);

  void install_custom_viewer_handlers();

  // Bi-directionally bind/unbind the Python object and this controller.
  bool bind(PyObject *_self, TCustomControl *view);
  void unbind();

  static lookup_info_t lookup_info;
  friend TForm *pycim_get_tform(PyObject *self);
  friend TCustomControl *pycim_get_tcustom_control(PyObject *self);

public:
  py_customidamemo_t();
  virtual ~py_customidamemo_t();
  virtual void refresh()
  {
    refresh_viewer(view);
  }
  void set_node_info(PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags);
  void set_nodes_infos(PyObject *dict);
  PyObject *get_node_info(PyObject *py_node_idx);
  void del_nodes_infos(PyObject *py_nodes);
  PyObject *get_current_renderer_type();
  void set_current_renderer_type(PyObject *py_rto);
  PyObject *create_groups(PyObject *groups_infos);
  PyObject *delete_groups(PyObject *groups, PyObject *new_current);
  PyObject *set_groups_visibility(PyObject *groups, PyObject *expand, PyObject *new_current);

  // View events
  void on_view_activated();
  void on_view_deactivated();
  void on_view_keydown(int key, int state);
  void on_view_popup();
  void on_view_click(const view_mouse_event_t *event);
  void on_view_dblclick(const view_mouse_event_t *event);
  void on_view_curpos();
  void on_view_close();
  void on_view_switched(tcc_renderer_type_t rt);
  void on_view_mouse_over(const view_mouse_event_t *event);
  void on_view_mouse_moved(const view_mouse_event_t *event);
  inline bool has_callback(int flag) { return (cb_flags & flag) != 0; }
  int get_py_method_arg_count(char *method_name);

  // View events that are bound with 'set_custom_viewer_handler()'.
  static void idaapi s_on_view_mouse_moved(
          TCustomControl *cv,
          int shift,
          view_mouse_event_t *e,
          void *ud);
};

//-------------------------------------------------------------------------
py_customidamemo_t::py_customidamemo_t()
  : self(newref_t(NULL)),
    view(NULL)
{
  PYGLOG("%p: py_customidamemo_t()\n", this);
  ensure_view_callbacks_installed();
  ovc_num_args = -1;
  ovdc_num_args = -1;
  ovmo_num_args = -1;
  ovmm_num_args = -1;
}

//-------------------------------------------------------------------------
py_customidamemo_t::~py_customidamemo_t()
{
  PYGLOG("%p: ~py_customidamemo_t()\n", this);
  unbind();
  lookup_info.del_by_py_view(this);
}

//-------------------------------------------------------------------------
void py_customidamemo_t::ensure_view_callbacks_installed()
{
  static bool installed = false;
  if ( !installed )
  {
    struct ida_local lambda_t
    {
      static int idaapi callback(void * /*ud*/, int code, va_list va)
      {
        py_customidamemo_t *py_view;
        if ( lookup_info.find_by_view(NULL, &py_view, va_arg(va, TCustomControl *)) )
        {
          PYW_GIL_GET;
          switch ( code )
          {
            case view_activated:
              py_view->on_view_activated();
              break;
            case view_deactivated:
              py_view->on_view_deactivated();
              break;
            case view_keydown:
              {
                int key = va_arg(va, int);
                int state = va_arg(va, int);
                py_view->on_view_keydown(key, state);
              }
              break;
            case obsolete_view_popup:
              py_view->on_view_popup();
              break;
            case view_click:
            case view_dblclick:
              {
                const view_mouse_event_t *event = va_arg(va, view_mouse_event_t*);
                if ( code == view_click )
                  py_view->on_view_click(event);
                else
                  py_view->on_view_dblclick(event);
              }
              break;
            case view_curpos:
              py_view->on_view_curpos();
              break;
            case view_close:
              py_view->on_view_close();
              delete py_view;
              break;
            case view_switched:
              {
                tcc_renderer_type_t rt = (tcc_renderer_type_t) va_arg(va, int);
                py_view->on_view_switched(rt);
              }
              break;
            case view_mouse_over:
              {
                const view_mouse_event_t *event = va_arg(va, view_mouse_event_t*);
                py_view->on_view_mouse_over(event);
              }
              break;
          }
        }
        return 0;
      }
    };
    hook_to_notification_point(HT_VIEW, lambda_t::callback, NULL);
    installed = true;
  }
}

//-------------------------------------------------------------------------
void py_customidamemo_t::set_node_info(
        PyObject *py_node_idx,
        PyObject *py_node_info,
        PyObject *py_flags)
{
  if ( !PyNumber_Check(py_node_idx) || !PyNumber_Check(py_flags) )
    return;
  borref_t py_idx(py_node_idx);
  borref_t py_ni(py_node_info);
  borref_t py_fl(py_flags);
  node_info_t ni;
  convert_node_info(&ni, NULL, py_ni);
  int idx = PyInt_AsLong(py_idx.o);
  uint32 flgs = PyLong_AsLong(py_fl.o);
  viewer_set_node_info(view, idx, ni, flgs);
  node_info_modified(idx, &ni, flgs);
}

//-------------------------------------------------------------------------
void py_customidamemo_t::set_nodes_infos(PyObject *dict)
{
  if ( !PyDict_Check(dict) )
    return;
  Py_ssize_t pos = 0;
  PyObject *o_key, *o_value;
  while ( PyDict_Next(dict, &pos, &o_key, &o_value) )
  {
    borref_t key(o_key);
    borref_t value(o_value);
    if ( !PyNumber_Check(key.o) )
      continue;
    uint32 flags;
    node_info_t ni;
    convert_node_info(&ni, &flags, value);
    int idx = PyInt_AsLong(key.o);
    viewer_set_node_info(view, idx, ni, flags);
    node_info_modified(idx, &ni, flags);
  }
}

//-------------------------------------------------------------------------
PyObject *py_customidamemo_t::get_node_info(PyObject *py_node_idx)
{
  if ( !PyNumber_Check(py_node_idx) )
    Py_RETURN_NONE;
  node_info_t ni;
  if ( !viewer_get_node_info(view, &ni, PyInt_AsLong(py_node_idx)) )
    Py_RETURN_NONE;
  return Py_BuildValue("(kkks)", ni.bg_color, ni.frame_color, ni.ea, ni.text.c_str());
}

//-------------------------------------------------------------------------
void py_customidamemo_t::del_nodes_infos(PyObject *py_nodes)
{
  if ( !PySequence_Check(py_nodes) )
    return;
  Py_ssize_t sz = PySequence_Size(py_nodes);
  for ( Py_ssize_t i = 0; i < sz; ++i )
  {
    newref_t item(PySequence_GetItem(py_nodes, i));
    if ( !PyNumber_Check(item.o) )
      continue;
    int idx = PyInt_AsLong(item.o);
    viewer_del_node_info(view, idx);
    node_info_modified(idx, NULL, 0);
  }
}

//-------------------------------------------------------------------------
PyObject *py_customidamemo_t::get_current_renderer_type()
{
  tcc_renderer_type_t rt = get_view_renderer_type(view);
  return PyLong_FromLong(long(rt));
}

//-------------------------------------------------------------------------
void py_customidamemo_t::set_current_renderer_type(PyObject *py_rto)
{
  tcc_renderer_type_t rt = TCCRT_INVALID;
  borref_t py_rt(py_rto);
  if ( PyNumber_Check(py_rt.o) )
  {
    rt = tcc_renderer_type_t(PyLong_AsLong(py_rt.o));
    set_view_renderer_type(view, rt);
  }
}

//-------------------------------------------------------------------------
PyObject *py_customidamemo_t::create_groups(PyObject *_groups_infos)
{
  if ( !PySequence_Check(_groups_infos) )
    Py_RETURN_NONE;
  borref_t groups_infos(_groups_infos);
  groups_crinfos_t gis;
  Py_ssize_t sz = PySequence_Size(groups_infos.o);
  for ( Py_ssize_t i = 0; i < sz; ++i )
  {
    newref_t item(PySequence_GetItem(groups_infos.o, i));
    if ( !PyDict_Check(item.o) )
      continue;
    borref_t nodes(PyDict_GetItemString(item.o, "nodes"));
    if ( nodes.o == NULL || !PySequence_Check(nodes.o) )
      continue;
    borref_t text(PyDict_GetItemString(item.o, "text"));
    if ( text.o == NULL || !PyString_Check(text.o) )
      continue;
    group_crinfo_t gi;
    Py_ssize_t nodes_cnt = PySequence_Size(nodes.o);
    for ( Py_ssize_t k = 0; k < nodes_cnt; ++k )
    {
      newref_t node(PySequence_GetItem(nodes.o, k));
      if ( PyInt_Check(node.o) )
        gi.nodes.add_unique(PyInt_AsLong(node.o));
    }
    if ( !gi.nodes.empty() )
    {
      gi.text = PyString_AsString(text.o);
      gis.push_back(gi);
    }
  }
  intvec_t groups;
  if ( gis.empty() || !viewer_create_groups(view, &groups, gis) || groups.empty() )
    Py_RETURN_NONE;

  PyObject *py_groups = PyList_New(0);
  for ( intvec_t::const_iterator it = groups.begin(); it != groups.end(); ++it )
    PyList_Append(py_groups, PyInt_FromLong(long(*it)));
  return py_groups;
}

//-------------------------------------------------------------------------
static void pynodes_to_idanodes(intvec_t *idanodes, ref_t pynodes)
{
  Py_ssize_t sz = PySequence_Size(pynodes.o);
  for ( Py_ssize_t i = 0; i < sz; ++i )
  {
    newref_t item(PySequence_GetItem(pynodes.o, i));
    if ( !PyInt_Check(item.o) )
      continue;
    idanodes->add_unique(PyInt_AsLong(item.o));
  }
}

//-------------------------------------------------------------------------
PyObject *py_customidamemo_t::delete_groups(PyObject *_groups, PyObject *_new_current)
{
  if ( !PySequence_Check(_groups) || !PyNumber_Check(_new_current) )
    Py_RETURN_NONE;
  borref_t groups(_groups);
  borref_t new_current(_new_current);
  intvec_t ida_groups;
  pynodes_to_idanodes(&ida_groups, groups);
  if ( ida_groups.empty() )
    Py_RETURN_NONE;
  if ( viewer_delete_groups(view, ida_groups, int(PyInt_AsLong(new_current.o))) )
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

//-------------------------------------------------------------------------
PyObject *py_customidamemo_t::set_groups_visibility(PyObject *_groups, PyObject *_expand, PyObject *_new_current)
{
  if ( !PySequence_Check(_groups)
    || !PyBool_Check(_expand)
    || !PyNumber_Check(_new_current) )
    Py_RETURN_NONE;
  borref_t groups(_groups);
  borref_t expand(_expand);
  borref_t new_current(_new_current);
  intvec_t ida_groups;
  pynodes_to_idanodes(&ida_groups, groups);
  if ( ida_groups.empty() )
    Py_RETURN_NONE;
  if ( viewer_set_groups_visibility(view, ida_groups, expand.o == Py_True, int(PyInt_AsLong(new_current.o))) )
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

//-------------------------------------------------------------------------
bool py_customidamemo_t::bind(PyObject *_self, TCustomControl *view)
{
  if ( this->self != NULL || this->view != NULL )
    return false;
  PYGLOG("%p: py_customidamemo_t::bind(_self=%p, view=%p)\n", this, _self, view);
  PYW_GIL_CHECK_LOCKED_SCOPE();

  newref_t py_cobj(PyCObject_FromVoidPtr(this, NULL));
  PyObject_SetAttrString(_self, S_M_THIS, py_cobj.o);

  this->self = borref_t(_self);
  this->view = view;
  return true;
}

//-------------------------------------------------------------------------
void py_customidamemo_t::unbind()
{
  if ( self == NULL )
    return;
  PYGLOG("%p: py_customidamemo_t::unbind(); self.o=%p, view=%p\n", this, self.o, view);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_cobj(PyCObject_FromVoidPtr(NULL, NULL));
  PyObject_SetAttrString(self.o, S_M_THIS, py_cobj.o);
  self = newref_t(NULL);
  view = NULL;
}

//-------------------------------------------------------------------------
void idaapi py_customidamemo_t::s_on_view_mouse_moved(
        TCustomControl *cv,
        int shift,
        view_mouse_event_t *e,
        void *ud)
{
  PYW_GIL_GET;
  py_customidamemo_t *_this = (py_customidamemo_t *) ud;
  _this->on_view_mouse_moved(e);
}

//-------------------------------------------------------------------------
int py_customidamemo_t::get_py_method_arg_count(char *method_name)
{
  newref_t method(PyObject_GetAttrString(self.o, method_name));
  if ( method != NULL && PyCallable_Check(method.o) )
  {
    newref_t fc(PyObject_GetAttrString(method.o, "func_code"));
    if ( fc != NULL )
    {
      newref_t ac(PyObject_GetAttrString(fc.o, "co_argcount"));
      if ( ac != NULL )
        return PyInt_AsLong(ac.o);
    }
  }
  return -1;
}

//-------------------------------------------------------------------------
void py_customidamemo_t::collect_class_callbacks_ids(callbacks_ids_t *out)
{
  out->add(S_ON_VIEW_ACTIVATED, GRBASE_HAVE_VIEW_ACTIVATED);
  out->add(S_ON_VIEW_DEACTIVATED, GRBASE_HAVE_VIEW_DEACTIVATED);
  out->add(S_ON_VIEW_KEYDOWN, GRBASE_HAVE_KEYDOWN);
  out->add(S_ON_POPUP, GRBASE_HAVE_POPUP);
  out->add(S_ON_VIEW_CLICK, GRBASE_HAVE_VIEW_CLICK);
  out->add(S_ON_VIEW_DBLCLICK, GRBASE_HAVE_VIEW_DBLCLICK);
  out->add(S_ON_VIEW_CURPOS, GRBASE_HAVE_VIEW_CURPOS);
  out->add(S_ON_CLOSE, GRBASE_HAVE_CLOSE);
  out->add(S_ON_VIEW_SWITCHED, GRBASE_HAVE_VIEW_SWITCHED);
  out->add(S_ON_VIEW_MOUSE_OVER, GRBASE_HAVE_VIEW_MOUSE_OVER);
  out->add(S_ON_VIEW_MOUSE_MOVED, GRBASE_HAVE_VIEW_MOUSE_MOVED);
}

//-------------------------------------------------------------------------
bool py_customidamemo_t::collect_pyobject_callbacks(PyObject *o)
{
  callbacks_ids_t cbids;
  collect_class_callbacks_ids(&cbids);
  cb_flags = 0;
  for ( callbacks_ids_t::const_iterator it = cbids.begin(); it != cbids.end(); ++it )
  {
    const callback_id_t &cbid = *it;
    ref_t attr(PyW_TryGetAttrString(o, cbid.name.c_str()));
    int have = cbid.have;
    // Mandatory fields not present?
    if ( (attr == NULL && have <= 0 )
         // Mandatory callback fields present but not callable?
         || (attr != NULL && have >= 0 && PyCallable_Check(attr.o) == 0))
    {
      return false;
    }
    if ( have > 0 && attr != NULL )
      cb_flags |= have;
  }

  return true;
}

//-------------------------------------------------------------------------
void py_customidamemo_t::install_custom_viewer_handlers()
{
  if ( has_callback(GRBASE_HAVE_VIEW_MOUSE_MOVED) )
  {
    // Set user-data
    set_custom_viewer_handler(view, CVH_USERDATA, (void *)this);

    //
    set_custom_viewer_handler(view, CVH_MOUSEMOVE, (void *)s_on_view_mouse_moved);
  }
}

//-------------------------------------------------------------------------
#define CHK_EVT(flag_needed)                                \
  if ( self == NULL || !has_callback(flag_needed) )         \
    return;                                                 \
  PYW_GIL_CHECK_LOCKED_SCOPE()


#ifdef PYGDBG_ENABLED
#define CHK_RES()                                               \
  do                                                            \
  {                                                             \
    PYGLOG("%s: return code: %p\n", __FUNCTION__, result.o);    \
    if (PyErr_Occurred())                                       \
      PyErr_Print();                                            \
  } while ( false )
#else
#define CHK_RES()                                               \
  do                                                            \
  {                                                             \
    if (PyErr_Occurred())                                       \
      PyErr_Print();                                            \
  } while ( false )
#endif

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_activated()
{
  CHK_EVT(GRBASE_HAVE_VIEW_ACTIVATED);
  newref_t result(
          PyObject_CallMethod(
                  self.o,
                  (char *)S_ON_VIEW_ACTIVATED,
                  NULL));
  CHK_RES();
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_deactivated()
{
  CHK_EVT(GRBASE_HAVE_VIEW_DEACTIVATED);
  newref_t result(
          PyObject_CallMethod(
                  self.o,
                  (char *)S_ON_VIEW_DEACTIVATED,
                  NULL));
  CHK_RES();
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_keydown(int key, int state)
{
  CHK_EVT(GRBASE_HAVE_KEYDOWN);
  newref_t result(
          PyObject_CallMethod(
                  self.o,
                  (char *)S_ON_VIEW_KEYDOWN,
                  "ii",
                  key, state));
  CHK_RES();
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_popup()
{
  CHK_EVT(GRBASE_HAVE_POPUP);
  newref_t result(
          PyObject_CallMethod(
                  self.o,
                  (char *)S_ON_POPUP,
                  NULL));
  CHK_RES();
}

//-------------------------------------------------------------------------
static PyObject *build_renderer_pos_swig_proxy(const view_mouse_event_t *event)
{
  return SWIG_NewPointerObj(
          SWIG_as_voidptr(&event->renderer_pos),
          SWIGTYPE_p_renderer_pos_info_t,
          0);
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_click(const view_mouse_event_t *event)
{
  CHK_EVT(GRBASE_HAVE_VIEW_CLICK);
  if ( ovc_num_args < 0 )
    ovc_num_args = get_py_method_arg_count((char*)S_ON_VIEW_CLICK);
  if ( ovc_num_args == 6 )
  {
    PyObject *rpos = build_renderer_pos_swig_proxy(event);
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_VIEW_CLICK,
                    "iiiiO",
                    event->x, event->y, event->state, event->button, rpos));
    CHK_RES();
  }
  else if ( ovc_num_args == 5 )
  {
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_VIEW_CLICK,
                    "iiii",
                    event->x, event->y, event->state, event->button));
    CHK_RES();
  }
  else
  {
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_VIEW_CLICK,
                    "iii",
                    event->x, event->y, event->state));
    CHK_RES();
  }
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_dblclick(const view_mouse_event_t *event)
{
  CHK_EVT(GRBASE_HAVE_VIEW_DBLCLICK);
  if ( ovdc_num_args < 0 )
    ovdc_num_args = get_py_method_arg_count((char*)S_ON_VIEW_DBLCLICK);
  if ( ovdc_num_args == 5 )
  {
    PyObject *rpos = build_renderer_pos_swig_proxy(event);
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_VIEW_DBLCLICK,
                    "iiiO",
                    event->x, event->y, event->state, rpos));
    CHK_RES();
  }
  else
  {
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_VIEW_DBLCLICK,
                    "iii",
                    event->x, event->y, event->state));
    CHK_RES();
  }
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_curpos()
{
  CHK_EVT(GRBASE_HAVE_VIEW_CURPOS);
  newref_t result(
          PyObject_CallMethod(
                  self.o,
                  (char *)S_ON_VIEW_CURPOS,
                  NULL));
  CHK_RES();
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_close()
{
  CHK_EVT(GRBASE_HAVE_CLOSE);
  newref_t result(PyObject_CallMethod(self.o, (char *)S_ON_CLOSE, NULL));
  CHK_RES();
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_switched(tcc_renderer_type_t rt)
{
  CHK_EVT(GRBASE_HAVE_VIEW_SWITCHED);
  newref_t result(PyObject_CallMethod(self.o, (char *)S_ON_VIEW_SWITCHED, "i", int(rt)));
  CHK_RES();
}

//-------------------------------------------------------------------------
static ref_t build_current_graph_item_tuple(int *out_icode, const view_mouse_event_t *event)
{
  const selection_item_t *item = event->location.item;
  ref_t tuple;
  if ( (event->rtype == TCCRT_GRAPH || event->rtype == TCCRT_PROXIMITY)
    && item != NULL )
  {
    if ( item->is_node )
    {
      *out_icode = 1;
      tuple = newref_t(Py_BuildValue("(i)", item->node));
    }
    else
    {
      *out_icode = 2;
      tuple = newref_t(Py_BuildValue("(ii)", item->elp.e.src, item->elp.e.dst));
    }
  }
  else
  {
    *out_icode = 0;
    tuple = newref_t(Py_BuildValue("()"));
  }
  return tuple;
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_mouse_over(const view_mouse_event_t *event)
{
  CHK_EVT(GRBASE_HAVE_VIEW_MOUSE_OVER);
  if ( ovmo_num_args < 0 )
    ovmo_num_args = get_py_method_arg_count((char*)S_ON_VIEW_MOUSE_OVER);
  if ( event->rtype != TCCRT_GRAPH && event->rtype != TCCRT_PROXIMITY )
    return;

  int icode;
  ref_t tuple = build_current_graph_item_tuple(&icode, event);
  if ( ovmo_num_args == 7 )
  {
    PyObject *rpos = build_renderer_pos_swig_proxy(event);
    newref_t result(PyObject_CallMethod(
                            self.o,
                            (char *)S_ON_VIEW_MOUSE_OVER,
                            "iiiiOO",
                            event->x, event->y, event->state, icode, tuple.o, rpos));
    CHK_RES();
  }
  else
  {
    newref_t result(PyObject_CallMethod(
                            self.o,
                            (char *)S_ON_VIEW_MOUSE_OVER,
                            "iiiiO",
                            event->x, event->y, event->state, icode, tuple.o));
    CHK_RES();
  }
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_mouse_moved(const view_mouse_event_t *event)
{
  CHK_EVT(GRBASE_HAVE_VIEW_MOUSE_MOVED);
  if ( ovmm_num_args < 0 )
    ovmm_num_args = get_py_method_arg_count((char*)S_ON_VIEW_MOUSE_MOVED);

  int icode;
  ref_t tuple = build_current_graph_item_tuple(&icode, event);
  if ( ovmm_num_args == 7 )
  {
    PyObject *rpos = build_renderer_pos_swig_proxy(event);
    newref_t result(PyObject_CallMethod(
                            self.o,
                            (char *)S_ON_VIEW_MOUSE_MOVED,
                            "iiiiOO",
                            event->x, event->y, event->state, icode, tuple.o, rpos));
    CHK_RES();
  }
}


#undef CHK_RES
#undef CHK_EVT

//-------------------------------------------------------------------------
//-------------------------------------------------------------------------

#define GET_THIS() py_customidamemo_t *_this = view_extract_this<py_customidamemo_t>(self)
#define CHK_THIS()                                                      \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    return
#define CHK_THIS_OR_NULL()                                              \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    return NULL;
#define CHK_THIS_OR_NONE()                                              \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    Py_RETURN_NONE

//-------------------------------------------------------------------------
void pygc_refresh(PyObject *self)
{
  CHK_THIS();
  _this->refresh();
}

//-------------------------------------------------------------------------
void pygc_set_node_info(PyObject *self, PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags)
{
  CHK_THIS();
  _this->set_node_info(py_node_idx, py_node_info, py_flags);
}

//-------------------------------------------------------------------------
void pygc_set_nodes_infos(PyObject *self, PyObject *values)
{
  CHK_THIS();
  _this->set_nodes_infos(values);
}

//-------------------------------------------------------------------------
PyObject *pygc_get_node_info(PyObject *self, PyObject *py_node_idx)
{
  GET_THIS();
  if ( _this != NULL )
    return _this->get_node_info(py_node_idx);
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
void pygc_del_nodes_infos(PyObject *self, PyObject *py_nodes)
{
  CHK_THIS();
  _this->del_nodes_infos(py_nodes);
}

//-------------------------------------------------------------------------
PyObject *pygc_get_current_renderer_type(PyObject *self)
{
  GET_THIS();
  if ( _this != NULL )
    return _this->get_current_renderer_type();
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
void pygc_set_current_renderer_type(PyObject *self, PyObject *py_rt)
{
  CHK_THIS();
  _this->set_current_renderer_type(py_rt);
}

//-------------------------------------------------------------------------
PyObject *pygc_create_groups(PyObject *self, PyObject *groups_infos)
{
  CHK_THIS_OR_NONE();
  return _this->create_groups(groups_infos);
}

//-------------------------------------------------------------------------
PyObject *pygc_delete_groups(PyObject *self, PyObject *groups, PyObject *new_current)
{
  CHK_THIS_OR_NONE();
  return _this->delete_groups(groups, new_current);
}

//-------------------------------------------------------------------------
PyObject *pygc_set_groups_visibility(PyObject *self, PyObject *groups, PyObject *expand, PyObject *new_current)
{
  CHK_THIS_OR_NONE();
  return _this->set_groups_visibility(groups, expand, new_current);
}

//-------------------------------------------------------------------------
TForm *pycim_get_tform(PyObject *self)
{
  CHK_THIS_OR_NULL();
  TForm *form = NULL;
  if ( !py_customidamemo_t::lookup_info.find_by_py_view(&form, NULL, _this) )
    return NULL;
  return form;
}

//-------------------------------------------------------------------------
TCustomControl *pycim_get_tcustom_control(PyObject *self)
{
  CHK_THIS_OR_NULL();
  TCustomControl *tcc = NULL;
  if ( !py_customidamemo_t::lookup_info.find_by_py_view(NULL, &tcc, _this) )
    return NULL;
  return tcc;
}

#undef CHK_THIS_OR_NONE
#undef CHK_THIS_OR_NULL
#undef CHK_THIS
#undef GET_THIS

//-------------------------------------------------------------------------
lookup_info_t py_customidamemo_t::lookup_info;
//</code(py_view_base)>

%}

%inline %{
//<inline(py_view_base)>
void pygc_refresh(PyObject *self);
void pygc_set_node_info(PyObject *self, PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags);
void pygc_set_nodes_infos(PyObject *self, PyObject *values);
PyObject *pygc_get_node_info(PyObject *self, PyObject *py_node_idx);
void pygc_del_nodes_infos(PyObject *self, PyObject *py_nodes);
PyObject *pygc_get_current_renderer_type(PyObject *self);
void pygc_set_current_renderer_type(PyObject *self, PyObject *py_rt);
PyObject *pygc_create_groups(PyObject *self, PyObject *groups_infos);
PyObject *pygc_delete_groups(PyObject *self, PyObject *groups, PyObject *new_current);
PyObject *pygc_set_groups_visibility(PyObject *self, PyObject *groups, PyObject *expand, PyObject *new_current);
TForm *pycim_get_tform(PyObject *self);
TCustomControl *pycim_get_tcustom_control(PyObject *self);
//</inline(py_view_base)>
%}

%pythoncode %{
#<pycode(py_view_base)>
class CustomIDAMemo(object):
    def Refresh(self):
        """
        Refreshes the graph. This causes the OnRefresh() to be called
        """
        _idaapi.pygc_refresh(self)

    def GetCurrentRendererType(self):
        return _idaapi.pygc_get_current_renderer_type(self)

    def SetCurrentRendererType(self, rtype):
        """
        Set the current view's renderer.

        @param rtype: The renderer type. Should be one of the idaapi.TCCRT_* values.
        """
        _idaapi.pygc_set_current_renderer_type(self, rtype)

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
        _idaapi.pygc_set_node_info(self, node_index, node_info, flags)

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
        _idaapi.pygc_set_nodes_infos(self, values)

    def GetNodeInfo(self, node):
        """
        Get the properties for the given node.

        @param node: The index of the node.
        @return: A tuple (bg_color, frame_color, ea, text), or None.
        """
        return _idaapi.pygc_get_node_info(self, node)

    def DelNodesInfos(self, *nodes):
        """
        Delete the properties for the given node(s).

        @param nodes: A list of node IDs
        """
        return _idaapi.pygc_del_nodes_infos(self, nodes)

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
        return _idaapi.pygc_create_groups(self, groups_infos)

    def DeleteGroups(self, groups, new_current = -1):
        """
        Send a request to delete the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param new_current: A node to focus on after the groups have been deleted
        @return: True on success, False otherwise.
        """
        return _idaapi.pygc_delete_groups(self, groups, new_current)

    def SetGroupsVisibility(self, groups, expand, new_current = -1):
        """
        Send a request to expand/collapse the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param expand: True to expand the group, False otherwise.
        @param new_current: A node to focus on after the groups have been expanded/collapsed.
        @return: True on success, False otherwise.
        """
        return _idaapi.pygc_set_groups_visibility(self, groups, expand, new_current)

    def GetTForm(self):
        """
        Return the TForm hosting this view.

        @return: The TForm that hosts this view, or None.
        """
        return _idaapi.pycim_get_tform(self)

    def GetTCustomControl(self):
        """
        Return the TCustomControl underlying this view.

        @return: The TCustomControl underlying this view, or None.
        """
        return _idaapi.pycim_get_tcustom_control(self)


#</pycode(py_view_base)>
%}

%{
//<code(py_idaview)>
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
  if ( lookup_info.find_by_form(&found_view, (py_customidamemo_t**) &py_view, tform) )
  {
    // If we have a py_idaview_t for that form, ensure it has
    // the expected view.
    QASSERT(30451, found_view == v);
  }
  else
  {
    py_view = new py_idaview_t();
    lookup_info_t::entry_t &e = lookup_info.new_entry(py_view);
    lookup_info.commit(e, tform, v);
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

//</code(py_idaview)>
%}

%inline %{
//<inline(py_idaview)>
bool pyidag_bind(PyObject *self);
bool pyidag_unbind(PyObject *self);
//</inline(py_idaview)>
%}

%pythoncode %{
#<pycode(py_idaview)>
class IDAViewWrapper(CustomIDAMemo):
    """This class wraps access to native IDA views. See kernwin.hpp file"""
    def __init__(self, title):
        """
        Constructs the IDAViewWrapper object around the view
        whose title is 'title'.

        @param title: The title of the existing IDA view. E.g., 'IDA View-A'
        """
        self._title = title

    def Bind(self):
        return _idaapi.pyidag_bind(self)

    def Unbind(self):
        return _idaapi.pyidag_unbind(self)

#</pycode(py_idaview)>
%}
