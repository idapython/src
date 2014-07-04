#ifndef __PY_VIEW_BASE__
#define __PY_VIEW_BASE__

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
  };

  static void ensure_view_callbacks_installed();
  int cb_flags;
  // number of arguments for OnViewClick implementation
  int ovc_num_args;

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

  // Bi-directionally bind/unbind the Python object and this controller.
  bool bind(PyObject *_self, TCustomControl *view);
  void unbind();

  static lookup_info_t lookup_info;

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
  inline bool has_callback(int flag) { return (cb_flags & flag) != 0; }
  int get_py_method_arg_count(char *method_name);
};

//-------------------------------------------------------------------------
py_customidamemo_t::py_customidamemo_t()
  : self(newref_t(NULL)),
    view(NULL)
{
  PYGLOG("%p: py_customidamemo_t()\n", this);
  ensure_view_callbacks_installed();
  ovc_num_args = -1;
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
            case view_popup:
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
#define CHK_EVT(flag_needed)                                \
  if ( self == NULL || !has_callback(flag_needed) )         \
    return;                                                 \
  PYW_GIL_CHECK_LOCKED_SCOPE()

#ifdef PYGDBG_ENABLED
#define CHK_RES() PYGLOG("%s: return code: %p\n", __FUNCTION__, result.o)
#else
#define CHK_RES()
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
void py_customidamemo_t::on_view_click(const view_mouse_event_t *event)
{
  CHK_EVT(GRBASE_HAVE_VIEW_CLICK);
  if ( ovc_num_args < 0 )
    ovc_num_args = get_py_method_arg_count((char*)S_ON_VIEW_CLICK);
  if ( ovc_num_args == 5 )
  {
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_VIEW_CLICK,
                    "iiii",
                    event->x, event->y, event->state, event->button));
  }
  else
  {
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_VIEW_CLICK,
                    "iii",
                    event->x, event->y, event->state));
  }
  CHK_RES();
}

//-------------------------------------------------------------------------
void py_customidamemo_t::on_view_dblclick(const view_mouse_event_t *event)
{
  CHK_EVT(GRBASE_HAVE_VIEW_DBLCLICK);
  newref_t result(
          PyObject_CallMethod(
                  self.o,
                  (char *)S_ON_VIEW_DBLCLICK,
                  "iii",
                  event->x, event->y, event->state));
  CHK_RES();
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
void py_customidamemo_t::on_view_mouse_over(const view_mouse_event_t *event)
{
  CHK_EVT(GRBASE_HAVE_VIEW_MOUSE_OVER);
  if ( event->rtype == TCCRT_GRAPH || event->rtype == TCCRT_PROXIMITY )
  {
    const selection_item_t *item = event->location.item;
    int icode;
    ref_t tuple;
    if ( item != NULL )
    {
      if ( item->is_node )
      {
        icode = 1;
        tuple = newref_t(Py_BuildValue("(i)", item->node));
      }
      else
      {
        icode = 2;
        tuple = newref_t(Py_BuildValue("(ii)", item->elp.e.src, item->elp.e.dst));
      }
    }
    else
    {
      icode = 0;
      tuple = newref_t(Py_BuildValue("()"));
    }
    newref_t result(PyObject_CallMethod(
                            self.o,
                            (char *)S_ON_VIEW_MOUSE_OVER,
                            "iiiiO",
                            event->x, event->y, event->state, icode, tuple.o));
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

#undef CHK_THIS_OR_NONE
#undef CHK_THIS
#undef GET_THIS

//-------------------------------------------------------------------------
lookup_info_t py_customidamemo_t::lookup_info;
//</code(py_view_base)>

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
//</inline(py_view_base)>



#endif // __PY_VIEW_BASE__

