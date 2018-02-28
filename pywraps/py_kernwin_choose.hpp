#ifndef __PY_KERNWIN_CHOOSE__
#define __PY_KERNWIN_CHOOSE__

//<code(py_kernwin_choose)>

//------------------------------------------------------------------------
// Helper functions
class py_choose_t;
typedef std::map<PyObject *, py_choose_t *> py2c_choose_map_t;
static py2c_choose_map_t choosers;

py_choose_t *choose_find_instance(PyObject *self)
{
  py2c_choose_map_t::iterator it = choosers.find(self);
  return it == choosers.end() ? NULL : it->second;
}

void choose_add_instance(PyObject *self, py_choose_t *pych)
{
  choosers[self] = pych;
}

void choose_del_instance(PyObject *self)
{
  py2c_choose_map_t::iterator it = choosers.find(self);
  if ( it != choosers.end() )
    choosers.erase(it);
}

// set `prm` to the integer value of the `name` attribute
template<class T>
static void py_get_int(PyObject *self, T *prm, const char *name)
{
  ref_t attr(PyW_TryGetAttrString(self, name));
  if ( attr != NULL && attr.o != Py_None )
    *prm = T(PyInt_AsLong(attr.o));
}

//------------------------------------------------------------------------
// Python's chooser class
class py_choose_t
{
public:
  // Python object link
  PyObject *self;

  // the chooser object will be created in the create() method
  chooser_base_t *chobj;

  enum
  {
    CHOOSE_HAVE_INIT      = 0x0001,
    CHOOSE_HAVE_GETICON   = 0x0002,
    CHOOSE_HAVE_GETATTR   = 0x0004,
    CHOOSE_HAVE_INS       = 0x0008,
    CHOOSE_HAVE_DEL       = 0x0010,
    CHOOSE_HAVE_EDIT      = 0x0020,
    CHOOSE_HAVE_ENTER     = 0x0040,
    CHOOSE_HAVE_REFRESH   = 0x0080,
    CHOOSE_HAVE_SELECT    = 0x0100,
    CHOOSE_HAVE_ONCLOSE   = 0x0200,
    CHOOSE_IS_EMBEDDED    = 0x0400,
  };

  // Callback flags (to tell which callback exists and which not)
  // One of CHOOSE_xxxx
  uint32 cb_flags;

  sizevec_t embedded_sel;

  // Chooser title
  qstring title;

  // Column widths
  intvec_t widths;

  // Chooser headers
  qstrvec_t header_strings;
  qvector<const char *> header;

public:
  py_choose_t(PyObject *self_) : self(self_), chobj(NULL), cb_flags(0)
  {
    PYW_GIL_GET;
    choose_add_instance(self, this);

    // Increase object reference
    Py_INCREF(self);
  }

  // if the chooser object was created it will delete linked Python's
  // chooser.
  // if it was not created (e.g. because of the lack of a mandatory
  // callback) it will be deleted in choose_close().
  ~py_choose_t()
  {
    PYW_GIL_GET;
    // Remove from list
    choose_del_instance(self);

    Py_XDECREF(self);
  }

  // common callbacks
  bool idaapi init()
  {
    if ( (cb_flags & CHOOSE_HAVE_INIT) == 0 )
      return chobj->chooser_base_t::init();
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self, (char *)S_ON_INIT, NULL));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chobj->chooser_base_t::init();
    return bool(PyInt_AsLong(pyres.result.o));
  }

  size_t idaapi get_count() const
  {
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self, (char *)S_ON_GET_SIZE, NULL));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return 0;

    return size_t(PyInt_AsLong(pyres.result.o));
  }

  void idaapi get_row(
          qstrvec_t *cols,
          int *icon_,
          chooser_item_attrs_t *attrs,
          size_t n) const
  {
    PYW_GIL_GET;

    // Call Python
    PYW_GIL_CHECK_LOCKED_SCOPE();
    pycall_res_t list(
            PyObject_CallMethod(
                    self, (char *)S_ON_GET_LINE,
                    "i", int(n)));
    if ( list.result != NULL )
    {
      // Go over the List returned by Python and convert to C strings
      for ( int i = chobj->columns - 1; i >= 0; --i )
      {
        borref_t item(PyList_GetItem(list.result.o, Py_ssize_t(i)));
        if ( item == NULL )
          continue;

        const char *str = PyString_AsString(item.o);
        if ( str != NULL )
          (*cols)[i] = str;
      }
    }

    *icon_ = chobj->icon;
    if ( (cb_flags & CHOOSE_HAVE_GETICON) != 0 )
    {
      pycall_res_t pyres(
              PyObject_CallMethod(
                      self, (char *)S_ON_GET_ICON,
                      "i", int(n)));
      if ( pyres.result != NULL )
        *icon_ = PyInt_AsLong(pyres.result.o);
    }

    if ( (cb_flags & CHOOSE_HAVE_GETATTR) != 0 )
    {
      pycall_res_t pyres(
              PyObject_CallMethod(
                      self, (char *)S_ON_GET_LINE_ATTR,
                      "i", int(n)));
      if ( pyres.result != NULL && PyList_Check(pyres.result.o) )
      {
        PyObject *item;
        if ( (item = PyList_GetItem(pyres.result.o, 0)) != NULL )
          attrs->color = PyInt_AsLong(item);
        if ( (item = PyList_GetItem(pyres.result.o, 1)) != NULL )
          attrs->flags = PyInt_AsLong(item);
      }
    }
  }

  void idaapi closed()
  {
    if ( (cb_flags & CHOOSE_HAVE_ONCLOSE) == 0 )
    {
      chobj->chooser_base_t::closed();
      return;
    }
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(self, (char *)S_ON_CLOSE, NULL));
    // delete UI hook
    PyObject_DelAttrString(self, "ui_hooks_trampoline");
  }

public:
  static py_choose_t *find_chooser(const char *title)
  {
    return static_cast<py_choose_t *>(::get_chooser_obj(title));
  }

  void close()
  {
    // will trigger closed()
    close_chooser(chobj->title);
  }

  bool activate()
  {
    TWidget *widget = get_widget();
    if ( widget == NULL )
      return false;

    activate_widget(widget, true);
    return true;
  }

  TWidget *get_widget()
  {
    return find_widget(chobj->title);
  }

  // Create a chooser.
  // If it doesn't detect the "embedded" attribute, then the chooser window
  // is created and displayed.
  // See ::choose() for the returned values.
  // \retval NO_ATTR  some mandatory attribute is missing
  int create();

  inline PyObject *get_self()
  {
    return self;
  }

  void do_refresh()
  {
    refresh_chooser(chobj->title);
  }

  chooser_base_t *get_chobj() const
  {
    return chobj;
  }

  const sizevec_t *get_sel_vec() const
  {
    return &embedded_sel;
  }

  bool is_valid() const
  {
    return chobj != NULL;
  }

  bool is_embedded() const
  {
    return (cb_flags & CHOOSE_IS_EMBEDDED) != 0;
  }
};

//------------------------------------------------------------------------
// link from the chooser object to the Python's chooser
struct py_chooser_link_t
{
  py_choose_t *link;  // link to Python's chooser
  py_chooser_link_t(py_choose_t *pych) : link(pych) {}
  ~py_chooser_link_t() { delete link; }
};

//------------------------------------------------------------------------
// we do not use virtual subclasses so we use #define for common code
#define DEFINE_COMMON_CALLBACKS                                         \
  virtual void *get_chooser_obj() ida_override { return link; }         \
  virtual bool idaapi init() ida_override { return link->init(); }      \
  virtual size_t idaapi get_count() const ida_override                  \
  {                                                                     \
    return link->get_count();                                           \
  }                                                                     \
  virtual void idaapi get_row(                                          \
          qstrvec_t *cols,                                              \
          int *icon_,                                                   \
          chooser_item_attrs_t *attrs,                                  \
          size_t n) const ida_override                                  \
  {                                                                     \
    link->get_row(cols, icon_, attrs, n);                               \
  }                                                                     \
  virtual void idaapi closed() ida_override { link->closed(); }

//------------------------------------------------------------------------
// chooser class without multi-selection
class py_chooser_single_t
  : public py_chooser_link_t,
    public chooser_t
{
public:
  py_chooser_single_t(
          py_choose_t *pych,
          uint32 flags_ = 0,
          int columns_ = 0,
          const int *widths_ = NULL,
          const char *const *header_ = NULL,
          const char *title_ = NULL)
    : py_chooser_link_t(pych),
      chooser_t(flags_, columns_, widths_, header_, title_) {}

  DEFINE_COMMON_CALLBACKS

  virtual cbret_t idaapi ins(ssize_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_INS) == 0 )
      return chooser_t::ins(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_INSERT_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::ins(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi del(size_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_DEL) == 0 )
      return chooser_t::del(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_DELETE_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::del(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi edit(size_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_EDIT) == 0 )
      return chooser_t::edit(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_EDIT_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::edit(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi enter(size_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_ENTER) == 0 )
      return chooser_t::enter(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECT_LINE,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::enter(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual cbret_t idaapi refresh(ssize_t n) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_REFRESH) == 0 )
      return chooser_t::refresh(n);
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_REFRESH,
                    "i", int(n)));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_t::refresh(n);
    return py_as_cbret(pyres.result.o);
  }

  virtual void idaapi select(ssize_t n) const ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_SELECT) == 0 )
    {
      chooser_t::select(n);
      return;
    }
    PYW_GIL_GET;
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECTION_CHANGE,
                    "i", int(n)));
  }

protected:
  // [ changed, idx ]
  static cbret_t py_as_cbret(PyObject *py_ret)
  {
    cbret_t ret;
    if ( PySequence_Check(py_ret) )
    {
      {
        newref_t item(PySequence_GetItem(py_ret, 0));
        if ( item.o != NULL && PyInt_Check(item.o) )
          ret.changed = cbres_t(PyInt_AsLong(item.o));
      }
      if ( ret.changed != NOTHING_CHANGED )
      {
        newref_t item(PySequence_GetItem(py_ret, 1));
        if ( item.o != NULL && PyInt_Check(item.o) )
          ret.idx = ssize_t(PyInt_AsSsize_t(item.o));
      }
    }
    return ret;
  }
};

//------------------------------------------------------------------------
// chooser class with multi-selection
class py_chooser_multi_t
  : public py_chooser_link_t,
    public chooser_multi_t
{
public:
  py_chooser_multi_t(
          py_choose_t *pych,
          uint32 flags_ = 0,
          int columns_ = 0,
          const int *widths_ = NULL,
          const char *const *header_ = NULL,
          const char *title_ = NULL)
    : py_chooser_link_t(pych),
      chooser_multi_t(flags_, columns_, widths_, header_, title_) {}

  DEFINE_COMMON_CALLBACKS

  virtual cbres_t idaapi ins(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_INS) == 0 )
      return chooser_multi_t::ins(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_INSERT_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::ins(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi del(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_DEL) == 0 )
      return chooser_multi_t::del(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_DELETE_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::del(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi edit(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_EDIT) == 0 )
      return chooser_multi_t::edit(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_EDIT_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::edit(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi enter(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_ENTER) == 0 )
      return chooser_multi_t::enter(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECT_LINE,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::enter(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual cbres_t idaapi refresh(sizevec_t *sel) ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_REFRESH) == 0 )
      return chooser_multi_t::refresh(sel);
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_REFRESH,
                    "O", py_list.o));
    if ( pyres.result == NULL || pyres.result.o == Py_None )
      return chooser_multi_t::refresh(sel);
    return py_as_cbres_sel(sel, pyres.result.o);
  }

  virtual void idaapi select(const sizevec_t &sel) const ida_override
  {
    if ( (link->cb_flags & py_choose_t::CHOOSE_HAVE_SELECT) == 0 )
    {
      chooser_multi_t::select(sel);
      return;
    }
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(sel));
    pycall_res_t pyres(
            PyObject_CallMethod(
                    link->self, (char *)S_ON_SELECTION_CHANGE,
                    "O", py_list.o));
  }

protected:
  // [ changed, idx, ... ]
  static cbres_t py_as_cbres_sel(sizevec_t *sel, PyObject *py_ret)
  {
    // this is an easy but not an optimal way of converting
    if ( !PySequence_Check(py_ret)
      || PyW_PyListToSizeVec(sel, py_ret) <= 0 )
    {
      sel->clear();
      return NOTHING_CHANGED;
    }
    cbres_t res = cbres_t(sel->front());
    sel->erase(sel->begin());
    return res;
  }
};

//------------------------------------------------------------------------
int py_choose_t::create()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Get flags
  uint32 flags;
  ref_t flags_attr(PyW_TryGetAttrString(self, S_FLAGS));
  if ( flags_attr == NULL )
    return chooser_base_t::NO_ATTR;
  if ( PyInt_Check(flags_attr.o) )
    flags = uint32(PyInt_AsLong(flags_attr.o));
  // instruct TChooser destructor to delete this chooser when window
  // closes
  flags &= ~CH_KEEP;

  // Get the title
  if ( !PyW_GetStringAttr(self, S_TITLE, &title) )
    return chooser_base_t::NO_ATTR;

  // Get columns
  ref_t cols_attr(PyW_TryGetAttrString(self, "cols"));
  if ( cols_attr == NULL )
    return chooser_base_t::NO_ATTR;

  // Get col count
  int columns = int(PyList_Size(cols_attr.o));
  if ( columns < 1 )
    return chooser_base_t::NO_ATTR;

  // Get columns caption and widthes
  header_strings.resize(columns);
  header.resize(columns);
  widths.resize(columns);
  for ( int i = 0; i < columns; ++i )
  {
    // get list item: [name, width]
    borref_t list(PyList_GetItem(cols_attr.o, i));
    borref_t v(PyList_GetItem(list.o, 0));

    // Extract string
    const char *str = v == NULL ? "" : PyString_AsString(v.o);
    header_strings[i] = str;
    header[i] = header_strings[i].c_str();

    // Extract width
    int width;
    borref_t v2(PyList_GetItem(list.o, 1));
    // No width? Guess width from column title
    if ( v2 == NULL )
      width = strlen(str);
    else
      width = PyInt_AsLong(v2.o);
    widths[i] = width;
  }

  // Check what callbacks we have
  static const struct
  {
    const char *name;
    unsigned int have; // 0 = mandatory callback
    int chooser_t_flags;
  } callbacks[] =
  {
    { S_ON_INIT,             CHOOSE_HAVE_INIT,    0 },
    { S_ON_GET_SIZE,         0 },
    { S_ON_GET_LINE,         0 },
    { S_ON_GET_ICON,         CHOOSE_HAVE_GETICON, 0 },
    { S_ON_GET_LINE_ATTR,    CHOOSE_HAVE_GETATTR, 0 },
    { S_ON_INSERT_LINE,      CHOOSE_HAVE_INS,     CH_CAN_INS },
    { S_ON_DELETE_LINE,      CHOOSE_HAVE_DEL,     CH_CAN_DEL },
    { S_ON_EDIT_LINE,        CHOOSE_HAVE_EDIT,    CH_CAN_EDIT },
    { S_ON_SELECT_LINE,      CHOOSE_HAVE_ENTER,   0 },
    { S_ON_REFRESH,          CHOOSE_HAVE_REFRESH, CH_CAN_REFRESH },
    { S_ON_SELECTION_CHANGE, CHOOSE_HAVE_SELECT,  0 },
    { S_ON_CLOSE,            CHOOSE_HAVE_ONCLOSE, 0 },
  };
  // we can forbid some callbacks explicitly
  uint32 forbidden_cb = 0;
  ref_t forbidden_cb_attr(PyW_TryGetAttrString(self, "forbidden_cb"));
  if ( forbidden_cb_attr != NULL && PyInt_Check(forbidden_cb_attr.o) )
    forbidden_cb = uint32(PyInt_AsLong(forbidden_cb_attr.o));
  cb_flags = 0;
  for ( int i = 0; i < qnumber(callbacks); ++i )
  {
    ref_t cb_attr(PyW_TryGetAttrString(self, callbacks[i].name));
    bool have_cb = cb_attr != NULL && PyCallable_Check(cb_attr.o);
    if ( have_cb && (forbidden_cb & callbacks[i].have) == 0 )
    {
      cb_flags |= callbacks[i].have;
      flags |= callbacks[i].chooser_t_flags;
    }
    else
    {
      // Mandatory field?
      if ( callbacks[i].have == 0 )
        return chooser_base_t::NO_ATTR;
    }
  }

  // create chooser object
  if ( (flags & CH_MULTI) == 0 )
  {
    chobj = new py_chooser_single_t(
                        this,
                        flags,
                        columns, widths.begin(), header.begin(),
                        title.c_str());
  }
  else
  {
    chobj = new py_chooser_multi_t(
                        this,
                        flags,
                        columns, widths.begin(), header.begin(),
                        title.c_str());
  }

  // Get *x1,y1,x2,y2
  py_get_int(self, &chobj->x0, "x1");
  py_get_int(self, &chobj->y0, "y1");
  py_get_int(self, &chobj->x1, "x2");
  py_get_int(self, &chobj->y1, "y2");

  // Get *icon
  py_get_int(self, &chobj->icon, "icon");

  // Get *popup names
  // An array of 4 strings: ("Insert", "Delete", "Edit", "Refresh")
  ref_t pn_attr(PyW_TryGetAttrString(self, S_POPUP_NAMES));
  if ( pn_attr != NULL && PyList_Check(pn_attr.o) )
  {
    int npopups = int(PyList_Size(pn_attr.o));
    if ( npopups > chooser_base_t::NSTDPOPUPS )
      npopups = chooser_base_t::NSTDPOPUPS;
    for ( int i = 0; i < npopups; ++i )
    {
      const char *str = PyString_AsString(PyList_GetItem(pn_attr.o, i));
      chobj->popup_names[i] = str;
    }
  }

  // Check if *embedded
  ref_t emb_attr(PyW_TryGetAttrString(self, S_EMBEDDED));
  if ( emb_attr != NULL && PyObject_IsTrue(emb_attr.o) == 1 )
  {
    cb_flags |= CHOOSE_IS_EMBEDDED;
    py_get_int(self, &chobj->width, "width");
    py_get_int(self, &chobj->height, "height");
    return 0; // success
  }

  // run
  ssize_t res;
  if ( !chobj->is_multi() )
  {
    // Get *deflt
    ssize_t deflt = 0;
    py_get_int(self, &deflt, "deflt");
    res = ((chooser_t *)chobj)->choose(deflt);
  }
  else
  {
    // Get *deflt
    sizevec_t deflt;
    ref_t deflt_attr(PyW_TryGetAttrString(self, "deflt"));
    if ( deflt_attr != NULL
      && PyList_Check(deflt_attr.o)
      && PyW_PyListToSizeVec(&deflt, deflt_attr.o) < 0 )
    {
      deflt.clear();
    }
    res = ((chooser_multi_t *)chobj)->choose(deflt);
  }
  // assert: `this` is deleted in the case of the modal chooser

  return res;
}

//------------------------------------------------------------------------
int choose_create(PyObject *self)
{
  py_choose_t *pych;

  pych = choose_find_instance(self);
  if ( pych != NULL && pych->is_valid() )
  {
    if ( !pych->is_embedded() )
      pych->activate();
    return chooser_base_t::ALREADY_EXISTS;
  }

  if ( pych == NULL )
    pych = new py_choose_t(self);
  // assert: returned value != chooser_base_t::ALREADY_EXISTS
  return pych->create();
}

//------------------------------------------------------------------------
void choose_close(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych == NULL )
    return;

  if ( !pych->is_valid() )
  {
    // the chooser object is not created
    // so we delete Python's chooser ourself
    delete pych;
    return;
  }

  // embedded chooser is deleted by form
  if ( pych->is_embedded() )
    return;

  // modal chooser is closed and deleted in py_choose_t::create()
  // assert: !pych->is_modal()

  // close the non-modal chooser,
  // in turn this will lead to the deletion of the object
  pych->close();
}

//------------------------------------------------------------------------
void choose_refresh(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych != NULL && pych->is_valid() )
    pych->do_refresh();
}

//------------------------------------------------------------------------
void choose_activate(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych != NULL && pych->is_valid() )
    pych->activate();
}

//------------------------------------------------------------------------
PyObject *choose_get_embedded_selection(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  py_choose_t *pych = choose_find_instance(self);
  if ( pych == NULL || !pych->is_valid() || !pych->is_embedded() )
    Py_RETURN_NONE;

  ref_t ret(PyW_SizeVecToPyList(*pych->get_sel_vec()));
  ret.incref();
  return ret.o;
}

//------------------------------------------------------------------------
// Return the C instances as 64bit numbers
PyObject *choose_get_embedded(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  py_choose_t *pych = choose_find_instance(self);
  if ( pych == NULL || !pych->is_valid() || !pych->is_embedded() )
    Py_RETURN_NONE;

  return Py_BuildValue(
                 "(KK)",
                 PTR2U64(pych->get_chobj()),
                 PTR2U64(pych->get_sel_vec()));
}

//------------------------------------------------------------------------
PyObject *choose_find(const char *title)
{
  py_choose_t *pych = py_choose_t::find_chooser(title);
  if ( pych == NULL || !pych->is_valid() )
    Py_RETURN_NONE;
  PyObject *self = pych->get_self();
  Py_INCREF(self);
  return self;
}
//</code(py_kernwin_choose)>

//---------------------------------------------------------------------------
//<inline(py_kernwin_choose)>
PyObject *choose_find(const char *title);
void choose_refresh(PyObject *self);
void choose_close(PyObject *self);
int choose_create(PyObject *self);
void choose_activate(PyObject *self);
PyObject *choose_get_embedded(PyObject *self);
PyObject *choose_get_embedded_selection(PyObject *self);

PyObject *py_get_chooser_data(const char *chooser_caption, int n)
{
  qstrvec_t data;
  if ( !get_chooser_data(&data, chooser_caption, n) )
    Py_RETURN_NONE;
  PyObject *py_list = PyList_New(data.size());
  for ( size_t i = 0; i < data.size(); ++i )
    PyList_SetItem(py_list, i, PyString_FromString(data[i].c_str()));
  return py_list;
}

//-------------------------------------------------------------------------
TWidget *choose_get_widget(PyObject *self)
{
  py_choose_t *pych = choose_find_instance(self);
  if ( pych == NULL || !pych->is_valid() )
    return NULL;
  return pych->get_widget();
}

//</inline(py_kernwin_choose)>

#endif // __PY_KERNWIN_CHOOSE__
