#ifndef __PY_KERNWIN_CHOOSE__
#define __PY_KERNWIN_CHOOSE__

//<code(py_kernwin_choose)>

// set `prm` to the integer value of the `name` attribute
template <class T>
static void py_get_int(PyObject *self, T *prm, const char *name)
{
  ref_t attr(PyW_TryGetAttrString(self, name));
  if ( attr != nullptr && attr.o != Py_None )
    *prm = T(PyInt_AsLong(attr.o));
}

enum feature_t
{
  CFEAT_INIT          = 0x0001,
  CFEAT_GETICON       = 0x0002,
  CFEAT_GETATTR       = 0x0004,
  CFEAT_INS           = 0x0008,
  CFEAT_DEL           = 0x0010,
  CFEAT_EDIT          = 0x0020,
  CFEAT_ENTER         = 0x0040,
  CFEAT_REFRESH       = 0x0080,
  CFEAT_SELECT        = 0x0100,
  CFEAT_ONCLOSE       = 0x0200,
  CFEAT_EMBEDDED      = 0x0400,
  CFEAT_GETEA         = 0x0800,
  CFEAT_GETDIRTREE    = 0x1000,
  CFEAT_INDEX2INODE   = 0x2000,
  CFEAT_INDEX2DIFFPOS = 0x4000,
  CFEAT_LAZYLOADDIR   = 0x8000,
};

//------------------------------------------------------------------------
// we do not use virtual subclasses so we use #define for common code
#define DEFINE_COMMON_CALLBACKS                                         \
  virtual const void *get_obj_id(size_t *len) const override            \
  {                                                                     \
    return mixin_get_obj_id(len);                                       \
  }                                                                     \
  virtual void *get_chooser_obj() override                              \
  {                                                                     \
    return mixin_get_chooser_obj();                                     \
  }                                                                     \
  virtual bool idaapi init() override                                   \
  {                                                                     \
    return mixin_init(this);                                            \
  }                                                                     \
  virtual size_t idaapi get_count() const override                      \
  {                                                                     \
    return mixin_get_count();                                           \
  }                                                                     \
  virtual void idaapi get_row(                                          \
        qstrvec_t *cols,                                                \
        int *icon_,                                                     \
        chooser_item_attrs_t *attrs,                                    \
        size_t n) const override                                        \
  {                                                                     \
    mixin_get_row(cols, icon_, attrs, n, this);                         \
  }                                                                     \
  virtual void idaapi closed() override                                 \
  {                                                                     \
    mixin_closed(this);                                                 \
  }                                                                     \
  virtual ea_t idaapi get_ea(size_t n) const override                   \
  {                                                                     \
    return mixin_get_ea(n);                                             \
  }                                                                     \
  virtual dirtree_t *idaapi get_dirtree() override                      \
  {                                                                     \
    return mixin_get_dirtree(this);                                     \
  }                                                                     \
  virtual inode_t idaapi index_to_inode(size_t n) const override        \
  {                                                                     \
    return mixin_index_to_inode(n);                                     \
  }                                                                     \
  virtual diffpos_t idaapi index_to_diffpos(size_t n) const override    \
  {                                                                     \
    return mixin_index_to_diffpos(n);                                   \
  }


//-------------------------------------------------------------------------
struct py_chooser_props_t
{
  qstring title;            // Chooser title
  intvec_t widths;          // Column widths
  qstrvec_t header_strings; // Chooser headers
  qvector<const char *> header;
  qstrvec_t popup_names;
  // Features flags (to tell which callback exists and which not)
  // See CHOOSE_xxxx
  uint32 features;
  uint32 flags;
  uint16 flags2;

  py_chooser_props_t() : features(0), flags(0) {}

  void swap(py_chooser_props_t &o)
  {
    title.swap(o.title);
    widths.swap(o.widths);
    header_strings.swap(o.header_strings);
    header.swap(o.header);
    popup_names.swap(o.popup_names);
    qswap(features, o.features);
    qswap(flags, o.flags);
    qswap(flags2, o.flags2);
  }

  bool has_feature(feature_t f) const { return (features & f) == f; }

  static bool is_valid_cb(
        PyObject *o,
        const char *name);

  static bool do_extract_from_pyobject(
        py_chooser_props_t *out,
        PyObject *o,
        bool title_only,
        qstring *errbuf);

  static bool extract_from_pyobject(
        py_chooser_props_t *out,
        PyObject *o,
        qstring *errbuf)
  {
    return do_extract_from_pyobject(out, o, /*title_only=*/ false, errbuf);
  }

  static bool get_title_from_pyobject(
        qstring *out,
        PyObject *o,
        qstring *errbuf)
  {
    py_chooser_props_t props;
    bool ok = do_extract_from_pyobject(&props, o, /*title_only=*/ true, errbuf);
    if ( ok )
      out->swap(props.title);
    return ok;
  }
};

//-------------------------------------------------------------------------
bool py_chooser_props_t::is_valid_cb(
        PyObject *o,
        const char *name)
{
  newref_t py_o_class(PyObject_GetAttrString(o, "__class__"));
  bool ok = py_o_class;
#ifdef TESTABLE_BUILD
  QASSERT(30706, ok);
#endif
  if ( ok )
  {
    newref_t py_oclass_meth(PyObject_GetAttrString(py_o_class.o, name));
    ok = py_oclass_meth && PyCallable_Check(py_oclass_meth.o);
#ifdef TESTABLE_BUILD
    QASSERT(30707, ok);
#endif
    if ( ok )
    {
      newref_t py_ida_kernwin(PyImport_ImportModule("ida_kernwin"));
      ok = py_ida_kernwin;
#ifdef TESTABLE_BUILD
      QASSERT(30708, ok);
#endif
      if ( ok )
      {
        newref_t py_chooser(PyObject_GetAttrString(py_ida_kernwin.o, "Choose"));
        ok = py_chooser;
#ifdef TESTABLE_BUILD
        QASSERT(30709, ok);
#endif
        if ( ok )
        {
          newref_t py_def_cb(PyObject_GetAttrString(py_chooser.o, name));
          ok = py_def_cb;
#ifdef TESTABLE_BUILD
          QASSERT(30710, ok);
#endif
          if ( ok )
          {
            ok = PyObject_RichCompareBool(py_def_cb.o, /*cb_attr*/py_oclass_meth.o, Py_EQ) == 0;
            // if ( ok )
            //   msg("HAS NON-DEF: %s\n", name);
          }
        }
      }
    }
  }
  return ok;
}

//-------------------------------------------------------------------------
bool py_chooser_props_t::do_extract_from_pyobject(
        py_chooser_props_t *out,
        PyObject *o,
        bool title_only,
        qstring *errbuf)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

#define RETERR(Format, ...) do { errbuf->sprnt(Format, __VA_ARGS__); return false; } while ( false )

  // Get the title
  if ( !PyW_GetStringAttr(o, S_TITLE, &out->title) )
    RETERR("Missing or invalid mandatory '%s' attribute", S_TITLE);

  if ( title_only )
    return true;

  // Get flags
  out->flags = 0;
  ref_t flags_attr(PyW_TryGetAttrString(o, S_FLAGS));
  if ( flags_attr == nullptr )
    RETERR("Missing or invalid mandatory '%s' attribute", S_FLAGS);

  if ( PyLong_Check(flags_attr.o) )
    out->flags = uint32(PyLong_AsLong(flags_attr.o));
  // instruct TChooser destructor to delete this chooser when widget
  // closes
  out->flags &= ~CH_KEEP;

  // Optionally get the extended flags
  out->flags2 = 0;
  ref_t flags2_attr(PyW_TryGetAttrString(o, S_FLAGS2));
  if ( flags2_attr != nullptr && PyLong_Check(flags2_attr.o) )
    out->flags2 = uint16(PyLong_AsLong(flags2_attr.o));

  // Get columns
  int ncols = -1;
  ref_t cols_attr(PyW_TryGetAttrString(o, "cols"));
  if ( cols_attr != nullptr )
    ncols = int(PyList_Size(cols_attr.o));
  if ( ncols < 1 )
    RETERR("Missing or invalid mandatory '%s' attribute", S_COLS);

  // Get columns caption and widthes
  out->header_strings.resize(ncols);
  out->header.resize(ncols);
  out->widths.resize(ncols);
  for ( int i = 0; i < ncols; ++i )
  {
    // get list item: [name, width]
    borref_t list(PyList_GetItem(cols_attr.o, i));
    // Extract string
    if ( ref_t v = borref_t(PyList_GetItem(list.o, 0)) )
      PyUnicode_as_qstring(&out->header_strings[i], v.o);
    out->header[i] = out->header_strings[i].c_str();

    // Extract width
    int width;
    // No width? Guess width from column title
    if ( ref_t v2 = borref_t(PyList_GetItem(list.o, 1)) )
      width = PyInt_AsLong(v2.o);
    else
      width = ::qustrlen(out->header_strings[i].c_str());
    out->widths[i] = width;
  }

  // Get popup names
  // An array of 4 strings: ("Insert", "Delete", "Edit", "Refresh")
  ref_t pn_attr(PyW_TryGetAttrString(o, S_POPUP_NAMES));
  if ( pn_attr != nullptr && PyList_Check(pn_attr.o) )
  {
    Py_ssize_t npopups = PyList_Size(pn_attr.o);
    if ( npopups > chooser_base_t::NSTDPOPUPS )
      npopups = chooser_base_t::NSTDPOPUPS;
    for ( Py_ssize_t i = 0; i < npopups; ++i )
    {
      qstring &buf = out->popup_names.push_back();
      PyUnicode_as_qstring(&buf, PyList_GetItem(pn_attr.o, i));
    }
  }

  // Check what callbacks we have
  static const struct
  {
    const char *name;
    unsigned int have; // 0 = mandatory callback
    int chooser_t_flags;
    int chooser_t_flags2;
  } callbacks[] =
  {
    { S_ON_INIT,             CFEAT_INIT,    0, 0 },
    { S_ON_GET_SIZE,         0, 0 },
    { S_ON_GET_LINE,         0, 0 },
    { S_ON_GET_ICON,         CFEAT_GETICON, 0, 0 },
    { S_ON_GET_LINE_ATTR,    CFEAT_GETATTR, 0, 0 },
    { S_ON_INSERT_LINE,      CFEAT_INS,     CH_CAN_INS, 0 },
    { S_ON_DELETE_LINE,      CFEAT_DEL,     CH_CAN_DEL, 0 },
    { S_ON_EDIT_LINE,        CFEAT_EDIT,    CH_CAN_EDIT, 0 },
    { S_ON_SELECT_LINE,      CFEAT_ENTER,   0, 0 },
    { S_ON_REFRESH,          CFEAT_REFRESH, CH_CAN_REFRESH, 0 },
    { S_ON_SELECTION_CHANGE, CFEAT_SELECT,  0, 0 },
    { S_ON_CLOSE,            CFEAT_ONCLOSE, 0, 0 },
    { S_ON_GET_EA,           CFEAT_GETEA,   0, 0 },
    { S_ON_GET_DIRTREE,      CFEAT_GETDIRTREE, CH_HAS_DIRTREE, 0 },
    { S_ON_INDEX_TO_INODE,   CFEAT_INDEX2INODE, CH_HAS_DIRTREE, 0 },
    { S_ON_INDEX_TO_DIFFPOS, CFEAT_INDEX2DIFFPOS, CH_HAS_DIFF, 0 },
    { S_ON_LAZY_LOAD_DIR,    CFEAT_LAZYLOADDIR, CH_HAS_DIRTREE, CH2_LAZY_LOADED },
  };
  // we can forbid some callbacks explicitly
  uint32 forbidden_cb = 0;
  ref_t forbidden_cb_attr(PyW_TryGetAttrString(o, "forbidden_cb"));
  if ( forbidden_cb_attr != nullptr && PyLong_Check(forbidden_cb_attr.o) )
    forbidden_cb = uint32(PyLong_AsLong(forbidden_cb_attr.o));

  out->features = 0;
  for ( int i = 0; i < qnumber(callbacks); ++i )
  {
    if ( (forbidden_cb & callbacks[i].have) == 0
      && is_valid_cb(o, callbacks[i].name) )
    {
      out->features |= callbacks[i].have;
      out->flags |= callbacks[i].chooser_t_flags;
      out->flags2 |= callbacks[i].chooser_t_flags2;
    }
    else
    {
      // Mandatory field?
      if ( callbacks[i].have == 0 )
        RETERR("Missing or invalid mandatory '%s' callback", callbacks[i].name);
    }
  }

  // Check if *embedded
  ref_t emb_attr(PyW_TryGetAttrString(o, S_EMBEDDED));
  if ( emb_attr != nullptr && PyObject_IsTrue(emb_attr.o) == 1 )
    out->features |= CFEAT_EMBEDDED;

#undef RETERR

  return true;
}

//-------------------------------------------------------------------------
struct py_chooser_mixin_t
{
  ref_t self; // link to actual Python object
  ref_t dirspec;
  ref_t dirtree;
  py_chooser_props_t props;

  py_chooser_mixin_t(PyObject *_self, py_chooser_props_t &_props)
    : self(borref_t(_self))
  {
    _instances.add_unique(this);
    props.swap(_props);
  }
  ~py_chooser_mixin_t()
  {
    PYW_GIL_GET;
    self = newref_t(nullptr);
    dirspec = newref_t(nullptr);
    dirtree = newref_t(nullptr);
    _instances.del(this);
  }

  bool has_feature(feature_t f) const { return props.has_feature(f); }
  static chooser_base_t *create_concrete_instance(
        py_chooser_props_t &props,
        PyObject *o);

  static py_chooser_mixin_t *find_by_pyobj(PyObject *o);

protected:
  const void *mixin_get_obj_id(size_t *len) const { *len = sizeof(self.o); return self.o; }
  void *mixin_get_chooser_obj() { return self.o; }
  bool mixin_init(chooser_base_t *chobj);
  size_t mixin_get_count() const;
  void mixin_get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n,
        const chooser_base_t *chobj) const;
  void mixin_closed(chooser_base_t *chobj);
  ea_t mixin_get_ea(size_t n) const;
  dirtree_t *mixin_get_dirtree(const chooser_base_t *chobj);
  inode_t mixin_index_to_inode(size_t n) const;
  diffpos_t mixin_index_to_diffpos(size_t n) const;
  void mixin_init_chooser_base_from_props(chooser_base_t *cb);
  bool mixin_lazy_load_dir(dirtree_t *dt, const qstring &dir_path);

private:
  static qvector<py_chooser_mixin_t*> _instances;
};

//-------------------------------------------------------------------------
qvector<py_chooser_mixin_t*> py_chooser_mixin_t::_instances;

//-------------------------------------------------------------------------
bool py_chooser_mixin_t::mixin_init(chooser_base_t *chobj)
{
  if ( !has_feature(CFEAT_INIT) )
    return chobj->chooser_base_t::init();
  PYW_GIL_GET;
  pycall_res_t pyres(PyObject_CallMethod(self.o, (char *)S_ON_INIT, nullptr));
  if ( pyres.result == nullptr || pyres.result.o == Py_None )
    return chobj->chooser_base_t::init();
  return bool(PyInt_AsLong(pyres.result.o));
}

//-------------------------------------------------------------------------
size_t py_chooser_mixin_t::mixin_get_count() const
{
  PYW_GIL_GET;
  pycall_res_t pyres(PyObject_CallMethod(self.o, (char *)S_ON_GET_SIZE, nullptr));
  if ( pyres.result == nullptr || pyres.result.o == Py_None )
    return 0;
  return size_t(PyInt_AsLong(pyres.result.o));
}

//-------------------------------------------------------------------------
void py_chooser_mixin_t::mixin_get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n,
        const chooser_base_t *chobj) const
{
  PYW_GIL_GET;

  // Call Python
  PYW_GIL_CHECK_LOCKED_SCOPE();
  pycall_res_t list(
          PyObject_CallMethod(
                  self.o, (char *)S_ON_GET_LINE,
                  "i", int(n)));
  if ( PyErr_Occurred() != nullptr )
    return;
  if ( list.result != nullptr )
  {
    if ( PySequence_Check(list.result.o) )
    {
      // Go over the List returned by Python and convert to C strings
      for ( int i = chobj->columns - 1; i >= 0; --i )
      {
        if ( ref_t item = newref_t(PySequence_GetItem(list.result.o, Py_ssize_t(i))) )
        {
          if ( !PyUnicode_Check(item.o) )
          {
            PyErr_Format(
                    PyExc_TypeError,
                    "Expected 'str' data for row %" FMT_Z ", column %d", n, i);
            break;
          }
          PyUnicode_as_qstring(&cols->at(i), item.o);
        }
      }
    }
    else
    {
      PyErr_Format(
              PyExc_TypeError,
              "Expected 'list' for row %" FMT_Z, n);
    }
  }
  if ( PyErr_Occurred() != nullptr )
    return;

  *icon_ = chobj->icon;
  if ( has_feature(CFEAT_GETICON) )
  {
    pycall_res_t pyres(
            PyObject_CallMethod(
                    self.o, (char *)S_ON_GET_ICON,
                    "i", int(n)));
    if ( PyErr_Occurred() != nullptr )
      return;
    if ( pyres.result != nullptr )
      *icon_ = PyInt_AsLong(pyres.result.o);
  }

  if ( has_feature(CFEAT_GETATTR) )
  {
    pycall_res_t pyres(
            PyObject_CallMethod(
                    self.o, (char *)S_ON_GET_LINE_ATTR,
                    "i", int(n)));
    if ( PyErr_Occurred() == nullptr && pyres.result != nullptr && PySequence_Check(pyres.result.o) )
    {
      {
        newref_t item(PySequence_GetItem(pyres.result.o, 0));
        if ( item && PyLong_Check(item.o) )
          attrs->color = PyLong_AsUnsignedLong(item.o);
      }
      {
        newref_t item(PySequence_GetItem(pyres.result.o, 1));
        if ( item && PyLong_Check(item.o) )
          attrs->flags = PyInt_AsLong(item.o);
      }
    }
  }
}

//-------------------------------------------------------------------------
void py_chooser_mixin_t::mixin_closed(chooser_base_t *chobj)
{
  PYW_GIL_GET;
  if ( has_feature(CFEAT_ONCLOSE) )
  {
    pycall_res_t pyres(PyObject_CallMethod(self.o, (char *)S_ON_CLOSE, nullptr));
  }
  else
  {
    chobj->chooser_base_t::closed();
  }
  if ( PyObject_HasAttrString(self.o, "ui_hooks_trampoline") )
  {
    {
      newref_t tramp(PyObject_GetAttrString(self.o, "ui_hooks_trampoline"));
      if ( tramp.o != Py_None )
      {
        newref_t unhook_res(PyObject_CallMethod(tramp.o, "unhook", nullptr));
      }
    }
    PyObject_DelAttrString(self.o, "ui_hooks_trampoline");
  }
}

//-------------------------------------------------------------------------
ea_t py_chooser_mixin_t::mixin_get_ea(size_t n) const
{
  ea_t ea = BADADDR;
  if ( has_feature(CFEAT_GETEA) )
  {
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self.o, (char *) S_ON_GET_EA, PY_BV_SZ, Py_ssize_t(n)));
    if ( pyres.result != nullptr )
    {
      uint64 u64;
      if ( PyW_GetNumber(pyres.result.o, &u64) )
        ea = ea_t(u64);
    }
  }
  return ea;
}

//-------------------------------------------------------------------------
dirtree_t *py_chooser_mixin_t::mixin_get_dirtree(const chooser_base_t * /*chobj*/)
{
  if ( !has_feature(CFEAT_GETDIRTREE) )
    return nullptr;
  PYW_GIL_GET;

  pycall_res_t pyres(PyObject_CallMethod(self.o, (char *) S_ON_GET_DIRTREE, nullptr));
  if ( pyres.result == nullptr )
    return nullptr;

  if ( !PyTuple_Check(pyres.result.o) || PyTuple_Size(pyres.result.o) != 2 )
  {
GET_DIRTREE_BAD_RESULT:
    PyErr_Format(PyExc_TypeError, "%s must return a tuple (dirspec_t, dirtree_t)", S_ON_GET_DIRTREE);
    return nullptr;
  }

  {
    borref_t py_dirspec(PyTuple_GetItem(pyres.result.o, 0));
    dirspec_t *dirspec_ptr = nullptr;
    if ( !SWIG_IsOK(SWIG_ConvertPtr(py_dirspec.o, (void **) &dirspec_ptr, SWIGTYPE_p_dirspec_t, 0)) )
      goto GET_DIRTREE_BAD_RESULT;
    dirspec = py_dirspec;
  }

  dirtree_t *dirtree_ptr = nullptr;
  {
    borref_t py_dirtree(PyTuple_GetItem(pyres.result.o, 1));
    if ( !SWIG_IsOK(SWIG_ConvertPtr(py_dirtree.o, (void **) &dirtree_ptr, SWIGTYPE_p_dirtree_t, 0)) )
      goto GET_DIRTREE_BAD_RESULT;
    dirtree = py_dirtree;
  }

  return dirtree_ptr;
}

//-------------------------------------------------------------------------
inode_t py_chooser_mixin_t::mixin_index_to_inode(size_t n) const
{
  inode_t inode = BADADDR;
  if ( has_feature(CFEAT_INDEX2INODE) )
  {
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self.o, (char *) S_ON_INDEX_TO_INODE, PY_BV_SZ, Py_ssize_t(n)));
    if ( pyres.result != nullptr )
    {
      uint64 u64;
      if ( PyW_GetNumber(pyres.result.o, &u64) )
        inode = inode_t(u64);
    }
  }
  return inode;
}

//-------------------------------------------------------------------------
diffpos_t py_chooser_mixin_t::mixin_index_to_diffpos(size_t n) const
{
  diffpos_t diffpos = diffpos_t(-1); // BADDIFF;
  if ( has_feature(CFEAT_INDEX2DIFFPOS) )
  {
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self.o, (char *) S_ON_INDEX_TO_DIFFPOS, PY_BV_SZ, Py_ssize_t(n)));
    if ( pyres.result != nullptr )
    {
      uint64 u64;
      if ( PyW_GetNumber(pyres.result.o, &u64) )
        diffpos = diffpos_t(u64);
    }
  }
  return diffpos;
}

//-------------------------------------------------------------------------
void py_chooser_mixin_t::mixin_init_chooser_base_from_props(
        chooser_base_t *cb)
{
  for ( size_t i = 0; i < props.popup_names.size(); ++i )
    cb->popup_names[i] = props.popup_names[i].begin();
}

//-------------------------------------------------------------------------
bool py_chooser_mixin_t::mixin_lazy_load_dir(
        dirtree_t *dt,
        const qstring &dir_path)
{
  if ( !has_feature(CFEAT_LAZYLOADDIR) )
    return false;
  PYW_GIL_GET;
  pycall_res_t pyres(PyObject_CallMethod(self.o, (char *)S_ON_LAZY_LOAD_DIR, "s", dir_path.c_str())); // TODO: pass the dirtree_t (presumably using PyObject_CallFunctionObjArgs)
  if ( pyres.result == nullptr || pyres.result.o == Py_None )
    return false;
  return bool(PyInt_AsLong(pyres.result.o));
}

//------------------------------------------------------------------------
// chooser class without multi-selection
class py_chooser_t : public chooser_t, public py_chooser_mixin_t
{
  bool _call(cbret_t *out, feature_t feature, const char *name, int n) const
  {
    if ( !has_feature(feature) )
      return false;
    PYW_GIL_GET;
    pycall_res_t pyres(PyObject_CallMethod(self.o, (char *) name, "i", n));
    if ( pyres.result == nullptr || pyres.result.o == Py_None )
      return false;
    if ( out != nullptr )
    {
      // [ changed, idx ]
      cbret_t ret;
      if ( PySequence_Check(pyres.result.o) )
      {
        {
          newref_t item(PySequence_GetItem(pyres.result.o, 0));
          if ( item && PyLong_Check(item.o) )
            ret.changed = cbres_t(PyLong_AsLong(item.o));
        }
        if ( ret.changed != NOTHING_CHANGED )
        {
          newref_t item(PySequence_GetItem(pyres.result.o, 1));
          if ( item && PyLong_Check(item.o) )
            ret.idx = ssize_t(PyLong_AsSsize_t(item.o));
        }
      }
      *out = ret;
    }
    return true;
  }

public:
  py_chooser_t(PyObject *self_, py_chooser_props_t &props_)
    : chooser_t(
            props_.flags,
            props_.widths.size(),
            props_.widths.begin(),
            props_.header.begin(),
            props_.title.c_str(),
            props_.flags2),
      py_chooser_mixin_t(self_, props_)
  {
    mixin_init_chooser_base_from_props(this);
  }

  DEFINE_COMMON_CALLBACKS

  virtual cbret_t idaapi ins(ssize_t n) override
  {
    cbret_t res;
    return _call(&res, CFEAT_INS, S_ON_INSERT_LINE, int(n)) ? res : chooser_t::ins(n);
  }

  virtual cbret_t idaapi del(size_t n) override
  {
    cbret_t res;
    return _call(&res, CFEAT_DEL, S_ON_DELETE_LINE, int(n)) ? res : chooser_t::del(n);
  }

  virtual cbret_t idaapi edit(size_t n) override
  {
    cbret_t res;
    return _call(&res, CFEAT_EDIT, S_ON_EDIT_LINE, int(n)) ? res : chooser_t::edit(n);
  }

  virtual cbret_t idaapi enter(size_t n) override
  {
    cbret_t res;
    return _call(&res, CFEAT_ENTER, S_ON_SELECT_LINE, int(n)) ? res : chooser_t::enter(n);
  }

  virtual cbret_t idaapi refresh(ssize_t n) override
  {
    cbret_t res;
    return _call(&res, CFEAT_REFRESH, S_ON_REFRESH, int(n)) ? res : chooser_t::refresh(n);
  }

  virtual void idaapi select(ssize_t n) const override
  {
    _call(nullptr, CFEAT_SELECT, S_ON_SELECTION_CHANGE, int(n));
  }

  virtual bool idaapi do_lazy_load_dir(
        dirtree_t *dt,
        const qstring &dir_path) override
  {
    return mixin_lazy_load_dir(dt, dir_path);
  }
};

//------------------------------------------------------------------------
// chooser class with multi-selection
class py_chooser_multi_t : public chooser_multi_t, public py_chooser_mixin_t
{
  bool _call(cbres_t *out, feature_t feature, const char *name, sizevec_t *sel) const
  {
    if ( !has_feature(feature) )
      return false;
    PYW_GIL_GET;
    ref_t py_list(PyW_SizeVecToPyList(*sel));
    pycall_res_t pyres(PyObject_CallMethod(self.o, (char *) name, "O", py_list.o));
    if ( pyres.result == nullptr || pyres.result.o == Py_None )
      return false;
    // [ changed, idx, ... ]
    cbres_t res;
    // this is an easy but not an optimal way of converting
    if ( !PySequence_Check(pyres.result.o)
      || PyW_PySeqToSizeVec(sel, pyres.result.o) <= 0 )
    {
      sel->clear();
      res = NOTHING_CHANGED;
    }
    else
    {
      res = cbres_t(sel->front());
      sel->erase(sel->begin());
    }
    if ( out != nullptr )
      *out = res;
    return true;
  }

public:
  py_chooser_multi_t(PyObject *self_, py_chooser_props_t &props_)
    : chooser_multi_t(
            props_.flags,
            props_.widths.size(),
            props_.widths.begin(),
            props_.header.begin(),
            props_.title.c_str(),
            props_.flags2),
      py_chooser_mixin_t(self_, props_)
  {
    mixin_init_chooser_base_from_props(this);
  }

 DEFINE_COMMON_CALLBACKS

  virtual cbres_t idaapi ins(sizevec_t *sel) override
  {
    cbres_t res = NOTHING_CHANGED;
    return _call(&res, CFEAT_INS, S_ON_INSERT_LINE, sel) ? res : chooser_multi_t::ins(sel);
  }

  virtual cbres_t idaapi del(sizevec_t *sel) override
  {
    cbres_t res = NOTHING_CHANGED;
    return _call(&res, CFEAT_DEL, S_ON_DELETE_LINE, sel) ? res : chooser_multi_t::del(sel);
  }

  virtual cbres_t idaapi edit(sizevec_t *sel) override
  {
    cbres_t res = NOTHING_CHANGED;
    return _call(&res, CFEAT_EDIT, S_ON_EDIT_LINE, sel) ? res : chooser_multi_t::edit(sel);
  }

  virtual cbres_t idaapi enter(sizevec_t *sel) override
  {
    cbres_t res = NOTHING_CHANGED;
    return _call(&res, CFEAT_ENTER, S_ON_SELECT_LINE, sel) ? res : chooser_multi_t::enter(sel);
  }

  virtual cbres_t idaapi refresh(sizevec_t *sel) override
  {
    cbres_t res = NOTHING_CHANGED;
    return _call(&res, CFEAT_REFRESH, S_ON_REFRESH, sel) ? res : chooser_multi_t::refresh(sel);
  }

  virtual void idaapi select(const sizevec_t &_sel) const override
  {
    sizevec_t sel = _sel;
    _call(nullptr, CFEAT_SELECT, S_ON_SELECTION_CHANGE, &sel);
  }

  virtual bool idaapi do_lazy_load_dir(
        dirtree_t *dt,
        const qstring &dir_path) override
  {
    return mixin_lazy_load_dir(dt, dir_path);
  }
};

//-------------------------------------------------------------------------
chooser_base_t *py_chooser_mixin_t::create_concrete_instance(
        py_chooser_props_t &props,
        PyObject *o)
{
  chooser_base_t *chobj = nullptr;
  if ( (props.flags & CH_MULTI) == 0 )
    chobj = new py_chooser_t(o, props);
  else
    chobj = new py_chooser_multi_t(o, props);

  // Get *x1,y1,x2,y2
  py_get_int(o, &chobj->x0, "x1");
  py_get_int(o, &chobj->y0, "y1");
  py_get_int(o, &chobj->x1, "x2");
  py_get_int(o, &chobj->y1, "y2");

  // Get *icon
  py_get_int(o, &chobj->icon, "icon");

  if ( props.has_feature(CFEAT_EMBEDDED) )
  {
    py_get_int(o, &chobj->width, "width");
    py_get_int(o, &chobj->height, "height");
  }
  return chobj;
}

//-------------------------------------------------------------------------
py_chooser_mixin_t * py_chooser_mixin_t::find_by_pyobj(
        PyObject *o)
{
  for ( auto m : _instances )
    if ( m->mixin_get_chooser_obj() == o )
      return m;
  return nullptr;
}

//-------------------------------------------------------------------------
PyObject *choose_choose(PyObject *self)
{
  qstring errbuf;
  py_chooser_props_t props;
  if ( !py_chooser_props_t::extract_from_pyobject(&props, self, &errbuf) )
  {
    PyErr_SetString(PyExc_AttributeError, errbuf.c_str());
    return nullptr;
  }
  chooser_base_t *chobj = py_chooser_mixin_t::create_concrete_instance(props, self);

  ssize_t res;
  if ( !chobj->is_multi() )
  {
    // Get *deflt
    ssize_t deflt = 0;
    py_get_int(self, &deflt, "deflt");
    res = ((chooser_t *) chobj)->choose(deflt);
  }
  else
  {
    // Get *deflt
    sizevec_t deflt;
    ref_t deflt_attr(PyW_TryGetAttrString(self, "deflt"));
    if ( deflt_attr != nullptr
      && PyList_Check(deflt_attr.o)
      && PyW_PySeqToSizeVec(&deflt, deflt_attr.o) < 0 )
    {
      deflt.clear();
    }
    res = ((chooser_multi_t *)chobj)->choose(deflt);
  }
  // assert: `this` is deleted in the case of the modal chooser

  return PyInt_FromLong(long(res));
}

//------------------------------------------------------------------------
void choose_close(PyObject *self)
{
  qstring title, errbuf;
  if ( py_chooser_props_t::get_title_from_pyobject(&title, self, &errbuf) )
    close_chooser(title.c_str());
}

//------------------------------------------------------------------------
void choose_refresh(PyObject *self)
{
  qstring title, errbuf;
  if ( py_chooser_props_t::get_title_from_pyobject(&title, self, &errbuf) )
    refresh_chooser(title.c_str());
}

//-------------------------------------------------------------------------
TWidget *choose_get_widget(PyObject *self)
{
  qstring title, errbuf;
  return py_chooser_props_t::get_title_from_pyobject(&title, self, &errbuf)
       ? find_widget(title.c_str())
       : nullptr;
}

//------------------------------------------------------------------------
void choose_activate(PyObject *self)
{
  TWidget *w = choose_get_widget(self);
  if ( w != nullptr )
    activate_widget(w, true);
}

//------------------------------------------------------------------------
// Return the C instance as 64bit number
PyObject *choose_create_embedded_chobj(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  uint64 ptr = 0;
  qstring errbuf;
  py_chooser_props_t props;
  if ( py_chooser_props_t::extract_from_pyobject(&props, self, &errbuf) )
  {
    chooser_base_t *chobj = py_chooser_mixin_t::create_concrete_instance(props, self);
    ptr = uint64(chobj);
  }
  else
  {
    PyErr_SetString(PyExc_AttributeError, errbuf.c_str());
    return nullptr;
  }
  return PyLong_FromUnsignedLongLong(ptr);
}

//------------------------------------------------------------------------
PyObject *choose_find(const char *title)
{
  PyObject *o = static_cast<PyObject*>(::get_chooser_obj(title));
  if ( o == nullptr )
    Py_RETURN_NONE;
  if ( py_chooser_mixin_t::find_by_pyobj(o) == nullptr )
    Py_RETURN_NONE;
  Py_INCREF(o);
  return o;
}
//</code(py_kernwin_choose)>

//---------------------------------------------------------------------------
//<inline(py_kernwin_choose)>

#define CHOOSER_NO_SELECTION    0x01
#define CHOOSER_MULTI_SELECTION 0x02
#define CHOOSER_POPUP_MENU      0x04

  // The following are obsolete, only present for bw-compat
#define CHOOSER_MENU_EDIT   0
#define CHOOSER_MENU_JUMP   1
#define CHOOSER_MENU_SEARCH 2

PyObject *choose_find(const char *title);
void choose_refresh(PyObject *self);
void choose_close(PyObject *self);
TWidget *choose_get_widget(PyObject *self);
PyObject *choose_choose(PyObject *self);
void choose_activate(PyObject *self);
PyObject *choose_create_embedded_chobj(PyObject *self);

PyObject *py_get_chooser_data(const char *chooser_caption, int n)
{
  qstrvec_t data;
  if ( !get_chooser_data(&data, chooser_caption, n) )
    Py_RETURN_NONE;
  ref_t py_list_ref = PyW_StrVecToPyList(data);
  py_list_ref.incref();
  return py_list_ref.o;
}

#define CH_NOIDB 0x00000040 // bw-compat

//</inline(py_kernwin_choose)>

#endif // __PY_KERNWIN_CHOOSE__
