#ifndef __PYWRAPS_CUSTVIEWER__
#define __PYWRAPS_CUSTVIEWER__
//<code(py_kernwin_custview)>
//---------------------------------------------------------------------------
class cvdata_simpleline_t
{
  strvec_t lines;
  simpleline_place_t pl_min, pl_max;

public:
  void *get_ud() { return &lines; }
  place_t *get_min() { return &pl_min; }
  place_t *get_max() { return &pl_max; }
  strvec_t &get_lines() { return lines; }

  void clear()
  {
    lines.clear();
    set_minmax();
  }

  void set_minmax(size_t start=0, size_t end=size_t(-1))
  {
    if ( start == 0 && end == size_t(-1) )
    {
      end = lines.size();
      pl_min.n = 0;
      pl_max.n = end == 0 ? 0 : end - 1;
    }
    else
    {
      pl_min.n = start;
      pl_max.n = end;
    }
  }

  bool set_line(size_t nline, simpleline_t &sl)
  {
    if ( nline >= lines.size() )
      return false;
    lines[nline] = sl;
    return true;
  }

  bool del_line(size_t nline)
  {
    if ( nline >= lines.size() )
      return false;
    lines.erase(lines.begin()+nline);
    return true;
  }

  void add_line(simpleline_t &line)
  {
    lines.push_back(line);
  }

  void add_line(const char *str)
  {
    lines.push_back(simpleline_t(str));
  }

  bool insert_line(size_t nline, simpleline_t &line)
  {
    if ( nline >= lines.size() )
      return false;
    lines.insert(lines.begin()+nline, line);
    return true;
  }

  bool patch_line(size_t nline, size_t offs, int value)
  {
    if ( nline >= lines.size() )
      return false;
    qstring &L = lines[nline].line;
    L[offs] = (uchar) value & 0xFF;
    return true;
  }

  size_t to_lineno(place_t *pl) const
  {
    return ((simpleline_place_t *)pl)->n;
  }

  simpleline_t *get_line(size_t nline)
  {
    return nline >= lines.size() ? nullptr : &lines[nline];
  }

  simpleline_t *get_line(place_t *pl)
  {
    return pl == nullptr ? nullptr : get_line(((simpleline_place_t *)pl)->n);
  }

  size_t count() const
  {
    return lines.size();
  }

  void clear_lines()
  {
    lines.clear();
    set_minmax();
  }
};

//---------------------------------------------------------------------------
// FIXME: This should inherit py_view_base.hpp's py_customidamemo_t,
// just like py_graph.hpp's py_graph_t does.
// There should be a way to "merge" the two mechanisms; they are similar.
class py_simplecustview_t
{
  qstring title;
  TWidget *widget;
  custom_viewer_handlers_t handlers;

  cvdata_simpleline_t data;
  PyObject *py_self;
  PyObject *py_this;
  PyObject *py_last_link;

  int features;

  enum
  {
    HAVE_HINT     = 0x0001,
    HAVE_KEYDOWN  = 0x0002,
    HAVE_DBLCLICK = 0x0004,
    HAVE_CURPOS   = 0x0008,
    HAVE_CLICK    = 0x0010,
    HAVE_CLOSE    = 0x0020
  };

  static bool idaapi s_cv_keydown(
        TWidget * /*cv*/,
        int vk_key,
        int shift,
        void *ud)
  {
    PYW_GIL_GET;
    py_simplecustview_t *_this = (py_simplecustview_t *)ud;
    return _this->on_keydown(vk_key, shift);
  }

  // The user clicked
  static bool idaapi s_cv_click(TWidget * /*cv*/, int shift, void *ud)
  {
    PYW_GIL_GET;
    py_simplecustview_t *_this = (py_simplecustview_t *)ud;
    return _this->on_click(shift);
  }

  // The user double clicked
  static bool idaapi s_cv_dblclick(TWidget * /*cv*/, int shift, void *ud)
  {
    PYW_GIL_GET;
    py_simplecustview_t *_this = (py_simplecustview_t *)ud;
    return _this->on_dblclick(shift);
  }

  // Cursor position has been changed
  static void idaapi s_cv_curpos(TWidget * /*cv*/, void *ud)
  {
    PYW_GIL_GET;
    py_simplecustview_t *_this = (py_simplecustview_t *)ud;
    _this->on_curpos_changed();
  }

  //--------------------------------------------------------------------------
  static ssize_t idaapi s_ui_cb(void *ud, int code, va_list va)
  {
    // This hook gets called from the kernel. Ensure we hold the GIL.
    PYW_GIL_GET;
    py_simplecustview_t *_this = (py_simplecustview_t *)ud;
    switch ( code )
    {
      case ui_get_custom_viewer_hint:
        {
          if ( (_this->features & HAVE_HINT) == 0 )
            return 0;
          qstring &hint = *va_arg(va, qstring *);
          TWidget *viewer = va_arg(va, TWidget *);
          if ( _this->widget != viewer )
            return 0;
          place_t *place = va_arg(va, place_t *);
          if ( place == nullptr )
            return 0;
          int *important_lines = va_arg(va, int *);
          return _this->on_hint(place, important_lines, hint) ? 1 : 0;
        }

      case ui_widget_invisible:
        {
          TWidget *widget = va_arg(va, TWidget *);
          if ( _this->widget != widget )
            break;
        }
        // fallthrough...
      case ui_database_closed:
        idapython_unhook_from_notification_point(HT_UI, s_ui_cb, _this);
        _this->on_close();
        _this->init_vars();
        break;
    }

    return 0;
  }

  //-------------------------------------------------------------------------
  static bool get_color(uint32 *out, ref_t obj)
  {
    bool ok = PyLong_Check(obj.o) != 0;
    if ( ok )
    {
      *out = uint32(PyLong_AsUnsignedLong(obj.o));
    }
    else
    {
      ok = PyLong_Check(obj.o) != 0;
      if ( ok )
        *out = uint32(PyLong_AsLong(obj.o));
    }
    return ok;
  }

  //--------------------------------------------------------------------------
  // Convert a tuple (String, [color, [bgcolor]]) to a simpleline_t
  static bool py_to_simpleline(PyObject *py, simpleline_t &sl)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    if ( PyUnicode_Check(py) )
    {
      PyUnicode_as_qstring(&sl.line, py);
      return true;
    }
    Py_ssize_t sz;
    if ( !PyTuple_Check(py) || (sz = PyTuple_Size(py)) <= 0 )
      return false;

    PyObject *py_val = PyTuple_GetItem(py, 0);
    if ( !PyUnicode_Check(py_val) )
      return false;

    PyUnicode_as_qstring(&sl.line, py_val);
    uint32 col;
    if ( sz > 1 && get_color(&col, borref_t(PyTuple_GetItem(py, 1))) )
      sl.color = color_t(col);
    if ( sz > 2 && get_color(&col, borref_t(PyTuple_GetItem(py, 2))) )
      sl.bgcolor = bgcolor_t(col);
    return true;
  }

  //
  // Callbacks
  //
  bool on_click(int shift)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_CLICK, "i", shift));
    PyW_ShowCbErr(S_ON_CLICK);
    return py_result != nullptr && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  // OnDblClick
  bool on_dblclick(int shift)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_DBL_CLICK, "i", shift));
    PyW_ShowCbErr(S_ON_DBL_CLICK);
    return py_result != nullptr && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  // OnCurorPositionChanged
  void on_curpos_changed()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_CURSOR_POS_CHANGED, nullptr));
    PyW_ShowCbErr(S_ON_CURSOR_POS_CHANGED);
  }

  //--------------------------------------------------------------------------
  void on_close()
  {
    if ( py_self != nullptr )
    {
      // Call the close method if it is there and the object is still bound
      if ( (features & HAVE_CLOSE) != 0 )
      {
        PYW_GIL_CHECK_LOCKED_SCOPE();
        newref_t py_result(PyObject_CallMethod(py_self, (char *)S_ON_CLOSE, nullptr));
        PyW_ShowCbErr(S_ON_CLOSE);
      }

      // Cleanup
      Py_DECREF(py_self);
      py_self = nullptr;
    }
  }

  //--------------------------------------------------------------------------
  bool on_keydown(int vk_key, int shift)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(
            PyObject_CallMethod(
                    py_self,
                    (char *)S_ON_KEYDOWN,
                    "ii",
                    vk_key,
                    shift));

    PyW_ShowCbErr(S_ON_KEYDOWN);
    return py_result && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  bool on_hint(place_t *place, int *important_lines, qstring &hint)
  {
    size_t ln = data.to_lineno(place);
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(
            PyObject_CallMethod(
                    py_self,
                    (char *)S_ON_HINT,
                    PY_BV_SZ,
                    bvsz_t(ln)));

    PyW_ShowCbErr(S_ON_HINT);
    bool ok = py_result
           && PyTuple_Check(py_result.o)
           && PyTuple_Size(py_result.o) == 2;
    if ( ok )
    {
      if ( important_lines != nullptr )
        *important_lines = PyInt_AsLong(PyTuple_GetItem(py_result.o, 0));
      PyUnicode_as_qstring(&hint, PyTuple_GetItem(py_result.o, 1));
    }
    return ok;
  }

  //--------------------------------------------------------------------------
  bool on_popup_menu(size_t menu_id)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_result(
            PyObject_CallMethod(
                    py_self,
                    (char *)S_ON_POPUP_MENU,
                    PY_BV_SZ,
                    bvsz_t(menu_id)));
    PyW_ShowCbErr(S_ON_POPUP_MENU);
    return py_result && PyObject_IsTrue(py_result.o);
  }

  //--------------------------------------------------------------------------
  void refresh_range()
  {
    data.set_minmax();
    set_range();
  }

public:
  py_simplecustview_t()
  {
    py_this = py_self = py_last_link = nullptr;
    init_vars();
  }
  ~py_simplecustview_t() {}

  TWidget *get_widget() { return widget; }

  void init_vars()
  {
    data.clear();
    features = 0;
    widget = nullptr;
  }

  void close()
  {
    if ( widget != nullptr )
      close_widget(widget, WCLS_SAVE | WCLS_CLOSE_LATER);
  }

  bool set_range(
        const place_t *minplace = nullptr,
        const place_t *maxplace = nullptr)
  {
    if ( widget == nullptr )
      return false;

    set_custom_viewer_range(
      widget,
      minplace == nullptr ? data.get_min() : minplace,
      maxplace == nullptr ? data.get_max() : maxplace);
    return true;
  }

  place_t *get_place(
    bool mouse = false,
    int *x = 0,
    int *y = 0)
  {
    return widget == nullptr ? nullptr : get_custom_viewer_place(widget, mouse, x, y);
  }

  bool refresh()
  {
    if ( widget == nullptr )
      return false;

    refresh_custom_viewer(widget);
    return true;
  }

  bool get_current_word(bool mouse, qstring &word)
  {
    // query the cursor position
    int x, y;
    if ( get_place(mouse, &x, &y) == nullptr )
      return false;

    // query the line at the cursor
    qstring qline;
    get_current_line(&qline, mouse, true);
    const char *line = qline.begin();
    if ( line == nullptr )
      return false;

    if ( x >= (int)qstrlen(line) )
      return false;

    // find the beginning of the word
    const char *ptr = line + x;
    while ( ptr > line && !qisspace(ptr[-1]) )
      ptr--;

    // find the end of the word
    const char *begin = ptr;
    ptr = line + x;
    while ( !qisspace(*ptr) && *ptr != '\0' )
      ptr++;

    word.qclear();
    word.append(begin, ptr-begin);
    return true;
  }

  void get_current_line(qstring *out, bool mouse, bool notags)
  {
    *out = get_custom_viewer_curline(widget, mouse);
    if ( notags )
      tag_remove(out);
  }

  bool is_focused()
  {
    return get_current_viewer() == widget;
  }

  bool create(const char *_title, int _features)
  {
    // Already created? (in the instance)
    if ( widget != nullptr )
      return true;

    // Already created? (in IDA windows list)
    TWidget *found = find_widget(_title);
    if ( found != nullptr )
      return false;

    title    = _title;
    features = _features;

    //
    // Prepare handlers
    //
    if ( (features & HAVE_KEYDOWN) != 0 )
      handlers.keyboard = s_cv_keydown;

    if ( (features & HAVE_CLICK) != 0 )
      handlers.click = s_cv_click;

    if ( (features & HAVE_DBLCLICK) != 0 )
      handlers.dblclick = s_cv_dblclick;

    if ( (features & HAVE_CURPOS) != 0 )
      handlers.curpos = s_cv_curpos;

    // Create the viewer
    widget = create_custom_viewer(
            title.c_str(),
            data.get_min(),
            data.get_max(),
            data.get_min(),
            (const renderer_info_t *) nullptr,
            data.get_ud(),
            &handlers,
            this);

    // Hook to UI notifications (for TWidget close event)
    idapython_hook_to_notification_point(HT_UI, s_ui_cb, this, /*is_hooks_base=*/ false);

    return true;
  }

  // Edits an existing line
  bool edit_line(size_t nline, PyObject *py_sl)
  {
    simpleline_t sl;
    if ( !py_to_simpleline(py_sl, sl) )
      return false;

    return data.set_line(nline, sl);
  }

  // Low level: patches a line string directly
  bool patch_line(size_t nline, size_t offs, int value)
  {
    return data.patch_line(nline, offs, value);
  }

  // Insert a line
  bool insert_line(size_t nline, PyObject *py_sl)
  {
    simpleline_t sl;
    if ( !py_to_simpleline(py_sl, sl) )
      return false;
    return data.insert_line(nline, sl);
  }

  // Adds a line tuple
  bool add_line(PyObject *py_sl)
  {
    simpleline_t sl;
    if ( !py_to_simpleline(py_sl, sl) )
      return false;
    data.add_line(sl);
    refresh_range();
    return true;
  }

  bool del_line(size_t nline)
  {
    bool ok = data.del_line(nline);
    if ( ok )
      refresh_range();
    return ok;
  }

  // Gets the position and returns a tuple (lineno, x, y)
  PyObject *get_pos(bool mouse)
  {
    place_t *pl;
    int x, y;
    pl = get_place(mouse, &x, &y);
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( pl == nullptr )
      Py_RETURN_NONE;
    return Py_BuildValue("(" PY_BV_SZ "ii)", bvsz_t(data.to_lineno(pl)), x, y);
  }

  // Returns the line tuple
  PyObject *get_line(size_t nline)
  {
    simpleline_t *r = data.get_line(nline);
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( r == nullptr )
      Py_RETURN_NONE;
    return Py_BuildValue("(sII)", r->line.c_str(), (unsigned int)r->color, (unsigned int)r->bgcolor);
  }

  // Returns the count of lines
  size_t count() const
  {
    return data.count();
  }

  // Clears lines
  void clear()
  {
    data.clear_lines();
    refresh_range();
  }

  bool jumpto(size_t ln, int x, int y)
  {
    simpleline_place_t l(ln);
    return ::jumpto(widget, &l, x, y);
  }

  // Initializes and links the Python object to this class
  bool init(PyObject *py_link, const char *title)
  {
    // Already created?
    if ( widget != nullptr )
      return true;

    // Probe callbacks
    int collected_features = 0;
    static struct
    {
      const char *cb_name;
      int feature;
    } const cbtable[] =
    {
      { S_ON_CLICK,              HAVE_CLICK },
      { S_ON_CLOSE,              HAVE_CLOSE },
      { S_ON_HINT,               HAVE_HINT },
      { S_ON_KEYDOWN,            HAVE_KEYDOWN },
      { S_ON_DBL_CLICK,          HAVE_DBLCLICK },
      { S_ON_CURSOR_POS_CHANGED, HAVE_CURPOS }
    };

    PYW_GIL_CHECK_LOCKED_SCOPE();
    for ( size_t i=0; i < qnumber(cbtable); i++ )
      if ( PyObject_HasAttrString(py_link, cbtable[i].cb_name) )
        collected_features |= cbtable[i].feature;

    if ( !create(title, collected_features) )
      return false;

    // Hold a reference to this object
    py_last_link = py_self = py_link;
    Py_INCREF(py_self);

    // Return a reference to the C++ instance (only once)
    if ( py_this == nullptr )
      py_this = PyCapsule_New(this, VALID_CAPSULE_NAME, nullptr);

    return true;
  }

  bool show()
  {
    if ( widget == nullptr && py_last_link != nullptr )
    {
      // Re-create the view (with same previous parameters)
      if ( !init(py_last_link, title.c_str()) )
        return false;
    }

    // Closed already?
    if ( widget == nullptr )
      return false;

    display_widget(widget, WOPN_DP_TAB|WOPN_RESTORE);
    return true;
  }

  bool get_selection(size_t *x1, size_t *y1, size_t *x2, size_t *y2)
  {
    if ( widget == nullptr )
      return false;

    twinpos_t p1, p2;
    if ( !::read_selection(widget, &p1, &p2) )
      return false;

    if ( y1 != nullptr )
      *y1 = data.to_lineno(p1.at);
    if ( y2 != nullptr )
      *y2 = data.to_lineno(p2.at);
    if ( x1 != nullptr )
      *x1 = size_t(p1.x);
    if ( x2 != nullptr )
      *x2 = p2.x;
    return true;
  }

  PyObject *py_get_selection()
  {
    size_t x1, y1, x2, y2;
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( !get_selection(&x1, &y1, &x2, &y2) )
      Py_RETURN_NONE;
    return Py_BuildValue(
            "(" PY_BV_SZ PY_BV_SZ PY_BV_SZ PY_BV_SZ ")",
            bvsz_t(x1), bvsz_t(y1), bvsz_t(x2), bvsz_t(y2));
  }

  static py_simplecustview_t *get_this(PyObject *py_this)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    return PyCapsule_IsValid(py_this, VALID_CAPSULE_NAME)
         ? (py_simplecustview_t *) PyCapsule_GetPointer(py_this, VALID_CAPSULE_NAME)
         : nullptr;
  }

  PyObject *get_pythis()
  {
    return py_this;
  }
};
//</code(py_kernwin_custview)>

//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
//---------------------------------------------------------------------------

//<inline(py_kernwin_custview)>
//
// Pywraps Simple Custom Viewer functions
//
PyObject *pyscv_init(PyObject *py_link, const char *title)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( py_link == nullptr )
    Py_RETURN_NONE;
  py_simplecustview_t *_this = new py_simplecustview_t();
  bool ok = _this->init(py_link, title);
  if ( !ok )
  {
    delete _this;
    Py_RETURN_NONE;
  }
  return _this->get_pythis();
}
#define DECL_THIS py_simplecustview_t *_this = py_simplecustview_t::get_this(py_this)

//--------------------------------------------------------------------------
bool pyscv_refresh(PyObject *py_this)
{
  DECL_THIS;
  return _this != nullptr && _this->refresh();
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_current_line(PyObject *py_this, bool mouse, bool notags)
{
  DECL_THIS;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( _this == nullptr )
    Py_RETURN_NONE;
  qstring line;
  _this->get_current_line(&line, mouse, notags);
  if ( line.empty() )
    Py_RETURN_NONE;
  return PyUnicode_FromStringAndSize(line.c_str(), line.length());
}

//--------------------------------------------------------------------------
bool pyscv_is_focused(PyObject *py_this)
{
  DECL_THIS;
  return _this != nullptr && _this->is_focused();
}

size_t pyscv_count(PyObject *py_this)
{
  DECL_THIS;
  return _this == nullptr ? 0 : _this->count();
}

bool pyscv_show(PyObject *py_this)
{
  DECL_THIS;
  return _this != nullptr && _this->show();
}

void pyscv_close(PyObject *py_this)
{
  DECL_THIS;
  if ( _this != nullptr )
    _this->close();
}

bool pyscv_jumpto(PyObject *py_this, size_t ln, int x, int y)
{
  DECL_THIS;
  return _this != nullptr && _this->jumpto(ln, x, y);
}

// Returns the line tuple
PyObject *pyscv_get_line(PyObject *py_this, size_t nline)
{
  DECL_THIS;
  if ( _this == nullptr )
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  }
  return _this->get_line(nline);
}

//--------------------------------------------------------------------------
// Gets the position and returns a tuple (lineno, x, y)
PyObject *pyscv_get_pos(PyObject *py_this, bool mouse)
{
  DECL_THIS;
  if ( _this == nullptr )
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  }
  return _this->get_pos(mouse);
}

//--------------------------------------------------------------------------
PyObject *pyscv_clear_lines(PyObject *py_this)
{
  DECL_THIS;
  if ( _this != nullptr )
    _this->clear();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_RETURN_NONE;
}

//--------------------------------------------------------------------------
// Adds a line tuple
bool pyscv_add_line(PyObject *py_this, PyObject *py_sl)
{
  DECL_THIS;
  return _this != nullptr && _this->add_line(py_sl);
}

//--------------------------------------------------------------------------
bool pyscv_insert_line(PyObject *py_this, size_t nline, PyObject *py_sl)
{
  DECL_THIS;
  return _this != nullptr && _this->insert_line(nline, py_sl);
}

//--------------------------------------------------------------------------
bool pyscv_patch_line(PyObject *py_this, size_t nline, size_t offs, int value)
{
  DECL_THIS;
  return _this != nullptr && _this->patch_line(nline, offs, value);
}

//--------------------------------------------------------------------------
bool pyscv_del_line(PyObject *py_this, size_t nline)
{
  DECL_THIS;
  return _this != nullptr && _this->del_line(nline);
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_selection(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == nullptr )
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  }
  return _this->py_get_selection();
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_current_word(PyObject *py_this, bool mouse)
{
  DECL_THIS;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( _this != nullptr )
  {
    qstring word;
    if ( _this->get_current_word(mouse, word) )
      return PyUnicode_FromString(word.c_str());
  }
  Py_RETURN_NONE;
}

//--------------------------------------------------------------------------
// Edits an existing line
bool pyscv_edit_line(PyObject *py_this, size_t nline, PyObject *py_sl)
{
  DECL_THIS;
  return _this != nullptr && _this->edit_line(nline, py_sl);
}

//-------------------------------------------------------------------------
TWidget *pyscv_get_widget(PyObject *py_this)
{
  DECL_THIS;
  return _this == nullptr ? nullptr : _this->get_widget();
}


#undef DECL_THIS
//</inline(py_kernwin_custview)>
//---------------------------------------------------------------------------
#endif // __PYWRAPS_CUSTVIEWER__
