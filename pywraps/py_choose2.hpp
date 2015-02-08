#ifndef __PY_CHOOSE2__
#define __PY_CHOOSE2__

//<code(py_kernwin)>

//------------------------------------------------------------------------
// Some defines
#define POPUP_NAMES_COUNT 4
#define MAX_CHOOSER_MENU_COMMANDS 20
#define thisobj ((py_choose2_t *) obj)
#define thisdecl py_choose2_t *_this = thisobj
#define MENU_COMMAND_CB(id) \
  static uint32 idaapi s_menu_command_##id(void *obj, uint32 n) \
  {                                                             \
    return thisobj->on_command(id, int(n));                     \
  }

//------------------------------------------------------------------------
// Helper functions
class py_choose2_t;
typedef std::map<PyObject *, py_choose2_t *> pychoose2_to_choose2_map_t;
static pychoose2_to_choose2_map_t choosers;

py_choose2_t *choose2_find_instance(PyObject *self)
{
  pychoose2_to_choose2_map_t::iterator it = choosers.find(self);
  return it == choosers.end() ? NULL : it->second;
}

void choose2_add_instance(PyObject *self, py_choose2_t *c2)
{
  choosers[self] = c2;
}

void choose2_del_instance(PyObject *self)
{
  pychoose2_to_choose2_map_t::iterator it = choosers.find(self);
  if ( it != choosers.end() )
    choosers.erase(it);
}

//------------------------------------------------------------------------
class py_choose2_t
{
private:
  enum
  {
    CHOOSE2_HAVE_DEL       = 0x0001,
    CHOOSE2_HAVE_INS       = 0x0002,
    CHOOSE2_HAVE_UPDATE    = 0x0004,
    CHOOSE2_HAVE_EDIT      = 0x0008,
    CHOOSE2_HAVE_ENTER     = 0x0010,
    CHOOSE2_HAVE_GETICON   = 0x0020,
    CHOOSE2_HAVE_GETATTR   = 0x0040,
    CHOOSE2_HAVE_COMMAND   = 0x0080,
    CHOOSE2_HAVE_ONCLOSE   = 0x0100,
    CHOOSE2_HAVE_SELECT    = 0x0200,
    CHOOSE2_HAVE_REFRESHED = 0x0400,
  };
  // Chooser flags
  int flags;

  // Callback flags (to tell which callback exists and which not)
  // One of CHOOSE2_HAVE_xxxx
  unsigned int cb_flags;
  chooser_info_t *embedded;
  intvec_t embedded_sel;

  // Menu callback index (in the menu_cbs array)
  int menu_cb_idx;

  // Chooser title
  qstring title;

  // Column widths
  intvec_t widths;

  // Python object link
  PyObject *self;
  // Chooser columns
  qstrvec_t cols;
  const char **popup_names;
  bool ui_cb_hooked;

  // The number of declarations should follow the MAX_CHOOSER_MENU_COMMANDS value
  MENU_COMMAND_CB(0)   MENU_COMMAND_CB(1)
  MENU_COMMAND_CB(2)   MENU_COMMAND_CB(3)
  MENU_COMMAND_CB(4)   MENU_COMMAND_CB(5)
  MENU_COMMAND_CB(6)   MENU_COMMAND_CB(7)
  MENU_COMMAND_CB(8)   MENU_COMMAND_CB(9)
  MENU_COMMAND_CB(10)  MENU_COMMAND_CB(11)
  MENU_COMMAND_CB(12)  MENU_COMMAND_CB(13)
  MENU_COMMAND_CB(14)  MENU_COMMAND_CB(15)
  MENU_COMMAND_CB(16)  MENU_COMMAND_CB(17)
  MENU_COMMAND_CB(18)  MENU_COMMAND_CB(19)
  static chooser_cb_t *menu_cbs[MAX_CHOOSER_MENU_COMMANDS];

  //------------------------------------------------------------------------
  // Static methods to dispatch to member functions
  //------------------------------------------------------------------------
  static int idaapi ui_cb(void *obj, int notification_code, va_list va)
  {
    // This hook gets called from the kernel. Ensure we hold the GIL.
    PYW_GIL_GET;

    // UI callback to handle chooser items with attributes
    if ( notification_code != ui_get_chooser_item_attrs )
      return 0;

    // Pass events that belong to our chooser only
    void *chooser_obj = va_arg(va, void *);
    if ( obj != chooser_obj )
      return 0;

    int n = int(va_arg(va, uint32));
    chooser_item_attrs_t *attr = va_arg(va, chooser_item_attrs_t *);
    thisobj->on_get_line_attr(n, attr);
    return 1;
  }

  static void idaapi s_select(void *obj, const intvec_t &sel)
  {
    thisobj->on_select(sel);
  }

  static void idaapi s_refreshed(void *obj)
  {
    thisobj->on_refreshed();
  }

  static uint32 idaapi s_sizer(void *obj)
  {
    return (uint32)thisobj->on_get_size();
  }

  static void idaapi s_getl(void *obj, uint32 n, char * const *arrptr)
  {
    thisobj->on_get_line(int(n), arrptr);
  }

  static uint32 idaapi s_del(void *obj, uint32 n)
  {
    return uint32(thisobj->on_delete_line(int(n)));
  }

  static void idaapi s_ins(void *obj)
  {
    thisobj->on_insert_line();
  }

  static uint32 idaapi s_update(void *obj, uint32 n)
  {
    return uint32(thisobj->on_refresh(int(n)));
  }

  static void idaapi s_edit(void *obj, uint32 n)
  {
    thisobj->on_edit_line(int(n));
  }

  static void idaapi s_enter(void * obj, uint32 n)
  {
    thisobj->on_enter(int(n));
  }

  static int idaapi s_get_icon(void *obj, uint32 n)
  {
    return thisobj->on_get_icon(int(n));
  }

  static void idaapi s_destroy(void *obj)
  {
    thisobj->on_close();
  }

  //------------------------------------------------------------------------
  // Member functions corresponding to each chooser2() callback
  //------------------------------------------------------------------------
  void clear_popup_names()
  {
    if ( popup_names == NULL )
      return;

    for ( int i=0; i<POPUP_NAMES_COUNT; i++ )
      qfree((void *)popup_names[i]);

    delete [] popup_names;
    popup_names = NULL;
  }

  void install_hooks(bool install)
  {
    if ( install )
    {
      if ( (flags & CH_ATTRS) != 0 )
      {
        if ( !hook_to_notification_point(HT_UI, ui_cb, this) )
          flags &= ~CH_ATTRS;
        else
          ui_cb_hooked = true;
      }
    }
    else
    {
      if ( (flags & CH_ATTRS) != 0 )
      {
        unhook_from_notification_point(HT_UI, ui_cb, this);
        ui_cb_hooked = false;
      }
    }
  }

  void on_get_line(int lineno, char * const *line_arr)
  {
    // Called from s_getl, which itself can be called from the kernel. Ensure GIL
    PYW_GIL_GET;

    // Get headers?
    if ( lineno == 0 )
    {
      // Copy the pre-parsed columns
      for ( size_t i=0; i < cols.size(); i++ )
        qstrncpy(line_arr[i], cols[i].c_str(), MAXSTR);
      return;
    }

    // Clear buffer
    int ncols = int(cols.size());
    for ( int i=ncols-1; i>=0; i-- )
      line_arr[i][0] = '\0';

    // Call Python
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t list(PyObject_CallMethod(self, (char *)S_ON_GET_LINE, "i", lineno - 1));
    if ( list == NULL )
      return;

    // Go over the List returned by Python and convert to C strings
    for ( int i=ncols-1; i>=0; i-- )
    {
      borref_t item(PyList_GetItem(list.o, Py_ssize_t(i)));
      if ( item == NULL )
        continue;

      const char *str = PyString_AsString(item.o);
      if ( str != NULL )
        qstrncpy(line_arr[i], str, MAXSTR);
    }
  }

  size_t on_get_size()
  {
    PYW_GIL_GET;
    newref_t pyres(PyObject_CallMethod(self, (char *)S_ON_GET_SIZE, NULL));
    if ( pyres == NULL )
      return 0;

    return PyInt_AsLong(pyres.o);
  }

  void on_refreshed()
  {
    PYW_GIL_GET;
    newref_t pyres(PyObject_CallMethod(self, (char *)S_ON_REFRESHED, NULL));
  }

  void on_select(const intvec_t &intvec)
  {
    PYW_GIL_GET;
    ref_t py_list(PyW_IntVecToPyList(intvec));
    newref_t pyres(PyObject_CallMethod(self, (char *)S_ON_SELECT, "O", py_list.o));
  }

  void on_close()
  {
    PYW_GIL_GET;
    newref_t pyres(PyObject_CallMethod(self, (char *)S_ON_CLOSE, NULL));

    // Delete this instance if none modal and not embedded
    if ( !is_modal() && get_embedded() == NULL )
      delete this;
  }

  int on_delete_line(int lineno)
  {
    PYW_GIL_GET;
    newref_t pyres(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_DELETE_LINE,
                    "i",
                    IS_CHOOSER_EVENT(lineno) ? lineno : lineno-1));
    return pyres == NULL ? 1 : PyInt_AsLong(pyres.o);
  }

  int on_refresh(int lineno)
  {
    PYW_GIL_GET;
    newref_t pyres(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_REFRESH,
                    "i",
                    lineno - 1));
    return pyres == NULL ? lineno : PyInt_AsLong(pyres.o) + 1;
  }

  void on_insert_line()
  {
    PYW_GIL_GET;
    newref_t pyres(PyObject_CallMethod(self, (char *)S_ON_INSERT_LINE, NULL));
  }

  void on_enter(int lineno)
  {
    PYW_GIL_GET;
    newref_t pyres(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_SELECT_LINE,
                    "i",
                    lineno - 1));
  }

  void on_edit_line(int lineno)
  {
    PYW_GIL_GET;
    newref_t pyres(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_EDIT_LINE,
                    "i",
                    lineno - 1));
  }

  int on_command(int cmd_id, int lineno)
  {
    PYW_GIL_GET;
    newref_t pyres(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_COMMAND,
                    "ii",
                    lineno - 1,
                    cmd_id));
    return pyres == NULL ? lineno : PyInt_AsLong(pyres.o);
  }

  int on_get_icon(int lineno)
  {
    PYW_GIL_GET;
    newref_t pyres(
            PyObject_CallMethod(
                    self,
                    (char *)S_ON_GET_ICON,
                    "i",
                    lineno - 1));
    return PyInt_AsLong(pyres.o);
  }

  void on_get_line_attr(int lineno, chooser_item_attrs_t *attr)
  {
    PYW_GIL_GET;
    newref_t pyres(PyObject_CallMethod(self, (char *)S_ON_GET_LINE_ATTR, "i", lineno - 1));
    if ( pyres != NULL )
    {
      if ( PyList_Check(pyres.o) )
      {
        PyObject *item;
        if ( (item = PyList_GetItem(pyres.o, 0)) != NULL )
          attr->color = PyInt_AsLong(item);
        if ( (item = PyList_GetItem(pyres.o, 1)) != NULL )
          attr->flags = PyInt_AsLong(item);
      }
    }
  }

  bool split_chooser_caption(qstring *out_title, qstring *out_caption, const char *caption) const
  {
    if ( get_embedded() != NULL )
    {
      // For embedded chooser, the "caption" will be overloaded to encode
      // the AskUsingForm's title, caption and embedded chooser id
      // Title:EmbeddedChooserID:Caption

      char title_buf[MAXSTR];
      const char *ptitle;

      static const char delimiter[] = ":";
      char temp[MAXSTR];
      qstrncpy(temp, caption, sizeof(temp));

      char *ctx;
      char *p = qstrtok(temp, delimiter, &ctx);
      if ( p == NULL )
        return false;

      // Copy the title
      char title_str[MAXSTR];
      qstrncpy(title_str, p, sizeof(title_str));

      // Copy the echooser ID
      p = qstrtok(NULL, delimiter, &ctx);
      if ( p == NULL )
        return false;

      char id_str[10];
      qstrncpy(id_str, p, sizeof(id_str));

      // Form the new title of the form: "AskUsingFormTitle:EchooserId"
      qsnprintf(title_buf, sizeof(title_buf), "%s:%s", title_str, id_str);

      // Adjust the title
      *out_title = title_buf;

      // Adjust the caption
      p = qstrtok(NULL, delimiter, &ctx);
      *out_caption = caption + (p - temp);
    }
    else
    {
      *out_title = title;
      *out_caption = caption;
    }
    return true;
  }

public:
  //------------------------------------------------------------------------
  // Public methods
  //------------------------------------------------------------------------
  py_choose2_t(): flags(0), cb_flags(0),
                  embedded(NULL), menu_cb_idx(0),
                  self(NULL), popup_names(NULL), ui_cb_hooked(false)
  {
  }

  ~py_choose2_t()
  {
    // Remove from list
    choose2_del_instance(self);

    // Uninstall hooks
    install_hooks(false);

    delete embedded;
    Py_XDECREF(self);
    clear_popup_names();
  }

  static py_choose2_t *find_chooser(const char *title)
  {
    return (py_choose2_t *) get_chooser_obj(title);
  }

  void close()
  {
    // Will trigger on_close()
    close_chooser(title.c_str());
  }

  bool activate()
  {
    TForm *frm = find_tform(title.c_str());
    if ( frm == NULL )
      return false;

    switchto_tform(frm, true);
    return true;
  }

  int add_command(
          const char *_caption,
          int flags=0,
          int menu_index=-1,
          int icon=-1)
  {
    if ( menu_cb_idx >= MAX_CHOOSER_MENU_COMMANDS )
      return -1;

    qstring title, caption;
    if ( !split_chooser_caption(&title, &caption, _caption)
      || !add_chooser_command(
              title.c_str(),
              caption.c_str(),
              menu_cbs[menu_cb_idx],
              menu_index,
              icon,
              flags) )
      return -1;

    return menu_cb_idx++;
  }

  // Create a chooser.
  // If it detects the "embedded" attribute, then it will create a chooser_info_t structure
  // Otherwise the chooser window is created and displayed
  int create(PyObject *self)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    // Get flags
    ref_t flags_attr(PyW_TryGetAttrString(self, S_FLAGS));
    if ( flags_attr == NULL )
      return -1;
    flags = PyInt_Check(flags_attr.o) != 0 ? PyInt_AsLong(flags_attr.o) : 0;

    // Get the title
    if ( !PyW_GetStringAttr(self, S_TITLE, &title) )
      return -1;

    // Get columns
    ref_t cols_attr(PyW_TryGetAttrString(self, "cols"));
    if ( cols_attr == NULL )
      return -1;

    // Get col count
    int ncols = int(PyList_Size(cols_attr.o));

    // Get cols caption and widthes
    cols.qclear();
    for ( int i=0; i<ncols; i++ )
    {
      // get list item: [name, width]
      borref_t list(PyList_GetItem(cols_attr.o, i));
      borref_t v(PyList_GetItem(list.o, 0));

      // Extract string
      const char *str = v == NULL ? "" : PyString_AsString(v.o);
      cols.push_back(str);

      // Extract width
      int width;
      borref_t v2(PyList_GetItem(list.o, 1));
      // No width? Guess width from column title
      if ( v2 == NULL )
        width = strlen(str);
      else
        width = PyInt_AsLong(v2.o);
      widths.push_back(width);
    }

    // Get *deflt
    int deflt = -1;
    ref_t deflt_attr(PyW_TryGetAttrString(self, "deflt"));
    if ( deflt_attr != NULL )
      deflt = PyInt_AsLong(deflt_attr.o);

    // Get *icon
    int icon = -1;
    ref_t icon_attr(PyW_TryGetAttrString(self, "icon"));
    if ( icon_attr != NULL )
      icon = PyInt_AsLong(icon_attr.o);

    // Get *x1,y1,x2,y2
    int pts[4];
    static const char *pt_attrs[qnumber(pts)] = {"x1", "y1", "x2", "y2"};
    for ( size_t i=0; i < qnumber(pts); i++ )
    {
      ref_t pt_attr(PyW_TryGetAttrString(self, pt_attrs[i]));
      if ( pt_attr == NULL )
        pts[i] = -1;
      else
        pts[i] = PyInt_AsLong(pt_attr.o);
    }

    // Check what callbacks we have
    static const struct
    {
      const char *name;
      unsigned int have; // 0 = mandatory callback
    } callbacks[] =
    {
      {S_ON_GET_SIZE,      0},
      {S_ON_GET_LINE,      0},
      {S_ON_CLOSE,         0},
      {S_ON_EDIT_LINE,        CHOOSE2_HAVE_EDIT},
      {S_ON_INSERT_LINE,      CHOOSE2_HAVE_INS},
      {S_ON_DELETE_LINE,      CHOOSE2_HAVE_DEL},
      {S_ON_REFRESH,          CHOOSE2_HAVE_UPDATE}, // update()
      {S_ON_SELECT_LINE,      CHOOSE2_HAVE_ENTER}, // enter()
      {S_ON_COMMAND,          CHOOSE2_HAVE_COMMAND},
      {S_ON_GET_LINE_ATTR,    CHOOSE2_HAVE_GETATTR},
      {S_ON_GET_ICON,         CHOOSE2_HAVE_GETICON},
      {S_ON_SELECTION_CHANGE, CHOOSE2_HAVE_SELECT},
      {S_ON_REFRESHED,        CHOOSE2_HAVE_REFRESHED},
    };
    cb_flags = 0;
    for ( int i=0; i<qnumber(callbacks); i++ )
    {
      ref_t cb_attr(PyW_TryGetAttrString(self, callbacks[i].name));
      bool have_cb = cb_attr != NULL && PyCallable_Check(cb_attr.o) != 0;
      if ( have_cb )
      {
        cb_flags |= callbacks[i].have;
      }
      else
      {
        // Mandatory field?
        if ( callbacks[i].have == 0 )
          return -1;
      }
    }

    // Get *popup names
    // An array of 4 strings: ("Insert", "Delete", "Edit", "Refresh"
    ref_t pn_attr(PyW_TryGetAttrString(self, S_POPUP_NAMES));
    if ( (pn_attr != NULL)
      && PyList_Check(pn_attr.o)
      && PyList_Size(pn_attr.o) == POPUP_NAMES_COUNT )
    {
      popup_names = new const char *[POPUP_NAMES_COUNT];
      for ( int i=0; i<POPUP_NAMES_COUNT; i++ )
      {
        const char *str = PyString_AsString(PyList_GetItem(pn_attr.o, i));
        popup_names[i] = qstrdup(str);
      }
    }

    // Adjust flags (if needed)
    if ( (cb_flags & CHOOSE2_HAVE_GETATTR) != 0 )
      flags |= CH_ATTRS;

    // Increase object reference
    Py_INCREF(self);
    this->self = self;

    // Hook to notification point (to handle chooser item attributes)
    install_hooks(true);

    // Check if *embedded
    ref_t emb_attr(PyW_TryGetAttrString(self, S_EMBEDDED));
    if ( emb_attr != NULL && PyObject_IsTrue(emb_attr.o) == 1 )
    {
      // Create an embedded chooser structure
      embedded               = new chooser_info_t();
      embedded->obj          = this;
      embedded->cb           = sizeof(chooser_info_t);
      embedded->title        = title.c_str();
      embedded->columns      = ncols;
      embedded->deflt        = deflt;
      embedded->flags        = flags;
      embedded->width        = pts[0]; // Take x1
      embedded->height       = pts[1]; // Take y1
      embedded->icon         = icon;
      embedded->popup_names  = popup_names;
      embedded->widths       = widths.begin();
      embedded->destroyer    = s_destroy;
      embedded->getl         = s_getl;
      embedded->sizer        = s_sizer;
      embedded->del          = (cb_flags & CHOOSE2_HAVE_DEL) != 0     ? s_del      : NULL;
      embedded->edit         = (cb_flags & CHOOSE2_HAVE_EDIT) != 0    ? s_edit     : NULL;
      embedded->enter        = (cb_flags & CHOOSE2_HAVE_ENTER) != 0   ? s_enter    : NULL;
      embedded->get_icon     = (cb_flags & CHOOSE2_HAVE_GETICON) != 0 ? s_get_icon : NULL;
      embedded->ins          = (cb_flags & CHOOSE2_HAVE_INS) != 0     ? s_ins      : NULL;
      embedded->update       = (cb_flags & CHOOSE2_HAVE_UPDATE) != 0  ? s_update   : NULL;
      embedded->get_attrs    = NULL;
      // Fill callbacks that are only present in idaq
      if ( is_idaq() )
      {
        embedded->select     = (cb_flags & CHOOSE2_HAVE_SELECT)   != 0 ? s_select    : NULL;
        embedded->refresh    = (cb_flags & CHOOSE2_HAVE_REFRESHED)!= 0 ? s_refreshed : NULL;
      }
      else
      {
        embedded->select       = NULL;
        embedded->refresh      = NULL;
      }
    }

    // Create the chooser (if not embedded)
    int r;
    if ( embedded == NULL )
    {
      r = ::choose2(
        flags,
        pts[0], pts[1], pts[2], pts[3],
        this,
        ncols,
        &widths[0],
        s_sizer,
        s_getl,
        title.c_str(),
        icon,
        deflt,
        (cb_flags & CHOOSE2_HAVE_DEL)    != 0 ? s_del     : NULL,
        (cb_flags & CHOOSE2_HAVE_INS)    != 0 ? s_ins     : NULL,
        (cb_flags & CHOOSE2_HAVE_UPDATE) != 0 ? s_update  : NULL,
        (cb_flags & CHOOSE2_HAVE_EDIT)   != 0 ? s_edit    : NULL,
        (cb_flags & CHOOSE2_HAVE_ENTER)  != 0 ? s_enter   : NULL,
        s_destroy,
        popup_names,
        (cb_flags & CHOOSE2_HAVE_GETICON) != 0 ? s_get_icon : NULL);

      clear_popup_names();

      // Modal chooser return the index of the selected item
      if ( is_modal() )
        r--;
    }
    // Embedded chooser?
    else
    {
      // Return success
      r = 1;
    }

    return r;
  }

  inline PyObject *get_self()
  {
    return self;
  }

  void refresh()
  {
    refresh_chooser(title.c_str());
  }

  bool is_modal()
  {
    return (flags & CH_MODAL) != 0;
  }

  intvec_t *get_sel_vec()
  {
    return &embedded_sel;
  }

  chooser_info_t *get_embedded() const
  {
    return embedded;
  }
};

//------------------------------------------------------------------------
// Initialize the callback pointers
#define DECL_MENU_COMMAND_CB(id) s_menu_command_##id
chooser_cb_t *py_choose2_t::menu_cbs[MAX_CHOOSER_MENU_COMMANDS] =
{
  DECL_MENU_COMMAND_CB(0),  DECL_MENU_COMMAND_CB(1),
  DECL_MENU_COMMAND_CB(2),  DECL_MENU_COMMAND_CB(3),
  DECL_MENU_COMMAND_CB(4),  DECL_MENU_COMMAND_CB(5),
  DECL_MENU_COMMAND_CB(6),  DECL_MENU_COMMAND_CB(7),
  DECL_MENU_COMMAND_CB(8),  DECL_MENU_COMMAND_CB(9),
  DECL_MENU_COMMAND_CB(10), DECL_MENU_COMMAND_CB(11),
  DECL_MENU_COMMAND_CB(12), DECL_MENU_COMMAND_CB(13),
  DECL_MENU_COMMAND_CB(14), DECL_MENU_COMMAND_CB(15),
  DECL_MENU_COMMAND_CB(16), DECL_MENU_COMMAND_CB(17),
  DECL_MENU_COMMAND_CB(18), DECL_MENU_COMMAND_CB(19)
};
#undef DECL_MENU_COMMAND_CB

#undef POPUP_NAMES_COUNT
#undef MAX_CHOOSER_MENU_COMMANDS
#undef thisobj
#undef thisdecl
#undef MENU_COMMAND_CB

//------------------------------------------------------------------------
int choose2_create(PyObject *self, bool embedded)
{
  py_choose2_t *c2;

  c2 = choose2_find_instance(self);
  if ( c2 != NULL )
  {
    if ( !embedded )
      c2->activate();
    return 1;
  }

  c2 = new py_choose2_t();

  choose2_add_instance(self, c2);

  int r = c2->create(self);
  // Non embedded chooser? Return immediately
  if ( !embedded )
    return r;

  // Embedded chooser was not created?
  if ( c2->get_embedded() == NULL || r != 1 )
  {
    delete c2;
    r = 0;
  }
  return r;
}

//------------------------------------------------------------------------
void choose2_close(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if ( c2 == NULL )
    return;

  // Modal or embedded chooser?
  if ( c2->get_embedded() != NULL || c2->is_modal() )
  {
    // Then simply delete the instance
    delete c2;
  }
  else
  {
    // Close the chooser.
    // In turn this will lead to the deletion of the object
    c2->close();
  }
}

//------------------------------------------------------------------------
void choose2_refresh(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if ( c2 != NULL )
    c2->refresh();
}

//------------------------------------------------------------------------
void choose2_activate(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if ( c2 != NULL )
    c2->activate();
}

//------------------------------------------------------------------------
PyObject *choose2_get_embedded_selection(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  py_choose2_t *c2 = choose2_find_instance(self);
  chooser_info_t *embedded;

  if ( c2 == NULL || (embedded = c2->get_embedded()) == NULL )
    Py_RETURN_NONE;

  // Returned as 1-based
  intvec_t &intvec = *c2->get_sel_vec();

  // Make 0-based
  for ( intvec_t::iterator it=intvec.begin(); it != intvec.end(); ++it)
    (*it)--;

  ref_t ret(PyW_IntVecToPyList(intvec));
  ret.incref();
  return ret.o;
}

//------------------------------------------------------------------------
// Return the C instances as 64bit numbers
PyObject *choose2_get_embedded(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  py_choose2_t *c2 = choose2_find_instance(self);
  chooser_info_t *embedded;

  if ( c2 == NULL || (embedded = c2->get_embedded()) == NULL )
    Py_RETURN_NONE;
  else
    return Py_BuildValue("(KK)",
                         PY_ULONG_LONG(embedded),
                         PY_ULONG_LONG(c2->get_sel_vec()));
}

//------------------------------------------------------------------------
int choose2_add_command(
        PyObject *self,
        const char *caption,
        int flags=0,
        int menu_index=-1,
        int icon=-1)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  return c2 == NULL ? -2 : c2->add_command(caption, flags, menu_index, icon);
}

//------------------------------------------------------------------------
PyObject *choose2_find(const char *title)
{
  py_choose2_t *c2 = py_choose2_t::find_chooser(title);
  return c2 == NULL ? NULL : c2->get_self();
}
//</code(py_kernwin)>

//---------------------------------------------------------------------------
//<inline(py_kernwin)>
PyObject *choose2_find(const char *title);
int choose2_add_command(PyObject *self, const char *caption, int flags, int menu_index, int icon);
void choose2_refresh(PyObject *self);
void choose2_close(PyObject *self);
int choose2_create(PyObject *self, bool embedded);
void choose2_activate(PyObject *self);
PyObject *choose2_get_embedded(PyObject *self);
PyObject *choose2_get_embedded_selection(PyObject *self);
//</inline(py_kernwin)>

//---------------------------------------------------------------------------
// Testing functions. They belong to PyWraps and won't be copied to IDAPython
//---------------------------------------------------------------------------

static void NT_CDECL choose2_test_embedded(chooser_info_t *embedded)
{
  msg("cb=%d -> looks %valid\n",
    embedded->cb,
    embedded->cb == sizeof(chooser_info_t) ? "" : "in");
}
static size_t choose2_get_test_embedded()
{
  return (size_t)choose2_test_embedded;
}
#endif // __PY_CHOOSE2__
