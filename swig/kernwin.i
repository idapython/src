// Ignore the va_list functions
%ignore AskUsingForm_cv;
%ignore close_form;
%ignore vaskstr;
%ignore vasktext;
%ignore add_menu_item;
%rename (add_menu_item) py_add_menu_item;
%ignore del_menu_item;
%rename (del_menu_item) py_del_menu_item;
%ignore vwarning;
%ignore vinfo;
%ignore vnomem;
%ignore vmsg;
%ignore show_wait_box_v;
%ignore askbuttons_cv;
%ignore askfile_cv;
%ignore askyn_cv;
%ignore askyn_v;
// Ignore these string functions. There are trivial replacements in Python.
%ignore addblanks;
%ignore trim;
%ignore skipSpaces;
%ignore stristr;

// CLI
%ignore cli_t;
%ignore install_command_interpreter;
%rename (install_command_interpreter) py_install_command_interpreter;
%ignore remove_command_interpreter;
%rename (remove_command_interpreter) py_remove_command_interpreter;

%include "typemaps.i"

%rename (asktext) py_asktext;
%rename (str2ea)  py_str2ea;
%ignore execute_sync;
%ignore exec_request_t;
%rename (execute_sync) py_execute_sync;

// Make askaddr(), askseg(), and asklong() return a
// tuple: (result, value)
%apply unsigned long *INOUT { sval_t *value };
%rename (_asklong) asklong;
%apply unsigned long *INOUT { ea_t   *addr };
%rename (_askaddr) askaddr;
%apply unsigned long *INOUT { sel_t  *sel };
%rename (_askseg) askseg;

%inline %{
void refresh_lists(void)
{
  callui(ui_list);
}
%}

%pythoncode %{
def asklong(defval, format):
    res, val = _idaapi._asklong(defval, format)

    if res == 1:
        return val
    else:
        return None

def askaddr(defval, format):
    res, ea = _idaapi._askaddr(defval, format)

    if res == 1:
        return ea
    else:
        return None

def askseg(defval, format):
    res, sel = _idaapi._askseg(defval, format)

    if res == 1:
        return sel
    else:
        return None

%}

# This is for get_cursor()
%apply int *OUTPUT {int *x, int *y};

# This is for read_selection()
%apply unsigned long *OUTPUT { ea_t *ea1, ea_t *ea2 };

%{
//<code(py_kernwin)>

//------------------------------------------------------------------------
struct py_add_del_menu_item_ctx
{
  qstring menupath;
  PyObject *cb_data;
};

//------------------------------------------------------------------------
bool idaapi py_menu_item_callback(void *userdata)
{
  // userdata is a tuple of ( func, args )
  // func and args are borrowed references from userdata
  PyObject *func = PyTuple_GET_ITEM(userdata, 0);
  PyObject *args = PyTuple_GET_ITEM(userdata, 1);

  // call the python function
  PyObject *result = PyEval_CallObject(func, args);

  // we cannot raise an exception in the callback, just print it.
  if ( result == NULL ) 
  {
    PyErr_Print();
    return false;
  }

  bool ret = PyObject_IsTrue(result);
  Py_DECREF(result);
  return ret;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def set_dock_pos(src, dest, orient, left = 0, top = 0, right = 0, bottom = 0)
    """
    Sets the dock orientation of a window relatively to another window.

    @param src: Source docking control
    @param dest: Destination docking control
    @param orient: One of DOR_XXXX constants
    @param left, top, right, bottom: These parameter if DOR_FLOATING is used, or if you want to specify the width of docked windows
    @return: Boolean

    Example:
        set_dock_pos('Structures', 'Enums', DOR_RIGHT) <- docks the Structures window to the right of Enums window
    """
    pass
#</pydoc>
*/

//------------------------------------------------------------------------
/*
int py_execute_sync(PyObject *py_callable, int reqf)
{
  if ( !PyCallable_Check(py_callable) )
    return -1;

  struct py_exec_request_t: exec_request_t
  {
    PyObject *py_callable;
    virtual int idaapi execute(void)
    {
      PyObject *py_result = PyObject_CallFunctionObjArgs(py_callable, NULL);
      int r = py_result == NULL || !PyInt_Check(py_result) ? -1 : PyInt_AsLong(py_result);
      Py_XDECREF(py_result);
      return r;
    }
    py_exec_request_t(PyObject *pyc): py_callable(pyc) { }
  };
  py_exec_request_t req(py_callable);
  return execute_sync(req, reqf);
}
*/



//------------------------------------------------------------------------
// Some defines
#define POPUP_NAMES_COUNT 4
#define MAX_CHOOSER_MENU_COMMANDS 12
#define thisobj ((py_choose2_t *) obj)
#define thisdecl py_choose2_t *_this = thisobj
#define MENU_COMMAND_CB(id) static uint32 idaapi s_menu_command_##id(void *obj, uint32 n) { return thisobj->on_command(id, int(n)); }

//------------------------------------------------------------------------
// Helper functions
class py_choose2_t;
typedef std::map<PyObject *, py_choose2_t *> pychoose2_to_choose2_map_t;
static pychoose2_to_choose2_map_t choosers;

py_choose2_t *choose2_find_instance(PyObject *self)
{
  pychoose2_to_choose2_map_t::iterator it = choosers.find(self);
  if ( it == choosers.end() )
    return NULL;
  return it->second;
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
    CHOOSE2_HAVE_DEL =    0x0001,
    CHOOSE2_HAVE_INS =    0x0002,
    CHOOSE2_HAVE_UPDATE = 0x0004,
    CHOOSE2_HAVE_EDIT =   0x0008,
    CHOOSE2_HAVE_ENTER =  0x0010,
    CHOOSE2_HAVE_GETICON = 0x0020,
    CHOOSE2_HAVE_GETATTR = 0x0040,
    CHOOSE2_HAVE_COMMAND = 0x0080,
    CHOOSE2_HAVE_ONCLOSE = 0x0100
  };
  int flags;
  int cb_flags;
  qstring title;
  PyObject *self;
  qstrvec_t cols;
  // the number of declarations should follow the MAX_CHOOSER_MENU_COMMANDS value
  MENU_COMMAND_CB(0)   MENU_COMMAND_CB(1)
  MENU_COMMAND_CB(2)   MENU_COMMAND_CB(3)
  MENU_COMMAND_CB(4)   MENU_COMMAND_CB(5)
  MENU_COMMAND_CB(6)   MENU_COMMAND_CB(7)
  MENU_COMMAND_CB(8)   MENU_COMMAND_CB(9)
  MENU_COMMAND_CB(10)  MENU_COMMAND_CB(11)
  static chooser_cb_t *menu_cbs[MAX_CHOOSER_MENU_COMMANDS];
  int menu_cb_idx;
  //------------------------------------------------------------------------
  // Static methods to dispatch to member functions
  //------------------------------------------------------------------------
  static int idaapi ui_cb(void *obj, int notification_code, va_list va)
  {
    if ( notification_code != ui_get_chooser_item_attrs )
      return 0;
    va_arg(va, void *);
    int n = int(va_arg(va, uint32));
    chooser_item_attrs_t *attr = va_arg(va, chooser_item_attrs_t *);
    thisobj->on_get_line_attr(n, attr);
    return 1;
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
    thisobj->on_select_line(int(n));
  }
  static int idaapi s_get_icon(void *obj, uint32 n)
  {
    return thisobj->on_get_icon(int(n));
  }
  static void idaapi s_destroy(void *obj)
  {
    thisobj->on_close();
  }
private:
  //------------------------------------------------------------------------
  // Member functions corresponding to each chooser2() callback
  //------------------------------------------------------------------------
  void on_get_line(int lineno, char * const *line_arr)
  {
    if ( lineno == 0 )
    {
      for ( size_t i=0; i<cols.size(); i++ )
        qstrncpy(line_arr[i], cols[i].c_str(), MAXSTR);
      return;
    }

    // Clear buffer
    int ncols = int(cols.size());
    for ( int i=ncols-1; i>=0; i-- )
      line_arr[i][0] = '\0';

    // Call Python
    PyObject *list = PyObject_CallMethod(self, (char *)S_ON_GET_LINE, "i", lineno - 1);
    if ( list == NULL )
      return;
    for ( int i=ncols-1; i>=0; i-- )
    {
      PyObject *item = PyList_GetItem(list, Py_ssize_t(i));
      if ( item == NULL )
        continue;
      const char *str = PyString_AsString(item);
      if ( str != NULL )
        qstrncpy(line_arr[i], str, MAXSTR);
    }
    Py_DECREF(list);
  }

  size_t on_get_size()
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_GET_SIZE, NULL);
    if ( pyres == NULL )
      return 0;
    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res;
  }

  void on_close()
  {
#ifdef CH_ATTRS
    if ( (flags & CH_ATTRS) != 0 )
      unhook_from_notification_point(HT_UI, ui_cb, this);
#endif
    // Call Python
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_CLOSE, NULL);
    Py_XDECREF(pyres);
    Py_XDECREF(self);

    // Remove from list
    choose2_del_instance(self);

    // delete this instance if none modal
    if ( (flags & CH_MODAL) == 0 )
      delete this;
  }

  int on_delete_line(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_DELETE_LINE, "i", lineno - 1);
    if ( pyres == NULL )
      return lineno;
    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res + 1;
  }

  int on_refresh(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_REFRESH, "i", lineno - 1);
    if ( pyres == NULL )
      return lineno;
    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res + 1;
  }

  void on_insert_line()
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_INSERT_LINE, NULL);
    Py_XDECREF(pyres);
  }

  void on_select_line(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_SELECT_LINE, "i", lineno - 1);
    Py_XDECREF(pyres);
  }

  void on_edit_line(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_EDIT_LINE, "i", lineno - 1);
    Py_XDECREF(pyres);
  }

  int on_command(int cmd_id, int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_COMMAND, "ii", lineno - 1, cmd_id);
    if ( pyres==NULL )
      return lineno;
    size_t res = PyInt_AsLong(pyres);
    Py_XDECREF(pyres);
    return res;
  }

  int on_get_icon(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_GET_ICON, "i", lineno - 1);
    size_t res = PyInt_AsLong(pyres);
    Py_XDECREF(pyres);
    return res;
  }

  void on_get_line_attr(int lineno, chooser_item_attrs_t *attr)
  {
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_GET_LINE_ATTR, "i", lineno - 1);
    if ( pyres == NULL )
      return;

    if ( PyList_Check(pyres) )
    {
      PyObject *item;
      if ( (item = PyList_GetItem(pyres, 0)) != NULL )
        attr->color = PyInt_AsLong(item);
      if ( (item = PyList_GetItem(pyres, 1)) != NULL )
        attr->flags = PyInt_AsLong(item);
    }
    Py_XDECREF(pyres);
  }

public:
  //------------------------------------------------------------------------
  // Public methods
  //------------------------------------------------------------------------
  py_choose2_t()
  {
    flags = 0;
    cb_flags = 0;
    menu_cb_idx = 0;
    self = NULL;
  }

  static py_choose2_t *find_chooser(const char *title)
  {
    return (py_choose2_t *) get_chooser_obj(title);
  }

  void close()
  {
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

  int choose2(
    int fl,
    int ncols,
    const int *widths,
    const char *title,
    int deflt = -1,
    // An array of 4 strings: ("Insert", "Delete", "Edit", "Refresh"
    const char * const *popup_names = NULL,
    int icon = -1,
    int x1 = -1, int y1 = -1, int x2 = -1, int y2 = -1)
  {
    flags = fl;
    if ( (flags & CH_ATTRS) != 0 )
    {
      if ( !hook_to_notification_point(HT_UI, ui_cb, this) )
        flags &= ~CH_ATTRS;
    }
    this->title = title;
    return ::choose2(
      flags,
      x1, y1, x2, y2,
      this,
      ncols, widths,
      s_sizer,
      s_getl,
      title,
      icon,
      deflt,
      cb_flags & CHOOSE2_HAVE_DEL    ? s_del     : NULL,
      cb_flags & CHOOSE2_HAVE_INS    ? s_ins     : NULL,
      cb_flags & CHOOSE2_HAVE_UPDATE ? s_update  : NULL,
      cb_flags & CHOOSE2_HAVE_EDIT   ? s_edit    : NULL,
      cb_flags & CHOOSE2_HAVE_ENTER  ? s_enter   : NULL,
      s_destroy,
      popup_names,
      cb_flags & CHOOSE2_HAVE_GETICON ? s_get_icon : NULL);
  }

  int add_command(const char *caption, int flags=0, int menu_index=-1, int icon=-1)
  {
    if ( menu_cb_idx >= MAX_CHOOSER_MENU_COMMANDS )
      return -1;

    bool ret = add_chooser_command(title.c_str(), caption, menu_cbs[menu_cb_idx], menu_index, icon, flags);
    if ( !ret )
      return -1;

    return menu_cb_idx++;
  }

  int show(PyObject *self)
  {
    PyObject *attr;
    // get flags
    if ( (attr = PyW_TryGetAttrString(self, S_FLAGS)) == NULL )
      return -1;
    int flags = PyInt_Check(attr) != 0 ? PyInt_AsLong(attr) : 0;
    Py_DECREF(attr);

  qstring title;
    // get the title
    if ( !PyW_GetStringAttr(self, S_TITLE, &title) )
      return -1;

    // get columns
    if ( (attr = PyW_TryGetAttrString(self, "cols")) == NULL )
      return -1;

    // get col count
    int ncols = PyList_Size(attr);

    // get cols caption and widthes
    intvec_t widths;
    cols.qclear();
    for ( int i=0; i<ncols; i++ )
    {
      // get list item: [name, width]
      PyObject *list = PyList_GetItem(attr, i);
      PyObject *v = PyList_GetItem(list, 0);

      // Extract string
      const char *str;
      if ( v != NULL )
        str = PyString_AsString(v);
      else
        str = "";
      cols.push_back(str);

      // Extract width
      int width;
      v = PyList_GetItem(list, 1);
      if ( v == NULL )
        width = strlen(str);
      else
        width = PyInt_AsLong(v);
      widths.push_back(width);
    }
    Py_DECREF(attr);

    // get *deflt
    int deflt = -1;
    if ( (attr = PyW_TryGetAttrString(self, "deflt")) != NULL )
    {
      deflt = PyInt_AsLong(attr);
      Py_DECREF(attr);
    }

    // get *icon
    int icon = -1;
    if ( (attr = PyW_TryGetAttrString(self, "icon")) != NULL )
    {
      icon = PyInt_AsLong(attr);
      Py_DECREF(attr);
    }

    // get *x1,y1,x2,y2
    int pts[4];
    static const char *pt_attrs[qnumber(pts)] = {"x1", "y1", "x2", "y2"};
    for ( int i=0; i<qnumber(pts); i++ )
    {
      if ( (attr = PyW_TryGetAttrString(self, pt_attrs[i])) == NULL )
      {
        pts[i] = -1;
      }
      else
      {
        pts[i] = PyInt_AsLong(attr);
        Py_DECREF(attr);
      }
    }

    // check what callbacks we have
    static const struct
    {
      const char *name;
      int have;
    } callbacks[] =
    {
      {S_ON_GET_SIZE,      0}, // 0 = mandatory callback
      {S_ON_GET_LINE,      0},
      {S_ON_CLOSE,         0},
      {S_ON_EDIT_LINE,     CHOOSE2_HAVE_EDIT},
      {S_ON_INSERT_LINE,   CHOOSE2_HAVE_INS},
      {S_ON_DELETE_LINE,   CHOOSE2_HAVE_DEL},
      {S_ON_REFRESH,       CHOOSE2_HAVE_UPDATE},
      {S_ON_SELECT_LINE,   CHOOSE2_HAVE_ENTER},
      {S_ON_COMMAND,       CHOOSE2_HAVE_COMMAND},
      {S_ON_GET_LINE_ATTR, CHOOSE2_HAVE_GETATTR},
      {S_ON_GET_ICON,      CHOOSE2_HAVE_GETICON}
    };
    cb_flags = 0;
    for ( int i=0; i<qnumber(callbacks); i++ )
    {
      bool have_cb = (attr = PyW_TryGetAttrString(self, callbacks[i].name)) != NULL && PyCallable_Check(attr) != 0;
      Py_XDECREF(attr);

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

    // get *popup names
    const char **popup_names = NULL;
    if ( ((attr = PyW_TryGetAttrString(self, "popup_names")) != NULL)
      && PyList_Check(attr)
      && PyList_Size(attr) == POPUP_NAMES_COUNT )
    {
      popup_names = new const char *[POPUP_NAMES_COUNT];
      for ( int i=0; i<POPUP_NAMES_COUNT; i++ )
      {
        const char *str = PyString_AsString(PyList_GetItem(attr, i));
        popup_names[i] = qstrdup(str);
      }
    }
    Py_XDECREF(attr);

    // Adjust flags (if needed)
    if ( (cb_flags & CHOOSE2_HAVE_GETATTR) != 0 )
      flags |= CH_ATTRS;

    // Increase object reference
    Py_INCREF(self);
    this->self = self;

    // Create chooser
    int r = this->choose2(
      flags,
      ncols,
      &widths[0],
      title.c_str(),
      deflt,
      popup_names,
      icon,
      pts[0],
      pts[1],
      pts[2],
      pts[3]);

    // Clear temporary popup_names
    if ( popup_names != NULL )
    {
      for ( int i=0; i<POPUP_NAMES_COUNT; i++ )
        qfree((void *)popup_names[i]);

      delete [] popup_names;
    }

    // Modal chooser return the index of the selected item
    if ( (flags & CH_MODAL) != 0 )
      r--;

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
  DECL_MENU_COMMAND_CB(10), DECL_MENU_COMMAND_CB(11)
};
#undef DECL_MENU_COMMAND_CB

#undef POPUP_NAMES_COUNT
#undef MAX_CHOOSER_MENU_COMMANDS
#undef thisobj
#undef thisdecl
#undef MENU_COMMAND_CB

//------------------------------------------------------------------------
int choose2_show(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if ( c2 != NULL )
  {
    c2->activate();
    return 1;
  }
  c2 = new py_choose2_t();
  choose2_add_instance(self, c2);
  return c2->show(self);
}

//------------------------------------------------------------------------
void choose2_close(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if ( c2 != NULL )
    c2->close();
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
int choose2_add_command(PyObject *self, const char *caption, int flags=0, int menu_index=-1, int icon=-1)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if ( c2 != NULL )
    return c2->add_command(caption, flags, menu_index, icon);
  else
    return -2;
}

//------------------------------------------------------------------------
PyObject *choose2_find(const char *title)
{
  py_choose2_t *c2 = py_choose2_t::find_chooser(title);
  if ( c2 == NULL )
    return NULL;
  return c2->get_self();
}
//</code(py_kernwin)>

%}

#ifdef __NT__
%{
//<code(py_cli)>
//--------------------------------------------------------------------------
#define MAX_PY_CLI 12

// Callbacks table
// This structure was devised because the cli callbacks have no user-data parameter
struct py_cli_cbs_t
{
  bool (idaapi *execute_line)(const char *line);
  bool (idaapi *complete_line)(
    qstring *completion,
    const char *prefix,
    int n,
    const char *line,
    int x);
  bool (idaapi *keydown)(
    qstring *line,
    int *p_x,
    int *p_sellen,
    uint16 *vk_key,
    int shift);
};

// CLI Python wrapper class
class py_cli_t
{
private:
  //--------------------------------------------------------------------------
  cli_t cli;
  PyObject *self;
  qstring cli_sname, cli_lname, cli_hint;

  //--------------------------------------------------------------------------
  static py_cli_t *py_clis[MAX_PY_CLI];
  static const py_cli_cbs_t py_cli_cbs[MAX_PY_CLI];
  //--------------------------------------------------------------------------
#define IMPL_PY_CLI_CB(CBN) \
  static bool idaapi s_keydown##CBN(qstring *line, int *p_x, int *p_sellen, uint16 *vk_key, int shift) \
  { \
    return py_clis[CBN]->on_keydown(line, p_x, p_sellen, vk_key, shift); \
  } \
  static bool idaapi s_execute_line##CBN(const char *line) \
  { \
    return py_clis[CBN]->on_execute_line(line); \
  } \
  static bool idaapi s_complete_line##CBN(qstring *completion, const char *prefix, int n, const char *line, int x) \
  { \
    return py_clis[CBN]->on_complete_line(completion, prefix, n, line, x); \
  }

  IMPL_PY_CLI_CB(0);    IMPL_PY_CLI_CB(1);   IMPL_PY_CLI_CB(2);   IMPL_PY_CLI_CB(3);
  IMPL_PY_CLI_CB(4);    IMPL_PY_CLI_CB(5);   IMPL_PY_CLI_CB(6);   IMPL_PY_CLI_CB(7);
  IMPL_PY_CLI_CB(8);    IMPL_PY_CLI_CB(9);   IMPL_PY_CLI_CB(10);  IMPL_PY_CLI_CB(11);
#undef IMPL_PY_CLI_CB

  //--------------------------------------------------------------------------
  // callback: the user pressed Enter
  // CLI is free to execute the line immediately or ask for more lines
  // Returns: true-executed line, false-ask for more lines
  bool on_execute_line(const char *line)
  {
    PyObject *result = PyObject_CallMethod(self, (char *)S_ON_EXECUTE_LINE, "s", line);
    bool ok = result != NULL && PyObject_IsTrue(result);
    PyW_ShowErr(S_ON_EXECUTE_LINE);
    Py_XDECREF(result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // callback: a keyboard key has been pressed
  // This is a generic callback and the CLI is free to do whatever
  // it wants.
  //    line - current input line (in/out argument)
  //    p_x  - pointer to current x coordinate of the cursor (in/out)
  //    p_sellen - pointer to current selection length (usually 0)
  //    p_vk_key - pointer to virtual key code (in/out)
  //           if the key has been handled, it should be reset to 0 by CLI
  //    shift - shift state
  // Returns: true-modified input line or x coordinate or selection length
  // This callback is optional
  bool on_keydown(
    qstring *line,
    int *p_x,
    int *p_sellen,
    uint16 *vk_key,
    int shift)
  {
    PyObject *result = PyObject_CallMethod(
      self, 
      (char *)S_ON_KEYDOWN, 
      "siiHi", 
      line->c_str(), 
      *p_x,
      *p_sellen,
      *vk_key,
      shift);

    bool ok = result != NULL && PyTuple_Check(result);

    PyW_ShowErr(S_ON_KEYDOWN);

    if ( ok )
    {
      Py_ssize_t sz = PyTuple_Size(result);
      PyObject *item;
      
      if ( sz > 0 && (item = PyTuple_GetItem(result, 0)) != NULL && PyString_Check(item) )
        *line = PyString_AsString(item);
      
      if ( sz > 1 && (item = PyTuple_GetItem(result, 1)) != NULL && PyInt_Check(item) )
        *p_x = PyInt_AsLong(item);
      
      if ( sz > 2 && (item = PyTuple_GetItem(result, 2)) != NULL && PyInt_Check(item) )
        *p_sellen = PyInt_AsLong(item);

      if ( sz > 3 && (item = PyTuple_GetItem(result, 3)) != NULL && PyInt_Check(item) )
        *vk_key = PyInt_AsLong(item) & 0xffff;
    }

    Py_XDECREF(result);
    return ok;
  }

  // callback: the user pressed Tab
  // Find a completion number N for prefix PREFIX
  // LINE is given as context information. X is the index where PREFIX starts in LINE
  // New prefix should be stored in PREFIX.
  // Returns: true if generated a new completion
  // This callback is optional
  bool on_complete_line(
    qstring *completion,
    const char *prefix,
    int n,
    const char *line,
    int x)
  {
    PyObject *result = PyObject_CallMethod(self, (char *)S_ON_COMPLETE_LINE, "sisi", prefix, n, line, x);
    bool ok = result != NULL && PyString_Check(result);
    PyW_ShowErr(S_ON_COMPLETE_LINE);
    if ( ok )
      *completion = PyString_AsString(result);

    Py_XDECREF(result);
    return ok;
  }

  // Private ctor (use bind())
  py_cli_t() 
  { 
  }

public:
  //---------------------------------------------------------------------------
  static int bind(PyObject *py_obj)
  {
    int cli_idx;
    // Find an empty slot
    for ( cli_idx = 0; cli_idx < MAX_PY_CLI; ++cli_idx )
    {
      if ( py_clis[cli_idx] == NULL )
        break;
    }
    py_cli_t *py_cli = NULL;
    do 
    {
      // No free slots?
      if ( cli_idx >= MAX_PY_CLI )
        break;

      // Create a new instance
      py_cli = new py_cli_t();
      PyObject *attr;

      // Start populating the 'cli' member
      py_cli->cli.size = sizeof(cli_t);

      // Store 'flags'
      if ( (attr = PyW_TryGetAttrString(py_obj, S_FLAGS)) == NULL )
      {
        py_cli->cli.flags = 0;
      }
      else
      {
        py_cli->cli.flags = PyLong_AsLong(attr);
        Py_DECREF(attr);
      }

      // Store 'sname'
      if ( !PyW_GetStringAttr(py_obj, "sname", &py_cli->cli_sname) )
        break;
      py_cli->cli.sname = py_cli->cli_sname.c_str();

      // Store 'lname'
      if ( !PyW_GetStringAttr(py_obj, "lname", &py_cli->cli_lname) )
        break;
      py_cli->cli.lname = py_cli->cli_lname.c_str();

      // Store 'hint'
      if ( !PyW_GetStringAttr(py_obj, "hint", &py_cli->cli_hint) )
        break;
      py_cli->cli.hint = py_cli->cli_hint.c_str();

      // Store callbacks
      if ( !PyObject_HasAttrString(py_obj, S_ON_EXECUTE_LINE) )
        break;
      py_cli->cli.execute_line  = py_cli_cbs[cli_idx].execute_line;

      py_cli->cli.complete_line = PyObject_HasAttrString(py_obj, S_ON_COMPLETE_LINE) ? py_cli_cbs[cli_idx].complete_line : NULL;
      py_cli->cli.keydown       = PyObject_HasAttrString(py_obj, S_ON_KEYDOWN) ? py_cli_cbs[cli_idx].keydown : NULL;

      // install CLI
      install_command_interpreter(&py_cli->cli);

      // Take reference to this object
      py_cli->self = py_obj;
      Py_INCREF(py_obj);

      // Save the instance
      py_clis[cli_idx] = py_cli;

      return cli_idx;
    } while (false);

    delete py_cli;
    return -1;
  }

  //---------------------------------------------------------------------------
  static void unbind(int cli_idx)
  {
    // Out of bounds or not set?
    if ( cli_idx < 0 || cli_idx >= MAX_PY_CLI || py_clis[cli_idx] == NULL )
      return;

    py_cli_t *py_cli = py_clis[cli_idx];
    remove_command_interpreter(&py_cli->cli);
    
    Py_DECREF(py_cli->self);
    delete py_cli;

    py_clis[cli_idx] = NULL;

    return;
  }
};
py_cli_t *py_cli_t::py_clis[MAX_PY_CLI] = {NULL};
#define DECL_PY_CLI_CB(CBN) { s_execute_line##CBN, s_complete_line##CBN, s_keydown##CBN }
const py_cli_cbs_t py_cli_t::py_cli_cbs[MAX_PY_CLI] =
{
  DECL_PY_CLI_CB(0),   DECL_PY_CLI_CB(1),  DECL_PY_CLI_CB(2),   DECL_PY_CLI_CB(3),
  DECL_PY_CLI_CB(4),   DECL_PY_CLI_CB(5),  DECL_PY_CLI_CB(6),   DECL_PY_CLI_CB(7),
  DECL_PY_CLI_CB(8),   DECL_PY_CLI_CB(9),  DECL_PY_CLI_CB(10),  DECL_PY_CLI_CB(11)
};
#undef DECL_PY_CLI_CB
//</code(py_cli)>

//<code(py_custviewer)>
//---------------------------------------------------------------------------
// Base class for all custviewer place_t providers
class custviewer_data_t
{
public:
  virtual void    *get_ud() = 0;
  virtual place_t *get_min() = 0;
  virtual place_t *get_max() = 0;
};

//---------------------------------------------------------------------------
class cvdata_simpleline_t: public custviewer_data_t
{
private:
  strvec_t lines;
  simpleline_place_t pl_min, pl_max;
public:
  
  void *get_ud()
  {
    return &lines;
  }
  
  place_t *get_min()
  {
    return &pl_min;
  }
  
  place_t *get_max()
  {
    return &pl_max;
  }
  
  strvec_t &get_lines()
  {
    return lines;
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
  
  const size_t to_lineno(place_t *pl) const
  {
    return ((simpleline_place_t *)pl)->n;
  }
  
  bool curline(place_t *pl, size_t *n)
  {
    if ( pl == NULL )
      return false;

    *n = to_lineno(pl);
    return true;
  }
  
  simpleline_t *get_line(size_t nline)
  {
    return nline >= lines.size() ? NULL : &lines[nline];
  }
  
  simpleline_t *get_line(place_t *pl)
  {
    return pl == NULL ? NULL : get_line(((simpleline_place_t *)pl)->n);
  }
  
  const size_t count() const
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
class customviewer_t
{
protected:
  qstring _title;
  TForm *_form;
  TCustomControl *_cv;
  custviewer_data_t *_data;
  int _features;
  enum
  {
    HAVE_HINT     = 0x0001,
    HAVE_KEYDOWN  = 0x0002,
    HAVE_POPUP    = 0x0004,
    HAVE_DBLCLICK = 0x0008,
    HAVE_CURPOS   = 0x0010,
    HAVE_CLICK    = 0x0020,
    HAVE_CLOSE    = 0x0040
  };
private:
  struct cvw_popupctx_t
  {
    size_t menu_id;
    customviewer_t *cv;
    cvw_popupctx_t(): menu_id(0), cv(NULL) { }
    cvw_popupctx_t(size_t mid, customviewer_t *v): menu_id(mid), cv(v) { }
  };
  typedef std::map<unsigned int, cvw_popupctx_t> cvw_popupmap_t;
  static cvw_popupmap_t _global_popup_map;
  static size_t _global_popup_id;
  qstring _curline;
  intvec_t _installed_popups;

  static bool idaapi s_popup_cb(void *ud)
  {
    customviewer_t *_this = (customviewer_t *)ud;
    return _this->on_popup();
  }

  static bool idaapi s_popup_menu_cb(void *ud)
  {
    size_t mid = (size_t)ud;
    cvw_popupmap_t::iterator it = _global_popup_map.find(mid);
    if ( it == _global_popup_map.end() )
      return false;
    return it->second.cv->on_popup_menu(it->second.menu_id);
  }

  static bool idaapi s_cv_keydown(TCustomControl * /*cv*/, int vk_key, int shift, void *ud)
  {
    customviewer_t *_this = (customviewer_t *)ud;
    return _this->on_keydown(vk_key, shift);
  }

  // The popup menu is being constructed
  static void idaapi s_cv_popup(TCustomControl * /*cv*/, void *ud)
  {
    customviewer_t *_this = (customviewer_t *)ud;
    _this->on_popup();
  }

  // The user clicked
  static bool idaapi s_cv_click(TCustomControl *cv, int shift, void *ud)
  {
    customviewer_t *_this = (customviewer_t *)ud;
    return _this->on_click(shift);
  }

  // The user double clicked
  static bool idaapi s_cv_dblclick(TCustomControl * /*cv*/, int shift, void *ud)
  {
    customviewer_t *_this = (customviewer_t *)ud;
    return _this->on_dblclick(shift);
  }

  // Cursor position has been changed
  static void idaapi s_cv_curpos(TCustomControl * /*cv*/, void *ud)
  {
    customviewer_t *_this = (customviewer_t *)ud;
    _this->on_curpos_changed();
  }

  //--------------------------------------------------------------------------
  static int idaapi s_ui_cb(void *ud, int code, va_list va)
  {
    customviewer_t *_this = (customviewer_t *)ud;
    switch ( code )
    {
    case ui_get_custom_viewer_hint:
      {
        TCustomControl *viewer = va_arg(va, TCustomControl *);
        place_t *place         = va_arg(va, place_t *);
        int *important_lines   = va_arg(va, int *);
        qstring &hint          = *va_arg(va, qstring *);
        return ((_this->_features & HAVE_HINT) == 0 || place == NULL || _this->_cv != viewer) ? 0 : (_this->on_hint(place, important_lines, hint) ? 1 : 0);
      }

    case ui_tform_invisible:
      {
        TForm *form = va_arg(va, TForm *);
        if ( _this->_form != form )
          break;

        unhook_from_notification_point(HT_UI, s_ui_cb, _this);
        _this->on_close();
        _this->on_post_close();
      }
      break;
    }

    return 0;
  }

  void on_post_close()
  {
    init_vars();
    clear_popup_menu();
  }

public:
  //
  // All the overridable callbacks
  //

  // OnClick
  virtual bool on_click(int /*shift*/) { return false; }

  // OnDblClick
  virtual bool on_dblclick(int /*shift*/) { return false; }

  // OnCurorPositionChanged
  virtual void on_curpos_changed() { }

  // OnHostFormClose
  virtual void on_close() { }

  // OnKeyDown
  virtual bool on_keydown(int /*vk_key*/, int /*shift*/) { return false; }

  // OnPopupShow
  virtual bool on_popup() { return false; }

  // OnHint
  virtual bool on_hint(place_t * /*place*/, int * /*important_lines*/, qstring &/*hint*/) { return false; }
  // OnPopupMenuClick
  virtual bool on_popup_menu(size_t menu_id) { return false; }

  void init_vars()
  {
    _data = NULL;
    _features = 0;
    _curline.clear();
    _cv = NULL;
    _form = NULL;
  }

  customviewer_t()
  {
    init_vars();
  }

  ~customviewer_t()
  {
  }

  //--------------------------------------------------------------------------
  void close()
  {
    if ( _form != NULL )
      close_tform(_form, FORM_SAVE);
  }

  //--------------------------------------------------------------------------
  bool set_range(
    const place_t *minplace = NULL,
    const place_t *maxplace = NULL)
  {
    if ( _cv == NULL )
      return false;

    set_custom_viewer_range(
      _cv,
      minplace == NULL ? _data->get_min() : minplace,
      maxplace == NULL ? _data->get_max() : maxplace);
    return true;
  }

  place_t *get_place(
    bool mouse = false,
    int *x = 0,
    int *y = 0)
  {
    return _cv == NULL ? NULL : get_custom_viewer_place(_cv, mouse, x, y);
  }

  //--------------------------------------------------------------------------
  bool refresh()
  {
    if ( _cv == NULL )
      return false;

    refresh_custom_viewer(_cv);
    return true;
  }

  //--------------------------------------------------------------------------
  bool refresh_current()
  {
    int x, y;
    place_t *pl = get_place(false, &x, &y);
    if ( pl == NULL )
      return false;

    return jumpto(pl, x, y);
  }

  //--------------------------------------------------------------------------
  bool get_current_word(bool mouse, qstring &word)
  {
    // query the cursor position
    int x, y;
    if ( get_place(mouse, &x, &y) == NULL )
      return false;

    // query the line at the cursor
    const char *line = get_current_line(mouse, true);
    if ( line == NULL )
      return false;

    if ( x >= (int)strlen(line) )
      return false;

    // find the beginning of the word
    const char *ptr = line + x;
    while ( ptr > line && !isspace(ptr[-1]) )
      ptr--;

    // find the end of the word
    const char *begin = ptr;
    ptr = line + x;
    while ( !isspace(*ptr) && *ptr != '\0' )
      ptr++;

    word.qclear();
    word.append(begin, ptr-begin);
    return true;
  }

  //--------------------------------------------------------------------------
  const char *get_current_line(bool mouse, bool notags)
  {
    const char *r = get_custom_viewer_curline(_cv, mouse);
    if ( r == NULL || !notags )
      return r;

    size_t sz = strlen(r);
    if ( sz == 0 )
      return r;

    _curline.resize(sz + 5, '\0');
    tag_remove(r, &_curline[0], sz + 1);
    return _curline.c_str();
  }

  //--------------------------------------------------------------------------
  bool is_focused()
  {
    return get_current_viewer() == _cv;
  }

  //--------------------------------------------------------------------------
  bool jumpto(place_t *place, int x, int y)
  {
    return ::jumpto(_cv, place, x, y);
  }

  //--------------------------------------------------------------------------
  void clear_popup_menu()
  {
    if ( _cv != NULL )
      set_custom_viewer_popup_menu(_cv, NULL);

    for (intvec_t::iterator it=_installed_popups.begin(), it_end=_installed_popups.end();
         it != it_end;
         ++it)
    {
      _global_popup_map.erase(*it);
    }
    _installed_popups.clear();
  }

  //--------------------------------------------------------------------------
  size_t add_popup_menu(
    const char *title,
    const char *hotkey)
  {
    size_t menu_id = _global_popup_id + 1;

    // Overlap / already exists?
    if (_cv == NULL || // No custviewer?
        // Overlap?
        menu_id == 0 ||
        // Already exists?
        _global_popup_map.find(menu_id) != _global_popup_map.end())
    {
      return 0;
    }
    add_custom_viewer_popup_item(_cv, title, hotkey, s_popup_menu_cb, (void *)menu_id);

    // Save global association
    _global_popup_map[menu_id] = cvw_popupctx_t(menu_id, this);
    _global_popup_id = menu_id;

    // Remember what menu IDs are set with this form
    _installed_popups.push_back(menu_id);
    return menu_id;
  }

  //--------------------------------------------------------------------------
  bool create(const char *title, int features, custviewer_data_t *data)
  {
    // Already created? (in the instance)
    if ( _form != NULL )
      return true;

    // Already created? (in IDA windows list)
    HWND hwnd(NULL);
    TForm *form = create_tform(title, &hwnd);
    if ( hwnd == NULL )
      return false;

    _title    = title;
    _data     = data;
    _form     = form;
    _features = features;

    // Create the viewer
    _cv = create_custom_viewer(
      title,
      (TWinControl *)_form,
      _data->get_min(),
      _data->get_max(),
      _data->get_min(),
      0,
      _data->get_ud());

    // Set user-data
    set_custom_viewer_handler(_cv, CVH_USERDATA, (void *)this);

    //
    // Set other optional callbacks
    //
    if ( (features & HAVE_KEYDOWN) != 0 )
      set_custom_viewer_handler(_cv, CVH_KEYDOWN, (void *)s_cv_keydown);

    if ( (features & HAVE_POPUP) != 0 )
      set_custom_viewer_handler(_cv, CVH_POPUP, (void *)s_cv_popup);

    if ( (features & HAVE_DBLCLICK) != 0 )
      set_custom_viewer_handler(_cv, CVH_DBLCLICK, (void *)s_cv_dblclick);

    if ( (features & HAVE_CURPOS) != 0 )
      set_custom_viewer_handler(_cv, CVH_CURPOS, (void *)s_cv_curpos);

    if ( (features & HAVE_CLICK) != 0 )
      set_custom_viewer_handler(_cv, CVH_CLICK, (void *)s_cv_click);

    // Hook to UI notifications (for TForm close event)
    hook_to_notification_point(HT_UI, s_ui_cb, this);

    return true;
  }

  //--------------------------------------------------------------------------
  bool show()
  {
    // closed already?
    if ( _form == NULL )
      return false;

    open_tform(_form, FORM_TAB|FORM_MENU|FORM_RESTORE);
    int x, y;
    get_place(false, &x, &y);
    msg("curplace after open: %d %d\n", x, y);
    return true;
  }
};

customviewer_t::cvw_popupmap_t customviewer_t::_global_popup_map;
size_t customviewer_t::_global_popup_id = 0;
//---------------------------------------------------------------------------
class py_simplecustview_t: public customviewer_t
{
private:
  cvdata_simpleline_t data;
  PyObject *py_self, *py_this, *py_last_link;
  int features;

  //--------------------------------------------------------------------------
  // Convert a tuple (String, [color, [bgcolor]]) to a simpleline_t
  static bool py_to_simpleline(PyObject *py, simpleline_t &sl)
  {
    if ( PyString_Check(py) )
    {
      sl.line = PyString_AsString(py);
      return true;
    }
    Py_ssize_t sz;
    if ( !PyTuple_Check(py) || (sz = PyTuple_Size(py)) <= 0 )
      return false;

    PyObject *py_val = PyTuple_GetItem(py, 0);
    if ( !PyString_Check(py_val) )
      return false;
    sl.line = PyString_AsString(py_val);

    if ( (sz > 1) && (py_val = PyTuple_GetItem(py, 1)) && PyLong_Check(py_val)  )
      sl.color = color_t(PyLong_AsUnsignedLong(py_val));

    if ( (sz > 2) && (py_val = PyTuple_GetItem(py, 2)) && PyLong_Check(py_val)  )
      sl.bgcolor = PyLong_AsUnsignedLong(py_val);
    return true;
  }

  //
  // Callbacks
  //
  virtual bool on_click(int shift)
  {
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_CLICK, "i", shift);
    PyW_ShowErr(S_ON_CLICK);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnDblClick
  virtual bool on_dblclick(int shift)
  {
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_DBL_CLICK, "i", shift);
    PyW_ShowErr(S_ON_DBL_CLICK);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnCurorPositionChanged
  virtual void on_curpos_changed()
  {
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_CURSOR_POS_CHANGED, NULL);
    PyW_ShowErr(S_ON_CURSOR_POS_CHANGED);
    Py_XDECREF(py_result);
  }

  //--------------------------------------------------------------------------
  // OnHostFormClose
  virtual void on_close()
  {
    // Call the close method if it is there and the object is still bound
    if ( (features & HAVE_CLOSE) != 0 && py_self != NULL )
    {
      PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_CLOSE, NULL);
      PyW_ShowErr(S_ON_CLOSE);
      Py_XDECREF(py_result);

      // Cleanup
      Py_DECREF(py_self);
      py_self = NULL;
    }
  }

  //--------------------------------------------------------------------------
  // OnKeyDown
  virtual bool on_keydown(int vk_key, int shift)
  {
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_KEYDOWN, "ii", vk_key, shift);
    PyW_ShowErr(S_ON_KEYDOWN);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
// OnPopupShow
  virtual bool on_popup()
  {
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_POPUP, NULL);
    PyW_ShowErr(S_ON_POPUP);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnHint
  virtual bool on_hint(place_t *place, int *important_lines, qstring &hint)
  {
    size_t ln = data.to_lineno(place);
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_HINT, PY_FMT64, pyul_t(ln));
    PyW_ShowErr(S_ON_HINT);
    bool ok = py_result != NULL && PyTuple_Check(py_result) && PyTuple_Size(py_result) == 2;
    if ( ok )
    {
      // Borrow references
      PyObject *py_nlines = PyTuple_GetItem(py_result, 0);
      PyObject *py_hint   = PyTuple_GetItem(py_result, 1);

      if ( important_lines != NULL )
        *important_lines = PyInt_AsLong(py_nlines);
      hint = PyString_AsString(py_hint);
    }
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnPopupMenuClick
  virtual bool on_popup_menu(size_t menu_id)
  {
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_POPUP_MENU, PY_FMT64, pyul_t(menu_id));
    PyW_ShowErr(S_ON_POPUP_MENU);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
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
    py_this = py_self = py_last_link = NULL;
  }
  ~py_simplecustview_t()
  {
  }

  //--------------------------------------------------------------------------
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

  //--------------------------------------------------------------------------
  bool del_line(size_t nline)
  {
    bool ok = data.del_line(nline);
    if ( ok )
      refresh_range();
    return ok;
  }

  //--------------------------------------------------------------------------
  // Gets the position and returns a tuple (lineno, x, y)
  PyObject *get_pos(bool mouse)
  {
    place_t *pl;
    int x, y;
    pl = get_place(mouse, &x, &y);
    if ( pl == NULL )
      Py_RETURN_NONE;
    return Py_BuildValue("(" PY_FMT64 "ii)", pyul_t(data.to_lineno(pl)), x, y);
  }

  //--------------------------------------------------------------------------
  // Returns the line tuple
  PyObject *get_line(size_t nline)
  {
    simpleline_t *r = data.get_line(nline);
    if ( r == NULL )
      Py_RETURN_NONE;
    return Py_BuildValue("(sII)", r->line.c_str(), (unsigned int)r->color, (unsigned int)r->bgcolor);
  }

  // Returns the count of lines
  const size_t count() const
  {
    return data.count();
  }

  // Clears lines
  void clear()
  {
    data.clear_lines();
    refresh_range();
  }

  //--------------------------------------------------------------------------
  bool jumpto(size_t ln, int x, int y)
  {
    return customviewer_t::jumpto(&simpleline_place_t(ln), x, y);
  }

  //--------------------------------------------------------------------------
  // Initializes and links the Python object to this class
  bool init(PyObject *py_link, const char *title)
  {
    // Already created?
    if ( _form != NULL )
      return true;

    // Probe callbacks
    features = 0;
    static struct
    {
      const char *cb_name;
      int feature;
    } const cbtable[] =
    {
      {S_ON_CLICK,              HAVE_CLICK},
      {S_ON_CLOSE,              HAVE_CLOSE},
      {S_ON_HINT,               HAVE_HINT},
      {S_ON_KEYDOWN,            HAVE_KEYDOWN},
      {S_ON_POPUP,              HAVE_POPUP},
      {S_ON_DBL_CLICK,          HAVE_DBLCLICK},
      {S_ON_CURSOR_POS_CHANGED, HAVE_CURPOS}
    };
    for ( size_t i=0; i<qnumber(cbtable); i++ )
    {
      if ( PyObject_HasAttrString(py_link, cbtable[i].cb_name) )
        features |= cbtable[i].feature;
    }

    if ( !create(title, features, &data) )
      return false;

    // Hold a reference to this object
    py_last_link = py_self = py_link;
    Py_INCREF(py_self);

    // Return a reference to the C++ instance (only once)
    if ( py_this == NULL )
      py_this = PyCObject_FromVoidPtr(this, NULL);
    return true;
  }

  //--------------------------------------------------------------------------
  bool show()
  {
    // Form was closed, but object already linked?
    if ( _form == NULL && py_last_link != NULL )
    {
      // Re-create the view (with same previous parameters)
      if ( !init(py_last_link, _title.c_str()) )
        return false;
    }
    return customviewer_t::show();
  }

  //--------------------------------------------------------------------------
  bool get_selection(size_t *x1, size_t *y1, size_t *x2, size_t *y2)
  {
    if ( _cv == NULL )
      return false;

    twinpos_t p1, p2;
    if ( !::readsel2(_cv, &p1, &p2) )
      return false;

    if ( y1 != NULL )
      *y1 = data.to_lineno(p1.at);
    if ( y2 != NULL )
      *y2 = data.to_lineno(p2.at);
    if ( x1 != NULL )
      *x1 = size_t(p1.x);
    if ( x2 != NULL )
      *x2 = p2.x;
    return true;
  }

  PyObject *py_get_selection()
  {
    size_t x1, y1, x2, y2;
    if ( !get_selection(&x1, &y1, &x2, &y2) )
      Py_RETURN_NONE;
    return Py_BuildValue("(" PY_FMT64 PY_FMT64 PY_FMT64 PY_FMT64 ")", pyul_t(x1), pyul_t(y1), pyul_t(x2), pyul_t(y2));
  }
  static py_simplecustview_t *get_this(PyObject *py_this)
  {
    return PyCObject_Check(py_this) ? (py_simplecustview_t *) PyCObject_AsVoidPtr(py_this) : NULL;
  }

  PyObject *get_pythis()
  {
    return py_this;
  }
};

//</code(py_custviewer)>
%}
#endif

#ifdef __NT__
%inline %{
//<inline(py_cli)>
static int py_install_command_interpreter(PyObject *py_obj)
{ 
  return py_cli_t::bind(py_obj);
}

static void py_remove_command_interpreter(int cli_idx)
{ 
  py_cli_t::unbind(cli_idx);
}
//</inline(py_cli)>

//<inline(py_custviewer)>
//
// Pywraps Simple Custom Viewer functions
//
PyObject *pyscv_init(PyObject *py_link, const char *title)
{
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
  if ( _this == NULL )
    return false;
  return _this->refresh();
}

//--------------------------------------------------------------------------
bool pyscv_delete(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  _this->close();
  delete _this;
  return true;
}

//--------------------------------------------------------------------------
bool pyscv_refresh_current(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  return _this->refresh_current();
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_current_line(PyObject *py_this, bool mouse, bool notags)
{
  DECL_THIS;
  const char *line;
  if ( _this == NULL || (line = _this->get_current_line(mouse, notags)) == NULL )
    Py_RETURN_NONE;
  return PyString_FromString(line);
}

//--------------------------------------------------------------------------
bool pyscv_is_focused(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  return _this->is_focused();
}

void pyscv_clear_popup_menu(PyObject *py_this)
{
  DECL_THIS;
  if ( _this != NULL )
    _this->clear_popup_menu();
}

size_t pyscv_add_popup_menu(PyObject *py_this, const char *title, const char *hotkey)
{
  DECL_THIS;
  return _this == NULL ? 0 : _this->add_popup_menu(title, hotkey);
}

size_t pyscv_count(PyObject *py_this)
{
  DECL_THIS;
  return _this == NULL ? 0 : _this->count();
}

bool pyscv_show(PyObject *py_this)
{
  DECL_THIS;
  return _this == NULL ? false : _this->show();
}

void pyscv_close(PyObject *py_this)
{
  DECL_THIS;
  if ( _this != NULL )
    _this->close();
}

bool pyscv_jumpto(PyObject *py_this, size_t ln, int x, int y)
{
  DECL_THIS;
  if ( _this == NULL )
    return false;
  return _this->jumpto(ln, x, y);
}

// Returns the line tuple
PyObject *pyscv_get_line(PyObject *py_this, size_t nline)
{
  DECL_THIS;
  if ( _this == NULL )
    Py_RETURN_NONE;
  return _this->get_line(nline);
}

//--------------------------------------------------------------------------
// Gets the position and returns a tuple (lineno, x, y)
PyObject *pyscv_get_pos(PyObject *py_this, bool mouse)
{
  DECL_THIS;
  if ( _this == NULL )
    Py_RETURN_NONE;
  return _this->get_pos(mouse);
}

//--------------------------------------------------------------------------
PyObject *pyscv_clear_lines(PyObject *py_this)
{
  DECL_THIS;
  if ( _this != NULL )
    _this->clear();
  Py_RETURN_NONE;
}

//--------------------------------------------------------------------------
// Adds a line tuple
bool pyscv_add_line(PyObject *py_this, PyObject *py_sl)
{
  DECL_THIS;
  return _this == NULL ? false : _this->add_line(py_sl);
}

//--------------------------------------------------------------------------
bool pyscv_insert_line(PyObject *py_this, size_t nline, PyObject *py_sl)
{
  DECL_THIS;
  return _this == NULL ? false : _this->insert_line(nline, py_sl);
}

//--------------------------------------------------------------------------
bool pyscv_patch_line(PyObject *py_this, size_t nline, size_t offs, int value)
{
  DECL_THIS;
  return _this == NULL ? false : _this->patch_line(nline, offs, value);
}

//--------------------------------------------------------------------------
bool pyscv_del_line(PyObject *py_this, size_t nline)
{
  DECL_THIS;
  return _this == NULL ? false : _this->del_line(nline);
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_selection(PyObject *py_this)
{
  DECL_THIS;
  if ( _this == NULL )
    Py_RETURN_NONE;
  return _this->py_get_selection();
}

//--------------------------------------------------------------------------
PyObject *pyscv_get_current_word(PyObject *py_this, bool mouse)
{
  DECL_THIS;
  if ( _this != NULL )
  {
    qstring word;
    if ( _this->get_current_word(mouse, word) )
      return PyString_FromString(word.c_str());
  }
  Py_RETURN_NONE;
}

//--------------------------------------------------------------------------
// Edits an existing line
bool pyscv_edit_line(PyObject *py_this, size_t nline, PyObject *py_sl)
{
  DECL_THIS;
  return _this == NULL ? false : _this->edit_line(nline, py_sl);
}
#undef DECL_THIS
//</inline(py_custviewer)>
%}
#endif // __NT__

%inline %{
uint32 idaapi choose_sizer(void *self)
{
    PyObject *pyres;
    uint32 res;

    pyres = PyObject_CallMethod((PyObject *)self, "sizer", "");
    res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res;
}

char * idaapi choose_getl(void *self, uint32 n, char *buf)
{
    PyObject *pyres;
    char *res;

    pyres = PyObject_CallMethod((PyObject *)self, "getl", "l", n);

    if (!pyres)
    {
        strcpy(buf, "<Empty>");
        return buf;
    }

    res = PyString_AsString(pyres);

    if (res)
    {
        strncpy(buf, res, MAXSTR);
        res = buf;
    }
    else
    {
        strcpy(buf, "<Empty>");
        res = buf;
    }

    Py_DECREF(pyres);
    return res;
}

void idaapi choose_enter(void *self, uint32 n)
{
    PyObject_CallMethod((PyObject *)self, "enter", "l", n);
    return;
}

uint32 choose_choose(void *self,
  int flags,
  int x0,int y0,
  int x1,int y1,
  int width)
{
    PyObject *pytitle;
    const char *title;
    if ((pytitle = PyObject_GetAttrString((PyObject *)self, "title")))
    {
        title = PyString_AsString(pytitle);
    }
    else
    {
        title = "Choose";
        pytitle = NULL;
    }
    int r = choose(
        flags,
        x0, y0,
        x1, y1,
        self,
        width,
        &choose_sizer,
        &choose_getl,
        title,
        1,
        1,
        NULL, /* del */
        NULL, /* inst */
        NULL, /* update */
        NULL, /* edit */
        &choose_enter,
        NULL, /* destroy */
        NULL, /* popup_names */
        NULL  /* get_icon */
    );
    Py_XDECREF(pytitle);
    return r;
}

//<inline(py_kernwin)>
//------------------------------------------------------------------------



//------------------------------------------------------------------------
/*
#<pydoc>
def asktext(max_text, defval, prompt):
    """
    Asks for a long text

    @param max_text: Maximum text length
    @param defval: The default value
    @param prompt: The prompt value
    @return: None or the entered string
    """
    pass
#</pydoc>
*/
PyObject *py_asktext(int max_text, const char *defval, const char *prompt)
{
  if ( max_text <= 0 )
    Py_RETURN_NONE;

  char *buf = new char[max_text];
  if ( buf == NULL )
    Py_RETURN_NONE;

  PyObject *py_ret;
  if ( asktext(size_t(max_text), buf, defval, prompt) != NULL )
  {
    py_ret = PyString_FromString(buf);
  }
  else
  {
    py_ret = Py_None;
    Py_INCREF(py_ret);
  }
  delete [] buf;
  return py_ret;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def str2ea(addr):
    """
    Converts a string express to EA. The expression evaluator may be called as well.
    
    @return: BADADDR or address value
    """
    pass
#</pydoc>
*/
ea_t py_str2ea(const char *str, ea_t screenEA = BADADDR)
{
  ea_t ea;
  bool ok = str2ea(str, &ea, screenEA);
  return ok ? ea : BADADDR;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def del_menu_item(menu_ctx):
    """
    Deletes a menu item previously added with add_menu_item()
    
    @param menu_ctx: value returned by add_menu_item()
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_del_menu_item(PyObject *py_ctx)
{
  if ( !PyCObject_Check(py_ctx) )
    return false;

  py_add_del_menu_item_ctx *ctx = (py_add_del_menu_item_ctx *)PyCObject_AsVoidPtr(py_ctx);

  bool ok = del_menu_item(ctx->menupath.c_str());

  if ( ok )
  {
    Py_DECREF(ctx->cb_data);
    delete ctx;
  }

  return ok;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def add_menu_item(menupath, name, hotkey, flags, callback, args):
    """
    Adds a menu item
    
    @param menupath: path to the menu item after or before which the insertion will take place
    @param name: name of the menu item (~x~ is used to denote Alt-x hot letter)
    @param hotkey: hotkey for the menu item (may be empty)
    @param flags: one of SETMENU_... consts
    @param callback: function which gets called when the user selects the menu item.
               The function callback is of the form:
               def callback(*args):
                  pass
    @param args: tuple containing the arguments

    @return: None or a menu context (to be used by del_menu_item())
    """
    pass
#</pydoc>
*/
static PyObject *py_add_menu_item(
  const char *menupath,
  const char *name,
  const char *hotkey,
  int flags,
  PyObject *pyfunc,
  PyObject *args)
{
  bool no_args;
  
  if ( args == Py_None )
  {
    no_args = true;
    args = PyTuple_New(0);
    if ( args == NULL )
      return NULL;
  }
  else if ( !PyTuple_Check(args) )
  {
    PyErr_SetString(PyExc_TypeError, "args must be a tuple or None");
    return NULL;
  }
  else
  {
    no_args = false;
  }

  // Form a tuple holding the function to be called and its arguments
  PyObject *cb_data = Py_BuildValue("(OO)", pyfunc, args);

  // If we created an empty tuple, then we must free it
  if ( no_args )
    Py_DECREF(args);

  // Add the menu item
  bool b = add_menu_item(menupath, name, hotkey, flags, py_menu_item_callback, (void *)cb_data);
  
  if ( !b )
  {
    Py_XDECREF(cb_data);
    Py_RETURN_NONE;
  }
  // Create a context (for the delete_menu_item())
  py_add_del_menu_item_ctx *ctx = new py_add_del_menu_item_ctx();

  // Form the complete menu path
  ctx->menupath = menupath;
  ctx->menupath.append(name);
  // Save callback data
  ctx->cb_data = cb_data;

  // Return context to user
  return PyCObject_FromVoidPtr(ctx, NULL);
}

//------------------------------------------------------------------------
/*
#<pyd0c>

MFF_FAST = 0x0000
"""execute code as soon as possible
this mode is ok call ui related functions
that do not query the database."""

MFF_READ = 0x0001
"""execute code only when ida is idle and it is safe to query the database.
this mode is recommended only for code that does not modify the database.
(nb: ida may be in the middle of executing another user request, for example it may be waiting for him to enter values into a modal dialog box)"""

MFF_WRITE = 0x0002
"""execute code only when ida is idle and it is safe to modify the database. in particular, this flag will suspend execution if there is
a modal dialog box on the screen this mode can be used to call any ida api function. MFF_WRITE implies MFF_READ"""

def py_execute_sync(callable, reqf)
    """
    Converts a string express to EA. The expression evaluator may be called as well.

    @param callable: A python callable object
    @param reqf: one of MFF_ flags
    @return: BADADDR or address value
    """
    pass
#</pyd0c>
*/
//int py_execute_sync(PyObject *py_callable, int reqf);



PyObject *choose2_find(const char *title);
int choose2_add_command(PyObject *self, const char *caption, int flags, int menu_index, int icon);
void choose2_refresh(PyObject *self);
void choose2_close(PyObject *self);
int choose2_show(PyObject *self);
void choose2_activate(PyObject *self);
//</inline(py_kernwin)>
%}

%include "kernwin.hpp"
uint32 choose_choose(PyObject *self,
    int flags,
    int x0,int y0,
    int x1,int y1,
    int width);




%pythoncode %{

class Choose:
  """
  Choose - class for choose() with callbacks
  """
  def __init__(self, list, title, flags=0):
    self.list = list
    self.title = title

    self.flags = flags
    self.x0 = -1
    self.x1 = -1
    self.y0 = -1
    self.y1 = -1

    self.width = -1

    # HACK: Add a circular reference for non-modal choosers. This prevents the GC
    # from collecting the class object the callbacks need. Unfortunately this means
    # that the class will never be collected, unless refhack is set to None explicitly.
    if (flags & 1) == 0:
      self.refhack = self

  def sizer(self):
    """
    Callback: sizer - returns the length of the list
    """
    return len(self.list)

  def getl(self, n):
    """
    Callback: getl - get one item from the list
    """
    if n == 0:
       return self.title
    if n <= self.sizer():
      return str(self.list[n-1])
    else:
      return "<Empty>"

  def ins(self):
    pass

  def update(self, n):
    pass

  def edit(self, n):
    pass

  def enter(self, n):
    print "enter(%d) called" % n

  def destroy(self):
    pass

  def get_icon(self, n):
    pass

  def choose(self):
    """
    choose - Display the choose dialogue
    """
    return _idaapi.choose_choose(self, self.flags, self.x0, self.y0, self.x1, self.y1, self.width)

#<pycode(py_kernwin)>
DP_LEFT           = 0x0001
DP_TOP            = 0x0002
DP_RIGHT          = 0x0004
DP_BOTTOM         = 0x0008
DP_INSIDE         = 0x0010
# if not before, then it is after
# (use DP_INSIDE | DP_BEFORE to insert a tab before a given tab)
# this flag alone cannot be used to determine orientation
DP_BEFORE         = 0x0020
# used with combination of other flags
DP_RAW            = 0x0040
DP_FLOATING       = 0x0080



class Choose2(object):
    """
    Choose2 wrapper class.

    Some constants are defined in this class. Please refer to kernwin.hpp for more information.
    """

    CH_MODAL        = 0x01
    CH_MULTI        = 0x02
    CH_MULTI_EDIT   = 0x04
    CH_NOBTNS       = 0x08
    CH_ATTRS        = 0x10
    CH_BUILTIN_MASK = 0xF80000

    # column flags (are specified in the widths array)
    CHCOL_PLAIN  =  0x00000000
    CHCOL_PATH   =  0x00010000
    CHCOL_HEX    =  0x00020000
    CHCOL_DEC    =  0x00030000
    CHCOL_FORMAT =  0x00070000

    def __init__(self, title, cols, flags=0, popup_names=None, icon=-1, x1=-1, y1=-1, x2=-1, y2=-1, deflt=-1):
        """Constructs a chooser window.
        @param title: The chooser title
        @param cols: a list of colums; each list item is a list of two items
            example: [ ["Address", 10 | Choose2.CHCOL_HEX], ["Name", 30 | CHCOL_PLAIN] ]
        @param flags: One of CH_XXXX constants
        @param deflt: Default starting item
        @param popup_names: list of new captions to replace this list ["Insert", "Delete", "Edit", "Refresh"]
        @param icon: Icon index (the icon should exist in ida resources)
        @param x1, y1, x2, y2: The default location
        """
        self.title = title
        self.flags = flags
        self.cols = cols
        self.deflt = deflt
        self.popup_names = popup_names
        self.icon = icon
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2

    def Show(self, modal=False):
        """Activates or creates a chooser window"""
        if modal:
            self.flags |= Choose2.CH_MODAL
        else:
            self.flags &= ~Choose2.CH_MODAL
        return _idaapi.choose2_show(self)

    def Activate(self):
        """Activates a visible chooser"""
        return _idaapi.choose2_activate(self)

    def Refresh(self):
        """Causes the refresh callback to trigger"""
        return _idaapi.choose2_refresh(self)

    def Close(self):
        """Closes the chooser"""
        return _idaapi.choose2_close(self)

    def AddCommand(self, caption, flags = _idaapi.CHOOSER_POPUP_MENU, menu_index=-1,icon = -1):
        """Adds a new chooser command
        Save the returned value and later use it in the OnCommand handler

        @return: Returns a negative value on failure or the command index
        """
        return _idaapi.choose2_add_command(self, caption, flags, menu_index, icon)

    #
    # Implement these methods in the subclass:
    #
#<pydoc>
#    def OnClose(self):
#        """
#        Called when the window is being closed.
#        This callback is mandatory.
#        @return: nothing
#        """
#        pass
#
#    def OnGetLine(self, n):
#        """Called when the chooser window requires lines.
#        This callback is mandatory.
#        @return: The user should return a list with ncols elements.
#            example: a list [col1, col2, col3, ...] describing the n-th line
#        """
#        return ["col1 val", "col2 val"]
#
#    def OnGetSize(self):
#        """Returns the element count.
#        This callback is mandatory.
#        @return: Number of elements
#        """
#        return len(self.the_list)
#
#    def OnEditLine(self, n):
#        """
#        Called when an item is being edited.
#        @param n: Line number (zero based)
#        @return: Nothing
#        """
#        pass
#
#    def OnInsertLine(self):
#        """Called when 'Insert' is selected either via the hotkey or popup menu.
#        @return: Nothing
#        """
#        pass
#
#    def OnSelectLine(self, n):
#        """Called when the line selection changes"""
#        pass
#
#    def OnDeleteLine(self, n):
#        """Called when a line is about to be deleted"""
#        return self.n
#
#    def OnRefresh(self, n):
#        """Called when the 'Refresh' is selected
#        @return: Return the number of elements
#        """
#        return self.n
#
#    def OnCommand(self, n, cmd_id):
#        """Return int ; check add_chooser_command()"""
#        return 0
#
#    def OnGetIcon(self, n):
#        """Return icon number for a given item (or -1 if no icon is avail)"""
#        return -1
#
#    def OnGetLineAttr(self, n):
#        """Return list [bgcolor, flags=CHITEM_XXXX] or None; check chooser_item_attrs_t"""
#        return [0x0, CHITEM_BOLD]
#</pydoc>
#</pycode(py_kernwin)>
%}

%pythoncode %{
#<pycode(py_cli)>
class cli_t(pyidc_opaque_object_t):
    """
    cli_t wrapper class.

    This class allows you to implement your own command line interface handlers.
    """

    def __init__(self):
        self.__cli_idx = -1
        self.__clink__ = None


    def register(self, flags = 0, sname = None, lname = None, hint = None):
        """
        Registers the CLI.

        @param flags: Feature bits. No bits are defined yet, must be 0
        @param sname: Short name (displayed on the button)
        @param lname: Long name (displayed in the menu)
        @param hint:  Hint for the input line

        @return Boolean: True-Success, False-Failed
        """

        # Already registered?
        if self.__cli_idx >= 0:
            return True

        if sname is not None: self.sname = sname
        if lname is not None: self.lname = lname
        if hint is not None:  self.hint  = hint

        # Register
        self.__cli_idx = _idaapi.install_command_interpreter(self)
        return False if self.__cli_idx < 0 else True


    def unregister(self):
        """
        Unregisters the CLI (if it was registered)
        """
        if self.__cli_idx < 0:
            return False

        _idaapi.remove_command_interpreter(self.__cli_idx)
        self.__cli_idx = -1
        return True


    def __del__(self):
        self.unregister()

    #
    # Implement these methods in the subclass:
    #
#<pydoc>
#    def OnExecuteLine(self, line):
#        """
#        The user pressed Enter. The CLI is free to execute the line immediately or ask for more lines.
#
#        This callback is mandatory.
#
#        @param line: typed line(s)
#        @return Boolean: True-executed line, False-ask for more lines
#        """
#        return True
#
#    def OnKeydown(self, line, x, sellen, vkey, shift):
#        """
#        A keyboard key has been pressed
#        This is a generic callback and the CLI is free to do whatever it wants.
#
#        This callback is optional.
#
#        @param line: current input line
#        @param x: current x coordinate of the cursor
#        @param sellen: current selection length (usually 0)
#        @param vkey: virtual key code. if the key has been handled, it should be returned as zero
#        @param shift: shift state
#
#        @return:
#            None - Nothing was changed
#            tuple(line, x, sellen, vkey): if either of the input line or the x coordinate or the selection length has been modified.
#            It is possible to return a tuple with None elements to preserve old values. Example: tuple(new_line, None, None, None) or tuple(new_line)
#        """
#        return None
#
#    def OnCompleteLine(self, prefix, n, line, prefix_start):
#        """
#        The user pressed Tab. Find a completion number N for prefix PREFIX
#
#        This callback is optional.
#
#        @param prefix: Line prefix at prefix_start (string)
#        @param n: completion number (int)
#        @param line: the current line (string)
#        @param prefix_start: the index where PREFIX starts in LINE (int)
#
#        @return: None if no completion could be generated otherwise a String with the completion suggestion
#        """
#        return None
#</pydoc>

#</pycode(py_cli)>
#<pycode(py_custviewer)>
class simplecustviewer_t(object):
    """The base class for implementing simple custom viewers"""
    def __init__(self):
        self.__this = None

    def __del__(self):
        """Destructor. It also frees the associated C++ object"""
        try:
            _idaapi.pyscv_delete(self.__this)
        except:
            pass

    @staticmethod
    def __make_sl_arg(line, fgcolor=None, bgcolor=None):
        return line if (fgcolor is None and bgcolor is None) else (line, fgcolor, bgcolor)

    def Create(self, title):
        """
        Creates the custom view. This should be the first method called after instantiation

        @param title: The title of the view
        @return: Boolean whether it succeeds or fails. It may fail if a window with the same title is already open.
                 In this case better close existing windows
        """
        self.title = title
        self.__this = _idaapi.pyscv_init(self, title)
        return True if self.__this else False

    def Close(self):
        """
        Destroys the view.
        One has to call Create() afterwards.
        Show() can be called and it will call Create() internally.
        @return: Boolean
        """
        return _idaapi.pyscv_close(self.__this)

    def Show(self):
        """
        Shows an already created view. It the view was close, then it will call Create() for you
        @return: Boolean
        """
        return _idaapi.pyscv_show(self.__this)

    def Refresh(self):
        return _idaapi.pyscv_refresh(self.__this)

    def RefreshCurrent(self):
        """Refreshes the current line only"""
        return _idaapi.pyscv_refresh_current(self.__this)

    def Count(self):
        """Returns the number of lines in the view"""
        return _idaapi.pyscv_count(self.__this)

    def GetSelection(self):
        """
        Returns the selected area or None
        @return:
            - tuple(x1, y1, x2, y2)
            - None if no selection
        """
        return _idaapi.pyscv_get_selection(self.__this)

    def ClearLines(self):
        """Clears all the lines"""
        _idaapi.pyscv_clear_lines(self.__this)

    def AddLine(self, line, fgcolor=None, bgcolor=None):
        """
        Adds a colored line to the view
        @return: Boolean
        """
        return _idaapi.pyscv_add_line(self.__this, self.__make_sl_arg(line, fgcolor, bgcolor))

    def InsertLine(self, lineno, line, fgcolor=None, bgcolor=None):
        """
        Inserts a line in the given position
        @return Boolean
        """
        return _idaapi.pyscv_insert_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def EditLine(self, lineno, line, fgcolor=None, bgcolor=None):
        """
        Edits an existing line.
        @return Boolean
        """
        return _idaapi.pyscv_edit_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def PatchLine(self, lineno, offs, value):
        """Patches an existing line character at the given offset. This is a low level function. You must know what you're doing"""
        return _idaapi.pyscv_patch_line(self.__this, lineno, offs, value)

    def DelLine(self, lineno):
        """
        Deletes an existing line
        @return Boolean
        """
        return _idaapi.pyscv_del_line(self.__this, lineno)

    def GetLine(self, lineno):
        """
        Returns a line
        @param lineno: The line number
        @return:
            Returns a tuple (colored_line, fgcolor, bgcolor) or None
        """
        return _idaapi.pyscv_get_line(self.__this, lineno)

    def GetCurrentWord(self, mouse = 0):
        """
        Returns the current word
        @param mouse: Use mouse position or cursor position
        @return: None if failed or a String containing the current word at mouse or cursor
        """
        return _idaapi.pyscv_get_current_word(self.__this, mouse)

    def GetCurrentLine(self, mouse = 0, notags = 0):
        """
        Returns the current line.
        @param mouse: Current line at mouse pos
        @param notags: If True then tag_remove() will be called before returning the line
        @return: Returns the current line (colored or uncolored) or None on failure
        """
        return _idaapi.pyscv_get_current_line(self.__this, mouse, notags)

    def GetPos(self, mouse = 0):
        """
        Returns the current cursor or mouse position.
        @param mouse: return mouse position
        @return: Returns a tuple (lineno, x, y)
        """
        return _idaapi.pyscv_get_pos(self.__this, mouse)

    def GetLineNo(self, mouse = 0):
        """Calls GetPos() and returns the current line number only or None on failure"""
        r = self.GetPos(mouse)
        return None if not r else r[0]

    def Jump(self, lineno, x=0, y=0):
        return _idaapi.pyscv_jumpto(self.__this, lineno, x, y)

    def AddPopupMenu(self, title, hotkey=""):
        """
        Adds a popup menu item
        @param title: The name of the menu item
        @param hotkey: Hotkey of the item or just empty
        @return: Returns the
        """
        return _idaapi.pyscv_add_popup_menu(self.__this, title, hotkey)

    def ClearPopupMenu(self):
        """
        Clears all previously installed popup menu items.
        Use this function if you're generating menu items on the fly (in the OnPopup() callback),
        and before adding new items
        """
        _idaapi.pyscv_clear_popup_menu(self.__this)

    def IsFocused(self):
        """Returns True if the current view is the focused view"""
        return _idaapi.pyscv_is_focused(self.__this)

    # Here are all the supported events
#<pydoc>
#    def OnClick(self, shift):
#        """
#        User clicked in the view
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnClick, shift=%d" % shift
#        return True
#
#    def OnDblClick(self, shift):
#        """
#        User dbl-clicked in the view
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnDblClick, shift=%d" % shift
#        return True
#
#    def OnCursorPosChanged(self):
#        """
#        Cursor position changed.
#        @return: Nothing
#        """
#        print "OnCurposChanged"
#
#    def OnClose(self):
#        """
#        The view is closing. Use this event to cleanup.
#        @return: Nothing
#        """
#        print "OnClose"
#
#    def OnKeydown(self, vkey, shift):
#        """
#        User pressed a key
#        @param vkey: Virtual key code
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnKeydown, vk=%d shift=%d" % (vkey, shift)
#        return False
#
#    def OnPopup(self):
#        """
#        Context menu popup is about to be shown. Create items dynamically if you wish
#        @return: Boolean. True if you handled the event
#        """
#        print "OnPopup"
#
#    def OnHint(self, lineno):
#        """
#        Hint requested for the given line number.
#        @param lineno: The line number (zero based)
#        @return:
#            - tuple(number of important lines, hint string)
#            - None: if no hint available
#        """
#        return (1, "OnHint, line=%d" % lineno)
#
#    def OnPopupMenu(self, menu_id):
#        """
#        A context (or popup) menu item was executed.
#        @param menu_id: ID previously registered with add_popup_menu()
#        @return: Boolean
#        """
#        print "OnPopupMenu, menu_id=" % menu_id
#        return True
#</pydoc>
#</pycode(py_custviewer)>
%}
