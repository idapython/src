// Ignore the va_list functions
%ignore AskUsingForm_cv;
%ignore AskUsingForm_c;
%ignore close_form;
%ignore vaskstr;
%ignore load_custom_icon;
%ignore vasktext;
%ignore add_menu_item;
%rename (add_menu_item) py_add_menu_item;
%ignore del_menu_item;
%rename (del_menu_item) py_del_menu_item;
%ignore vwarning;

%ignore msg;
%rename (msg) py_msg;

%ignore warning;
%rename (warning) py_warning;

%ignore error;
%rename (error) py_error;

%ignore vinfo;
%ignore UI_Callback;
%ignore vnomem;
%ignore vmsg;
%ignore show_wait_box_v;
%ignore askbuttons_cv;
%ignore askfile_cv;
%ignore askyn_cv;
%ignore askyn_v;
%ignore add_custom_viewer_popup_item;
%ignore create_custom_viewer;
%ignore destroy_custom_viewer;
%ignore destroy_custom_viewerdestroy_custom_viewer;
%ignore get_custom_viewer_place;
%ignore set_custom_viewer_popup_menu;
%ignore set_custom_viewer_handler;
%ignore set_custom_viewer_range;
%ignore is_idaview;
%ignore refresh_custom_viewer;
%ignore set_custom_viewer_handlers;
// Ignore these string functions. There are trivial replacements in Python.
%ignore addblanks;
%ignore trim;
%ignore skipSpaces;
%ignore stristr;

%ignore get_highlighted_identifier;
%rename (get_highlighted_identifier) py_get_highlighted_identifier;

// CLI
%ignore cli_t;
%ignore install_command_interpreter;
%rename (install_command_interpreter) py_install_command_interpreter;
%ignore remove_command_interpreter;
%rename (remove_command_interpreter) py_remove_command_interpreter;

%include "typemaps.i"

%rename (asktext) py_asktext;
%rename (str2ea)  py_str2ea;
%rename (process_ui_action) py_process_ui_action;
%ignore execute_sync;
%ignore exec_request_t;


// Make askaddr(), askseg(), and asklong() return a
// tuple: (result, value)
%apply unsigned long *INOUT { sval_t *value };
%rename (_asklong) asklong;
%apply unsigned long *INOUT { ea_t   *addr };
%rename (_askaddr) askaddr;
%apply unsigned long *INOUT { sel_t  *sel };
%rename (_askseg) askseg;

%feature("director") UI_Hooks;
%inline %{
int py_msg(const char *format)
{
  return msg("%s", format);
}

void py_warning(const char *format)
{
  warning("%s", format);
}

void py_error(const char *format)
{
  error("%s", format);
}

void refresh_lists(void)
{
  callui(ui_list);
}
%}

# This is for get_cursor()
%apply int *OUTPUT {int *x, int *y};

# This is for read_selection()
%apply unsigned long *OUTPUT { ea_t *ea1, ea_t *ea2 };

%inline %{
//<inline(py_kernwin)>
//------------------------------------------------------------------------

//------------------------------------------------------------------------
/*
#<pydoc>
def get_highlighted_identifier(flags = 0):
    """
    Returns the currently highlighted identifier

    @param flags: reserved (pass 0)
    @return: None or the highlighted identifier
    """
    pass
#</pydoc>
*/
static PyObject *py_get_highlighted_identifier(int flags = 0)
{
  char buf[MAXSTR];
  bool ok = get_highlighted_identifier(buf, sizeof(buf), flags);
  if ( !ok )
    Py_RETURN_NONE;
  else
    return PyString_FromString(buf);
}

//------------------------------------------------------------------------
static int py_load_custom_icon_fn(const char *filename)
{
  return load_custom_icon(filename);
}

//------------------------------------------------------------------------
static int py_load_custom_icon_data(PyObject *data, const char *format)
{
  Py_ssize_t len;
  char *s;
  if ( PyString_AsStringAndSize(data, &s, &len) == -1 )
    return 0;
  else
    return load_custom_icon(s, len, format);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def free_custom_icon(icon_id):
    """
    Frees an icon loaded with load_custom_icon()
    """
    pass
#</pydoc>
*/

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
def process_ui_action(name, flags):
    """
    Invokes an IDA Pro UI action by name

    @param name:  action name
    @param flags: Reserved. Must be zero
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_process_ui_action(const char *name, int flags)
{
  return process_ui_action(name, flags, NULL);
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
bool idaapi py_menu_item_callback(void *userdata);
static PyObject *py_add_menu_item(
  const char *menupath,
  const char *name,
  const char *hotkey,
  int flags,
  PyObject *pyfunc,
  PyObject *args)
{
  bool no_args;

  // No slash in the menu path?
  const char *p = strrchr(menupath, '/');
  if ( p == NULL )
    Py_RETURN_NONE;

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
  ctx->menupath.append(menupath, p - menupath + 1);
  ctx->menupath.append(name);
  // Save callback data
  ctx->cb_data = cb_data;

  // Return context to user
  return PyCObject_FromVoidPtr(ctx, NULL);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def set_dock_pos(src, dest, orient, left = 0, top = 0, right = 0, bottom = 0):
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
#<pydoc>
def is_idaq():
    """
    Returns True or False depending if IDAPython is hosted by IDAQ
    """
#</pydoc>
*/

//---------------------------------------------------------------------------
// UI hooks
//---------------------------------------------------------------------------
int idaapi UI_Callback(void *ud, int notification_code, va_list va);
/*
#<pydoc>
class UI_Hooks(object):
    def hook(self):
        """
        Creates an UI hook

        @return: Boolean true on success
        """
        pass

    def unhook(self):
        """
        Removes the UI hook
        @return: Boolean true on success
        """
        pass

    def preprocess(self, name):
        """
        IDA ui is about to handle a user command

        @param name: ui command name
                     (these names can be looked up in ida[tg]ui.cfg)
        @return: 0-ok, nonzero - a plugin has handled the command
        """

    def postprocess(self):
        """
        An ida ui command has been handled

        @return: Ignored
        """

#</pydoc>
*/
class UI_Hooks
{
public:
  virtual ~UI_Hooks()
  {
  }

  bool hook()
  {
    return hook_to_notification_point(HT_UI, UI_Callback, this);
  }

  bool unhook()
  {
    return unhook_from_notification_point(HT_UI, UI_Callback, this);
  }

  virtual int preprocess(const char *name)
  {
    return 0;
  }

  virtual void postprocess()
  {
  }
};


//---------------------------------------------------------------------------
uint32 idaapi choose_sizer(void *self)
{
  PyObject *pyres;
  uint32 res;

  PYW_GIL_ENSURE;
  pyres = PyObject_CallMethod((PyObject *)self, "sizer", "");
  PYW_GIL_RELEASE;

  res = PyInt_AsLong(pyres);
  Py_DECREF(pyres);
  return res;
}

//---------------------------------------------------------------------------
char *idaapi choose_getl(void *self, uint32 n, char *buf)
{
  PYW_GIL_ENSURE;
  PyObject *pyres = PyObject_CallMethod(
    (PyObject *)self, 
    "getl", 
    "l", 
    n);
  PYW_GIL_RELEASE;

  const char *res;
  if (pyres == NULL || (res = PyString_AsString(pyres)) == NULL )
    qstrncpy(buf, "<Empty>", MAXSTR);
  else
    qstrncpy(buf, res, MAXSTR);
  
  Py_XDECREF(pyres);
  return buf;
}

//---------------------------------------------------------------------------
void idaapi choose_enter(void *self, uint32 n)
{
  PYW_GIL_ENSURE;
  Py_XDECREF(PyObject_CallMethod((PyObject *)self, "enter", "l", n));
  PYW_GIL_RELEASE;
}

//---------------------------------------------------------------------------
uint32 choose_choose(
    void *self,
    int flags,
    int x0,int y0,
    int x1,int y1,
    int width)
{
  PyObject *pytitle = PyObject_GetAttrString((PyObject *)self, "title");
  const char *title = pytitle != NULL ? PyString_AsString(pytitle) : "Choose";

  int r = choose(
    flags,
    x0, y0,
    x1, y1,
    self,
    width,
    choose_sizer,
    choose_getl,
    title,
    1,
    1,
    NULL, /* del */
    NULL, /* inst */
    NULL, /* update */
    NULL, /* edit */
    choose_enter,
    NULL, /* destroy */
    NULL, /* popup_names */
    NULL);/* get_icon */
  Py_XDECREF(pytitle);
  return r;
}


PyObject *choose2_find(const char *title);
int choose2_add_command(PyObject *self, const char *caption, int flags, int menu_index, int icon);
void choose2_refresh(PyObject *self);
void choose2_close(PyObject *self);
int choose2_create(PyObject *self, bool embedded);
void choose2_activate(PyObject *self);
PyObject *choose2_get_embedded(PyObject *self);
PyObject *choose2_get_embedded_selection(PyObject *self);


#define DECLARE_FORM_ACTIONS form_actions_t *fa = (form_actions_t *)p_fa;

//---------------------------------------------------------------------------
static bool formchgcbfa_enable_field(size_t p_fa, int fid, bool enable)
{
  DECLARE_FORM_ACTIONS;
  return fa->enable_field(fid, enable);
}

//---------------------------------------------------------------------------
static bool formchgcbfa_show_field(size_t p_fa, int fid, bool show)
{
  DECLARE_FORM_ACTIONS;
  return fa->show_field(fid, show);
}

//---------------------------------------------------------------------------
static bool formchgcbfa_move_field(
    size_t p_fa, 
    int fid, 
    int x, 
    int y, 
    int w, 
    int h)
{
  DECLARE_FORM_ACTIONS;
  return fa->move_field(fid, x, y, w, h);
}

//---------------------------------------------------------------------------
static int formchgcbfa_get_focused_field(size_t p_fa)
{
  DECLARE_FORM_ACTIONS;
  return fa->get_focused_field();
}

//---------------------------------------------------------------------------
static bool formchgcbfa_set_focused_field(size_t p_fa, int fid)
{
  DECLARE_FORM_ACTIONS;
  return fa->set_focused_field(fid);
}

//---------------------------------------------------------------------------
static void formchgcbfa_refresh_field(size_t p_fa, int fid)
{
  DECLARE_FORM_ACTIONS;
  return fa->refresh_field(fid);
}

//---------------------------------------------------------------------------
static void formchgcbfa_set_field_value(
    size_t p_fa, 
    int fid, 
    int ft,
    PyObject *py_val,
    size_t sz)
{
  DECLARE_FORM_ACTIONS;
  return fa->refresh_field(fid);
}

//---------------------------------------------------------------------------
static PyObject *formchgcbfa_get_field_value(
    size_t p_fa, 
    int fid, 
    int ft,
    size_t sz)
{
  DECLARE_FORM_ACTIONS;
  switch ( ft )
  {
    // button - uint32
  case 4:
    {
      uint32 val;
      if ( fa->get_field_value(fid, &val) )
        return PyLong_FromUnsignedLong(val);
      break;
    }
    // ushort
  case 2:
    {
      ushort val;
      if ( fa->get_field_value(fid, &val) )
        return PyLong_FromUnsignedLong(val);
      break;
    }
    // string label
  case 1:
    {
      char val[MAXSTR];
      if ( fa->get_field_value(fid, val) )
        return PyString_FromString(val);
      break;
    }
    // string input
  case 3:
    {
      qstring val;
      val.resize(sz + 1);
      if ( fa->get_field_value(fid, val.begin()) )
        return PyString_FromString(val.begin());
      break;
    }
  case 5:
    {
      intvec_t intvec;
      // Returned as 1-base
      if (fa->get_field_value(fid, &intvec))
      {
        // Make 0-based
        for ( intvec_t::iterator it=intvec.begin(); it != intvec.end(); ++it)
          (*it)--;

        return PyW_IntVecToPyList(intvec);
      }
    }
  }
  Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
static bool formchgcbfa_set_field_value(
  size_t p_fa, 
  int fid, 
  int ft,
  PyObject *py_val)
{
  DECLARE_FORM_ACTIONS;

  switch ( ft )
  {
    // button - uint32
  case 4:
    {
      uint32 val = PyLong_AsUnsignedLong(py_val);
      return fa->set_field_value(fid, &val);
    }
    // ushort
  case 2:
    {
      ushort val = PyLong_AsUnsignedLong(py_val) & 0xffff;
      return fa->set_field_value(fid, &val);
    }
    // strings
  case 3:
  case 1:
      return fa->set_field_value(fid, PyString_AsString(py_val));
    // intvec_t
  case 5:
    {
      intvec_t intvec;
      // Passed as 0-based
      PyW_PyListToIntVec(py_val, intvec);
      
      // Make 1-based
      for ( intvec_t::iterator it=intvec.begin(); it != intvec.end(); ++it)
        (*it)++;

      bool ok = fa->set_field_value(fid, &intvec);
      return ok;
    }
    // unknown
  default:
    return false;
  }
}

#undef DECLARE_FORM_ACTIONS

static size_t py_get_AskUsingForm()
{
  return (size_t)AskUsingForm_c;
}

//</inline(py_kernwin)>
%}

%{
//<code(py_kernwin)>
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
int idaapi UI_Callback(void *ud, int notification_code, va_list va)
{
  UI_Hooks *proxy = (UI_Hooks *)ud;
  int ret = 0;
  try
  {
    switch (notification_code)
    {
    case ui_preprocess:
      {
        const char *name = va_arg(va, const char *);
        return proxy->preprocess(name);
      }

    case ui_postprocess:
      proxy->postprocess();
      break;
    }
  }
  catch (Swig::DirectorException &)
  {
    msg("Exception in UI Hook function:\n");
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
}

//------------------------------------------------------------------------
bool idaapi py_menu_item_callback(void *userdata)
{
  // userdata is a tuple of ( func, args )
  // func and args are borrowed references from userdata
  PyObject *func = PyTuple_GET_ITEM(userdata, 0);
  PyObject *args = PyTuple_GET_ITEM(userdata, 1);

  // Call the python function
  PYW_GIL_ENSURE;
  PyObject *result = PyEval_CallObject(func, args);
  PYW_GIL_RELEASE;

  // We cannot raise an exception in the callback, just print it.
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
// Some defines
#define POPUP_NAMES_COUNT 4
#define MAX_CHOOSER_MENU_COMMANDS 20
#define thisobj ((py_choose2_t *) obj)
#define thisdecl py_choose2_t *_this = thisobj
#define MENU_COMMAND_CB(id) \
  static uint32 idaapi s_menu_command_##id(void *obj, uint32 n) \
  { \
    return thisobj->on_command(id, int(n)); \
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
    // UI callback to handle chooser items with attributes
    if ( notification_code != ui_get_chooser_item_attrs )
      return 0;

    va_arg(va, void *);
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
    PYW_GIL_ENSURE;
    PyObject *list = PyObject_CallMethod(self, (char *)S_ON_GET_LINE, "i", lineno - 1);
    PYW_GIL_RELEASE;
    if ( list == NULL )
      return;

    // Go over the List returned by Python and convert to C strings
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
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_GET_SIZE, NULL);
    PYW_GIL_RELEASE;
    if ( pyres == NULL )
      return 0;

    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res;
  }

  void on_refreshed()
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_REFRESHED, NULL);
    PYW_GIL_RELEASE;
    Py_XDECREF(pyres);
  }

  void on_select(const intvec_t &intvec)
  {
    PYW_GIL_ENSURE;
    PyObject *py_list = PyW_IntVecToPyList(intvec);
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_SELECT, "O", py_list);
    PYW_GIL_RELEASE;
    Py_XDECREF(pyres);
    Py_XDECREF(py_list);
  }

  void on_close()
  {
    // Call Python
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_CLOSE, NULL);
    PYW_GIL_RELEASE;
    Py_XDECREF(pyres);

    // Delete this instance if none modal and not embedded
    if ( !is_modal() && get_embedded() == NULL )
      delete this;
  }

  int on_delete_line(int lineno)
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(
        self,
        (char *)S_ON_DELETE_LINE,
        "i",
        lineno - 1);
    PYW_GIL_RELEASE;

    if ( pyres == NULL )
      return lineno;

    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res + 1;
  }

  int on_refresh(int lineno)
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(
        self,
        (char *)S_ON_REFRESH,
        "i",
        lineno - 1);
    PYW_GIL_RELEASE;
    if ( pyres == NULL )
      return lineno;

    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res + 1;
  }

  void on_insert_line()
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_INSERT_LINE, NULL);
    PYW_GIL_RELEASE;
    Py_XDECREF(pyres);
  }

  void on_enter(int lineno)
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(
        self,
        (char *)S_ON_SELECT_LINE,
        "i",
        lineno - 1);
    PYW_GIL_RELEASE;
    Py_XDECREF(pyres);
  }

  void on_edit_line(int lineno)
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(
      self,
      (char *)S_ON_EDIT_LINE,
      "i",
      lineno - 1);
    PYW_GIL_RELEASE;
    Py_XDECREF(pyres);
  }

  int on_command(int cmd_id, int lineno)
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(
          self,
          (char *)S_ON_COMMAND,
          "ii",
          lineno - 1,
          cmd_id);
    PYW_GIL_RELEASE;

    if ( pyres==NULL )
      return lineno;

    size_t res = PyInt_AsLong(pyres);
    Py_XDECREF(pyres);
    return res;
  }

  int on_get_icon(int lineno)
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(
        self,
        (char *)S_ON_GET_ICON,
        "i",
        lineno - 1);
    PYW_GIL_RELEASE;

    size_t res = PyInt_AsLong(pyres);
    Py_XDECREF(pyres);
    return res;
  }

  void on_get_line_attr(int lineno, chooser_item_attrs_t *attr)
  {
    PYW_GIL_ENSURE;
    PyObject *pyres = PyObject_CallMethod(self, (char *)S_ON_GET_LINE_ATTR, "i", lineno - 1);
    PYW_GIL_RELEASE;

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
    const char *caption,
    int flags=0,
    int menu_index=-1,
    int icon=-1)
  {
    if ( menu_cb_idx >= MAX_CHOOSER_MENU_COMMANDS )
      return -1;

    // For embedded chooser, the "caption" will be overloaded to encode
    // the AskUsingForm's title, caption and embedded chooser id
    // Title:EmbeddedChooserID:Caption
    char title_buf[MAXSTR];
    const char *ptitle;

    // Embedded chooser?
    if ( get_embedded() != NULL )
    {
      static const char delimiter[] = ":";
      char temp[MAXSTR];
      qstrncpy(temp, caption, sizeof(temp));

      char *p = strtok(temp, delimiter);
      if ( p == NULL )
        return -1;

      // Copy the title
      char title_str[MAXSTR];
      qstrncpy(title_str, p, sizeof(title_str));

      // Copy the echooser ID
      p = strtok(NULL, delimiter);
      if ( p == NULL )
        return -1;

      char id_str[10];
      qstrncpy(id_str, p, sizeof(id_str));

      // Form the new title of the form: "AskUsingFormTitle:EchooserId"
      qsnprintf(title_buf, sizeof(title_buf), "%s:%s", title_str, id_str);

      // Adjust the title
      ptitle = title_buf;
      
      // Adjust the caption
      p = strtok(NULL, delimiter);
      caption += (p - temp);
    }
    else
    {
      ptitle = title.c_str();
    }

    if ( !add_chooser_command(
      ptitle,
      caption, 
      menu_cbs[menu_cb_idx],
      menu_index,
      icon,
      flags))
    {
      return -1;
    }

    return menu_cb_idx++;
  }

  // Create a chooser.
  // If it detects the "embedded" attribute, then it will create a chooser_info_t structure
  // Otherwise the chooser window is created and displayed
  int create(PyObject *self)
  {
    PyObject *attr;

    // Get flags
    attr = PyW_TryGetAttrString(self, S_FLAGS);
    if ( attr == NULL )
      return -1;

    flags = PyInt_Check(attr) != 0 ? PyInt_AsLong(attr) : 0;
    Py_DECREF(attr);

    // Get the title
    if ( !PyW_GetStringAttr(self, S_TITLE, &title) )
      return -1;

    // Get columns
    attr = PyW_TryGetAttrString(self, "cols");
    if ( attr == NULL )
      return -1;

    // Get col count
    int ncols = int(PyList_Size(attr));

    // Get cols caption and widthes
    cols.qclear();
    for ( int i=0; i<ncols; i++ )
    {
      // get list item: [name, width]
      PyObject *list = PyList_GetItem(attr, i);
      PyObject *v = PyList_GetItem(list, 0);

      // Extract string
      const char *str = v == NULL ? "" : PyString_AsString(v);
      cols.push_back(str);

      // Extract width
      int width;
      v = PyList_GetItem(list, 1);
      // No width? Guess width from column title
      if ( v == NULL )
        width = strlen(str);
      else
        width = PyInt_AsLong(v);
      widths.push_back(width);
    }
    Py_DECREF(attr);

    // Get *deflt
    int deflt = -1;
    attr = PyW_TryGetAttrString(self, "deflt");
    if ( attr != NULL )
    {
      deflt = PyInt_AsLong(attr);
      Py_DECREF(attr);
    }

    // Get *icon
    int icon = -1;
    if ( (attr = PyW_TryGetAttrString(self, "icon")) != NULL )
    {
      icon = PyInt_AsLong(attr);
      Py_DECREF(attr);
    }

    // Get *x1,y1,x2,y2
    int pts[4];
    static const char *pt_attrs[qnumber(pts)] = {"x1", "y1", "x2", "y2"};
    for ( size_t i=0; i < qnumber(pts); i++ )
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
      attr = attr = PyW_TryGetAttrString(self, callbacks[i].name);
      bool have_cb = attr != NULL && PyCallable_Check(attr) != 0;
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

    // Get *popup names
    // An array of 4 strings: ("Insert", "Delete", "Edit", "Refresh"
    attr = PyW_TryGetAttrString(self, S_POPUP_NAMES);
    if ( (attr != NULL)
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

    // Hook to notification point (to handle chooser item attributes)
    install_hooks(true);

    // Check if *embedded
    attr = PyW_TryGetAttrString(self, S_EMBEDDED);
    if ( attr != NULL && PyObject_IsTrue(attr) == 1 )
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
    Py_XDECREF(attr);

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
  py_choose2_t *c2 = choose2_find_instance(self);
  chooser_info_t *embedded;

  if ( c2 == NULL || (embedded = c2->get_embedded()) == NULL )
    Py_RETURN_NONE;

  // Returned as 1-based
  intvec_t &intvec = *c2->get_sel_vec();

  // Make 0-based
  for ( intvec_t::iterator it=intvec.begin(); it != intvec.end(); ++it)
    (*it)--;

  return PyW_IntVecToPyList(intvec);
}

//------------------------------------------------------------------------
PyObject *choose2_get_embedded(PyObject *self)
{
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
  if ( c2 != NULL )
    return c2->add_command(caption, flags, menu_index, icon);
  else
    return -2;
}

//------------------------------------------------------------------------
PyObject *choose2_find(const char *title)
{
  py_choose2_t *c2 = py_choose2_t::find_chooser(title);
  return c2 == NULL ? NULL : c2->get_self();
}


//</code(py_kernwin)>

%}

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
    int *vk_key,
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
  static bool idaapi s_keydown##CBN(qstring *line, int *p_x, int *p_sellen, int *vk_key, int shift) \
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
    PYW_GIL_ENSURE;
    PyObject *result = PyObject_CallMethod(
        self, 
        (char *)S_ON_EXECUTE_LINE, 
        "s", 
        line);
    PYW_GIL_RELEASE;
    
    bool ok = result != NULL && PyObject_IsTrue(result);
    PyW_ShowCbErr(S_ON_EXECUTE_LINE);
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
    int *vk_key,
    int shift)
  {
    PYW_GIL_ENSURE;
    PyObject *result = PyObject_CallMethod(
      self, 
      (char *)S_ON_KEYDOWN, 
      "siiHi", 
      line->c_str(), 
      *p_x,
      *p_sellen,
      *vk_key,
      shift);
    PYW_GIL_RELEASE;

    bool ok = result != NULL && PyTuple_Check(result);

    PyW_ShowCbErr(S_ON_KEYDOWN);

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
    PYW_GIL_ENSURE;
    PyObject *result = PyObject_CallMethod(
        self, 
        (char *)S_ON_COMPLETE_LINE, 
        "sisi", 
        prefix, 
        n, 
        line, 
        x);
    PYW_GIL_RELEASE;
    
    bool ok = result != NULL && PyString_Check(result);
    PyW_ShowCbErr(S_ON_COMPLETE_LINE);
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

//<code(py_plgform)>
//---------------------------------------------------------------------------
class plgform_t
{
private:
  PyObject *py_obj;
  TForm *form;

  static int idaapi s_callback(void *ud, int notification_code, va_list va)
  {
    plgform_t *_this = (plgform_t *)ud;
    if ( notification_code == ui_tform_visible )
    {
      TForm *form = va_arg(va, TForm *);
      if ( form == _this->form )
      {
        // Qt: QWidget*
        // G: HWND
        // We wrap and pass as a CObject in the hope that a Python UI framework
        // can unwrap a CObject and get the hwnd/widget back
        PYW_GIL_ENSURE;
        PyObject *py_result = PyObject_CallMethod(
          _this->py_obj,
          (char *)S_ON_CREATE, "O", 
          PyCObject_FromVoidPtr(form, NULL));
        PYW_GIL_RELEASE;
        
        PyW_ShowCbErr(S_ON_CREATE);
        Py_XDECREF(py_result);
      }
    }
    else if ( notification_code == ui_tform_invisible )
    {
      TForm *form = va_arg(va, TForm *);
      if ( form == _this->form )
      {
        PYW_GIL_ENSURE;
        PyObject *py_result = PyObject_CallMethod(
          _this->py_obj,
          (char *)S_ON_CLOSE, "O", 
          PyCObject_FromVoidPtr(form, NULL));
        PYW_GIL_RELEASE;
        
        PyW_ShowCbErr(S_ON_CLOSE);
        Py_XDECREF(py_result);

        _this->unhook();
      }
    }
    return 0;
  }

  void unhook()
  {
    unhook_from_notification_point(HT_UI, s_callback, this);
    form = NULL;
    
    // Call DECREF at last, since it may trigger __del__
    Py_XDECREF(py_obj);
  }

public:
  plgform_t(): py_obj(NULL), form(NULL)
  {
  }

  bool show(
    PyObject *obj,
    const char *caption, 
    int options)
  {
    // Already displayed?
    TForm *f = find_tform(caption);
    if ( f != NULL )
    {
      // Our form?
      if ( f == form )
      {
        // Switch to it
        switchto_tform(form, true);
        return true;
      }
      // Fail to create
      return false;
    }

    // Create a form
    form = create_tform(caption, NULL);
    if ( form == NULL )
      return false;
  
    if ( !hook_to_notification_point(HT_UI, s_callback, this) )
    {
      form = NULL;
      return false;
    }

    py_obj = obj;
    Py_INCREF(obj);

    if ( is_idaq() )
      options |= FORM_QWIDGET;

    this->form = form;
    open_tform(form, options);
    return true;
  }

  void close(int options = 0)
  {
    if ( form != NULL )
      close_tform(form, options);
  }

  static PyObject *create()
  {
    return PyCObject_FromVoidPtr(new plgform_t(), destroy);
  }
  
  static void destroy(void *obj)
  {
    delete (plgform_t *)obj;
  }
};
//</code(py_plgform)>
%}

%inline %{
//<inline(py_plgform)>
//---------------------------------------------------------------------------
#define DECL_PLGFORM plgform_t *plgform = (plgform_t *) PyCObject_AsVoidPtr(py_link);
static PyObject *plgform_new()
{
  return plgform_t::create();
}

static bool plgform_show(
  PyObject *py_link,
  PyObject *py_obj, 
  const char *caption, 
  int options = FORM_MDI|FORM_TAB|FORM_MENU|FORM_RESTORE)
{
  DECL_PLGFORM;
  return plgform->show(py_obj, caption, options);
}

static void plgform_close(
  PyObject *py_link,
  int options)
{
  DECL_PLGFORM;
  plgform->close(options);
}
#undef DECL_PLGFORM
//</inline(py_plgform)>
%}

%{
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

  static bool idaapi s_cv_keydown(
      TCustomControl * /*cv*/,
      int vk_key, 
      int shift, 
      void *ud)
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
        if ( (_this->_features & HAVE_HINT) == 0 || place == NULL || _this->_cv != viewer )
          return 0;
        else
          return _this->on_hint(place, important_lines, hint) ? 1 : 0;
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
    // Closed already?
    if ( _form == NULL )
      return false;

    open_tform(_form, FORM_TAB|FORM_MENU|FORM_RESTORE);
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
    PYW_GIL_ENSURE;
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_CLICK, "i", shift);
    PYW_GIL_RELEASE;
    PyW_ShowCbErr(S_ON_CLICK);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnDblClick
  virtual bool on_dblclick(int shift)
  {
    PYW_GIL_ENSURE;
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_DBL_CLICK, "i", shift);
    PYW_GIL_RELEASE;
    PyW_ShowCbErr(S_ON_DBL_CLICK);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnCurorPositionChanged
  virtual void on_curpos_changed()
  {
    PYW_GIL_ENSURE;
    PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_CURSOR_POS_CHANGED, NULL);
    PYW_GIL_RELEASE;
    PyW_ShowCbErr(S_ON_CURSOR_POS_CHANGED);
    Py_XDECREF(py_result);
  }

  //--------------------------------------------------------------------------
  // OnHostFormClose
  virtual void on_close()
  {
    // Call the close method if it is there and the object is still bound
    if ( (features & HAVE_CLOSE) != 0 && py_self != NULL )
    {
      PYW_GIL_ENSURE;
      PyObject *py_result = PyObject_CallMethod(py_self, (char *)S_ON_CLOSE, NULL);
      PYW_GIL_RELEASE;
      
      PyW_ShowCbErr(S_ON_CLOSE);
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
    PYW_GIL_ENSURE;
    PyObject *py_result = PyObject_CallMethod(
        py_self, 
        (char *)S_ON_KEYDOWN, 
        "ii", 
        vk_key, 
        shift);
    PYW_GIL_RELEASE;

    PyW_ShowCbErr(S_ON_KEYDOWN);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
// OnPopupShow
  virtual bool on_popup()
  {
    PYW_GIL_ENSURE;
    PyObject *py_result = PyObject_CallMethod(
        py_self, 
        (char *)S_ON_POPUP, 
        NULL);
    PYW_GIL_RELEASE;
    
    PyW_ShowCbErr(S_ON_POPUP);
    bool ok = py_result != NULL && PyObject_IsTrue(py_result);
    Py_XDECREF(py_result);
    return ok;
  }

  //--------------------------------------------------------------------------
  // OnHint
  virtual bool on_hint(place_t *place, int *important_lines, qstring &hint)
  {
    size_t ln = data.to_lineno(place);
    PYW_GIL_ENSURE;
    PyObject *py_result = PyObject_CallMethod(
        py_self, 
        (char *)S_ON_HINT, 
        PY_FMT64, 
        pyul_t(ln));
    PYW_GIL_RELEASE;
    
    PyW_ShowCbErr(S_ON_HINT);
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
    PYW_GIL_ENSURE;
    PyObject *py_result = PyObject_CallMethod(
        py_self, 
        (char *)S_ON_POPUP_MENU, 
        PY_FMT64, 
        pyul_t(menu_id));
    PYW_GIL_RELEASE;

    PyW_ShowCbErr(S_ON_POPUP_MENU);
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

%include "kernwin.hpp"
uint32 choose_choose(PyObject *self,
    int flags,
    int x0,int y0,
    int x1,int y1,
    int width);




%pythoncode %{

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

# ----------------------------------------------------------------------
def load_custom_icon(file_name=None, data=None, format=None):
    """
    Loads a custom icon and returns an identifier that can be used with other APIs

    If file_name is passed then the other two arguments are ignored.

    @param file_name: The icon file name
    @param data: The icon data
    @param format: The icon data format

    @return: Icon id or 0 on failure.
             Use free_custom_icon() to free it
    """
    if file_name is not None:
       return _idaapi.py_load_custom_icon_fn(file_name)
    elif not (data is None and format is None):
       return _idaapi.py_load_custom_icon_data(data, format)
    else:
      return 0

# ----------------------------------------------------------------------
def asklong(defval, format):
    res, val = _idaapi._asklong(defval, format)

    if res == 1:
        return val
    else:
        return None

# ----------------------------------------------------------------------
def askaddr(defval, format):
    res, ea = _idaapi._askaddr(defval, format)

    if res == 1:
        return ea
    else:
        return None

# ----------------------------------------------------------------------
def askseg(defval, format):
    res, sel = _idaapi._askseg(defval, format)

    if res == 1:
        return sel
    else:
        return None



class Choose2(object):
    """
    Choose2 wrapper class.

    Some constants are defined in this class. Please refer to kernwin.hpp for more information.
    """

    CH_MODAL        = 0x01
    """Modal chooser"""

    CH_MULTI        = 0x02
    """Allow multi selection"""

    CH_MULTI_EDIT   = 0x04
    CH_NOBTNS       = 0x08
    CH_ATTRS        = 0x10
    CH_NOIDB        = 0x20
    """use the chooser even without an open database, same as x0=-2"""

    CH_BUILTIN_MASK = 0xF80000

    # column flags (are specified in the widths array)
    CHCOL_PLAIN  =  0x00000000
    CHCOL_PATH   =  0x00010000
    CHCOL_HEX    =  0x00020000
    CHCOL_DEC    =  0x00030000
    CHCOL_FORMAT =  0x00070000


    def __init__(self, title, cols, flags=0, popup_names=None,
                 icon=-1, x1=-1, y1=-1, x2=-1, y2=-1, deflt=-1,
                 embedded=False, width=None, height=None):
        """
        Constructs a chooser window.
        @param title: The chooser title
        @param cols: a list of colums; each list item is a list of two items
            example: [ ["Address", 10 | Choose2.CHCOL_HEX], ["Name", 30 | Choose2.CHCOL_PLAIN] ]
        @param flags: One of CH_XXXX constants
        @param deflt: Default starting item
        @param popup_names: list of new captions to replace this list ["Insert", "Delete", "Edit", "Refresh"]
        @param icon: Icon index (the icon should exist in ida resources or an index to a custom loaded icon)
        @param x1, y1, x2, y2: The default location
        @param embedded: Create as embedded chooser
        @param width: Embedded chooser width
        @param height: Embedded chooser height
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
        self.embedded = embedded
        if embedded:
	        self.x1 = width
	        self.y1 = height


    def Embedded(self):
        """
        Creates an embedded chooser (as opposed to Show())
        @return: Returns 1 on success
        """
        return _idaapi.choose2_create(self, True)


    def GetEmbSelection(self):
        """
        Returns the selection associated with an embedded chooser

        @return:
            - None if chooser is not embedded
            - A list with selection indices (0-based)
        """
        return _idaapi.choose2_get_embedded_selection(self)


    def Show(self, modal=False):
        """
        Activates or creates a chooser window
        @param modal: Display as modal dialog
        @return: For modal choosers it will return the selected item index (0-based)
        """
        if modal:
            self.flags |= Choose2.CH_MODAL

            # Disable the timeout
            old = _idaapi.set_script_timeout(0)
            n = _idaapi.choose2_create(self, False)
            _idaapi.set_script_timeout(old)

            # Delete the modal chooser instance
            self.Close()

            return n
        else:
            self.flags &= ~Choose2.CH_MODAL
            return _idaapi.choose2_create(self, False)


    def Activate(self):
        """Activates a visible chooser"""
        return _idaapi.choose2_activate(self)


    def Refresh(self):
        """Causes the refresh callback to trigger"""
        return _idaapi.choose2_refresh(self)


    def Close(self):
        """Closes the chooser"""
        return _idaapi.choose2_close(self)


    def AddCommand(self,
                   caption,
                   flags = _idaapi.CHOOSER_POPUP_MENU,
                   menu_index = -1,
                   icon = -1,
				   emb=None):
        """
        Adds a new chooser command
        Save the returned value and later use it in the OnCommand handler

        @return: Returns a negative value on failure or the command index
        """

        # Use the 'emb' as a sentinel. It will be passed the correct value from the EmbeddedChooserControl
        if self.embedded and ((emb is None) or (emb != 2002)):
            raise RuntimeError("Please add a command through EmbeddedChooserControl.AddCommand()")
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
#        @param n: Line number (0-based)
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
#        @param n: Line number (0-based)
#        @return: Nothing
#        """
#        pass
#
#    def OnInsertLine(self):
#        """
#        Called when 'Insert' is selected either via the hotkey or popup menu.
#        @return: Nothing
#        """
#        pass
#
#    def OnSelectLine(self, n):
#        """
#        Called when a line is selected and then Ok or double click was pressed
#        @param n: Line number (0-based)
#        """
#        pass
#
#    def OnSelectionChange(self, sel_list):
#        """
#        Called when the selection changes
#        @param sel_list: A list of selected item indices
#        """
#        pass
#
#    def OnDeleteLine(self, n):
#        """
#        Called when a line is about to be deleted
#        @param n: Line number (0-based)
#        """
#        return self.n
#
#    def OnRefresh(self, n):
#        """
#        Triggered when the 'Refresh' is called from the popup menu item.
#
#        @param n: The currently selected line (0-based) at the time of the refresh call
#        @return: Return the number of elements
#        """
#        return self.n
#
#    def OnRefreshed(self):
#        """
#        Triggered when a refresh happens (for example due to column sorting)
#        @param n: Line number (0-based)
#        @return: Return the number of elements
#        """
#        return self.n
#
#    def OnCommand(self, n, cmd_id):
#        """Return int ; check add_chooser_command()"""
#        return 0
#
#    def OnGetIcon(self, n):
#        """
#        Return icon number for a given item (or -1 if no icon is avail)
#        @param n: Line number (0-based)
#        """
#        return -1
#
#    def OnGetLineAttr(self, n):
#        """
#        Return list [bgcolor, flags=CHITEM_XXXX] or None; check chooser_item_attrs_t
#        @param n: Line number (0-based)
#        """
#        return [0x0, CHITEM_BOLD]
#</pydoc>


#ICON WARNING|QUESTION|INFO|NONE
#AUTOHIDE NONE|DATABASE|REGISTRY|SESSION
#HIDECANCEL
#BUTTON YES|NO|CANCEL "Value"
#STARTITEM {id:ItemName}
#HELP / ENDHELP
try:
    import types
    from ctypes import *
    # On Windows, we use stdcall

    # Callback for buttons
    # typedef void (idaapi *formcb_t)(TView *fields[], int code);

    _FORMCB_T = WINFUNCTYPE(c_void_p, c_void_p, c_int)

    # Callback for form change
    # typedef int (idaapi *formchgcb_t)(int field_id, form_actions_t &fa);
    _FORMCHGCB_T = WINFUNCTYPE(c_int, c_int, c_void_p)
except:
    try:
        _FORMCB_T    = CFUNCTYPE(c_void_p, c_void_p, c_int)
        _FORMCHGCB_T = CFUNCTYPE(c_int, c_int, c_void_p)
    except:
        _FORMCHGCB_T = _FORMCB_T = None


# -----------------------------------------------------------------------
class Form(object):

    FT_ASCII = 'A'
    """Ascii string - char *"""
    FT_SEG = 'S'
    """Segment - sel_t *"""
    FT_HEX = 'N'
    """Hex number - uval_t *"""
    FT_SHEX = 'n'
    """Signed hex number - sval_t *"""
    FT_COLOR = 'K'
    """Color button - bgcolor_t *"""
    FT_ADDR = '$'
    """Address - ea_t *"""
    FT_UINT64 = 'L'
    """default base uint64 - uint64"""
    FT_INT64 = 'l'
    """default base int64 - int64"""
    FT_RAWHEX = 'M'
    """Hex number, no 0x prefix - uval_t *"""
    FT_FILE = 'f'
    """File browse - char * at least QMAXPATH"""
    FT_DEC = 'D'
    """Decimal number - sval_t *"""
    FT_OCT = 'O'
    """Octal number, C notation - sval_t *"""
    FT_BIN = 'Y'
    """Binary number, 0b prefix - sval_t *"""
    FT_CHAR = 'H'
    """Char value -- sval_t *"""
    FT_IDENT = 'I'
    """Identifier - char * at least MAXNAMELEN"""
    FT_BUTTON = 'B'
    """Button - def handler(code)"""
    FT_DIR = 'F'
    """Path to directory - char * at least QMAXPATH"""
    FT_TYPE = 'T'
    """Type declaration - char * at least MAXSTR"""
    _FT_USHORT = '_US'
    """Unsigned short"""
    FT_FORMCHG = '%/'
    """Form change callback - formchgcb_t"""
    FT_ECHOOSER = 'E'
    """Embedded chooser - idaapi.Choose2"""

    FT_CHKGRP = 'C'
    FT_CHKGRP2= 'c'
    FT_RADGRP = 'R'
    FT_RADGRP2= 'r'

    @staticmethod
    def fieldtype_to_ctype(tp, i64 = False):
        """
        Factory method returning a ctype class corresponding to the field type string
        """
        if tp in (Form.FT_SEG, Form.FT_HEX, Form.FT_RAWHEX, Form.FT_ADDR):
            return c_ulonglong if i64 else c_ulong
        elif tp in (Form.FT_SHEX, Form.FT_DEC, Form.FT_OCT, Form.FT_BIN, Form.FT_CHAR):
            return c_longlong if i64 else c_long
        elif tp == Form.FT_UINT64:
            return c_ulonglong
        elif tp == Form.FT_INT64:
            return c_longlong
        elif tp == Form.FT_COLOR:
            return c_ulong
        elif tp == Form._FT_USHORT:
            return c_ushort
        elif tp in (Form.FT_FORMCHG, Form.FT_ECHOOSER):
            return c_void_p
        else:
            return None


    #
    # Generic argument helper classes
    #
    class NumericArgument(object):
        """
        Argument representing various integer arguments (ushort, uint32, uint64, etc...)
        @param tp: One of Form.FT_XXX
        """
        DefI64 = False
        def __init__(self, tp, value):
            cls = Form.fieldtype_to_ctype(tp, self.DefI64)
            if cls is None:
                raise TypeError("Invalid field type: %s" % tp)
            # Get a pointer type to the ctype type
            self.arg = pointer(cls(value))

        def __set_value(self, v):
            self.arg.contents.value = v
        value = property(lambda self: self.arg.contents.value, __set_value)


    class StringArgument(object):
        """
        Argument representing a character buffer
        """
        def __init__(self, size=None, value=None):
            if size is None:
                raise SyntaxError("The string size must be passed")

            if value is None:
                self.arg = create_string_buffer(size)
            else:
                self.arg = create_string_buffer(value, size)
            self.size = size

        def __set_value(self, v):
            self.arg.value = v
        value = property(lambda self: self.arg.value, __set_value)


    #
    # Base control class
    #
    class Control(object):
        def __init__(self):
            self.id = 0
            """Automatically assigned control ID"""

            self.arg = None
            """Control argument value. This could be one element or a list/tuple (for multiple args per control)"""

            self.form = None
            """Reference to the parent form. It is filled by Form.Add()
            """


        def get_tag(self):
            """
            Control tag character. One of Form.FT_XXXX.
            The form class will expand the {} notation and replace them with the tags
            """
            pass

        def get_arg(self):
            """
            Control returns the parameter to be pushed on the stack
            (Of AskUsingForm())
            """
            return self.arg

        def free(self):
            """
            Free the control
            """
            # Release the parent form reference
            self.form = None


    #
    # Label controls
    #
    class LabelControl(Control):
        """
        Base class for static label control
        """
        def __init__(self, tp):
            Form.Control.__init__(self)
            self.tp = tp

        def get_tag(self):
            return '%%%d%s' % (self.id, self.tp)


    class StringLabel(LabelControl):
        """
        String label control
        """
        def __init__(self, value, tp=None, sz=1024):
            """
            Type field can be one of:
            A - ascii string
            T - type declaration
            I - ident
            F - folder
            f - file
            X - command
            """
            if tp is None:
                tp = Form.FT_ASCII
            Form.LabelControl.__init__(self, tp)
            self.size  = sz
            self.arg = create_string_buffer(value, sz)


    class NumericLabel(LabelControl, NumericArgument):
        """
        Numeric label control
        """
        def __init__(self, value, tp=None):
            if tp is None:
                tp = Form.FT_HEX
            Form.LabelControl.__init__(self, tp)
            Form.NumericArgument.__init__(self, tp, value)


    #
    # Group controls
    #
    class GroupItemControl(Control):
        """
        Base class for group control items
        """
        def __init__(self, tag, parent):
            Form.Control.__init__(self)
            self.tag = tag
            self.parent = parent
            # Item position (filled when form is compiled)
            self.pos = 0

        def assign_pos(self):
            self.pos = self.parent.next_child_pos()

        def get_tag(self):
            return "%s%d" % (self.tag, self.id)


    class ChkGroupItemControl(GroupItemControl):
        """
        Checkbox group item control
        """
        def __init__(self, tag, parent):
            Form.GroupItemControl.__init__(self, tag, parent)

        def __get_value(self):
            return (self.parent.value & (1 << self.pos)) != 0

        def __set_value(self, v):
            pv = self.parent.value
            if v:
                pv = pv | (1 << self.pos)
            else:
                pv = pv & ~(1 << self.pos)

            self.parent.value = pv

        checked = property(__get_value, __set_value)
        """Get/Sets checkbox item check status"""


    class RadGroupItemControl(GroupItemControl):
        """
        Radiobox group item control
        """
        def __init__(self, tag, parent):
            Form.GroupItemControl.__init__(self, tag, parent)

        def __get_value(self):
            return self.parent.value == self.pos

        def __set_value(self, v):
            self.parent.value = self.pos

        selected = property(__get_value, __set_value)
        """Get/Sets radiobox item selection status"""


    class GroupControl(Control, NumericArgument):
        """
        Base class for group controls
        """
        def __init__(self, children_names, tag, value=0):
            Form.Control.__init__(self)
            self.children_names = children_names
            self.tag = tag
            self._reset()
            Form.NumericArgument.__init__(self, Form._FT_USHORT, value)

        def _reset(self):
            self.childpos = 0

        def next_child_pos(self):
            v = self.childpos
            self.childpos += 1
            return v

        def get_tag(self):
            return "%d" % self.id


    class ChkGroupControl(GroupControl):
        """
        Checkbox group control class.
        It holds a set of checkbox controls
        """
        ItemClass = None
        """
        Group control item factory class instance
        We need this because later we won't be treating ChkGroupControl or RadGroupControl
        individually, instead we will be working with GroupControl in general.
        """
        def __init__(self, children_names, value=0, secondary=False):
            # Assign group item factory class
            if Form.ChkGroupControl.ItemClass is None:
                Form.ChkGroupControl.ItemClass = Form.ChkGroupItemControl

            Form.GroupControl.__init__(
                self,
                children_names,
                Form.FT_CHKGRP2 if secondary else Form.FT_CHKGRP,
                value)


    class RadGroupControl(GroupControl):
        """
        Radiobox group control class.
        It holds a set of radiobox controls
        """
        ItemClass = None
        def __init__(self, children_names, value=0, secondary=False):
            """
            Creates a radiogroup control.
            @param children_names: A tuple containing group item names
            @param value: Initial selected radio item
            @param secondory: Allows rendering one the same line as the previous group control.
                              Use this if you have another group control on the same line.
            """
            # Assign group item factory class
            if Form.RadGroupControl.ItemClass is None:
                Form.RadGroupControl.ItemClass = Form.RadGroupItemControl

            Form.GroupControl.__init__(
                self,
                children_names,
                Form.FT_RADGRP2 if secondary else Form.FT_RADGRP,
                value)


    #
    # Input controls
    #
    class InputControl(Control):
        """
        Generic form input control.
        It could be numeric control, string control, directory/file browsing, etc...
        """
        def __init__(self, tp, width, swidth, hlp = None):
            """
            @param width: Display width
            @param swidth: String width
            """
            Form.Control.__init__(self)
            self.tp = tp
            self.width = width
            self.switdh = swidth
            self.hlp = hlp

        def get_tag(self):
            return "%s%d:%s:%s:%s" % (
                self.tp, self.id,
                self.width,
                self.switdh,
                ":" if self.hlp is None else self.hlp)


    class NumericInput(InputControl, NumericArgument):
        """
        A composite class serving as a base numeric input control class
        """
        def __init__(self, tp=None, value=0, width=50, swidth=10, hlp=None):
            if tp is None:
                tp = Form.FT_HEX
            Form.InputControl.__init__(self, tp, width, swidth, hlp)
            Form.NumericArgument.__init__(self, self.tp, value)


    class ColorInput(NumericInput):
        """
        Color button input control
        """
        def __init__(self, value = 0):
            """
            @param value: Initial color value in RGB
            """
            Form.NumericInput.__init__(self, tp=Form.FT_COLOR, value=value)


    class StringInput(InputControl, StringArgument):
        """
        Base string input control class.
        This class also constructs a StringArgument
        """
        def __init__(self,
                     tp=None,
                     width=1024,
                     swidth=40,
                     hlp=None,
                     value=None,
                     size=None):
            """
            @param width: String size. But in some cases it has special meaning. For example in FileInput control.
                          If you want to define the string buffer size then pass the 'size' argument
            @param swidth: Control width
            @param value: Initial value
            @param size: String size
            """
            if tp is None:
                tp = Form.FT_ASCII
            if not size:
                size = width
            Form.InputControl.__init__(self, tp, width, swidth, hlp)
            Form.StringArgument.__init__(self, size=size, value=value)


    class FileInput(StringInput):
        """
        File Open/Save input control
        """
        def __init__(self,
                     width=512,
                     swidth=80,
                     save=False, open=False,
                     hlp=None, value=None):

            if save == open:
                raise ValueError("Invalid mode. Choose either open or save")
            if width < 512:
                raise ValueError("Invalid width. Must be greater than 512.")

            # The width field is overloaded in this control and is used
            # to denote the type of the FileInput dialog (save or load)
            # On the other hand it is passed as is to the StringArgument part
            Form.StringInput.__init__(
                self,
                tp=Form.FT_FILE,
                width="1" if save else "0",
                swidth=swidth,
                hlp=hlp,
                size=width,
                value=value)


    class DirInput(StringInput):
        """
        Directory browsing control
        """
        def __init__(self,
                     width=512,
                     swidth=80,
                     hlp=None,
                     value=None):

            if width < 512:
                raise ValueError("Invalid width. Must be greater than 512.")

            Form.StringInput.__init__(
                self,
                tp=Form.FT_DIR,
                width=width,
                swidth=swidth,
                hlp=hlp,
                size=width,
                value=value)


    class ButtonInput(InputControl):
        """
        Button control.
        A handler along with a 'code' (numeric value) can be associated with the button.
        This way one handler can handle many buttons based on the button code (or in other terms id or tag)
        """
        def __init__(self, handler, code="", swidth="", hlp=None):
            """
            @param handler: Button handler. A callback taking one argument which is the code.
            @param code: A code associated with the button and that is later passed to the handler.
            """
            Form.InputControl.__init__(
                self,
                Form.FT_BUTTON,
                code,
                swidth,
                hlp)
            self.arg = _FORMCB_T(lambda view, code, h=handler: h(code))


    class FormChangeCb(Control):
        """
        Form change handler.
        This can be thought of like a dialog procedure.
        Everytime a form action occurs, this handler will be called along with the control id.
        The programmer can then call various form actions accordingly:
          - EnableField
          - ShowField
          - MoveField
          - GetFieldValue
          - etc...

        Special control IDs: -1 (The form is initialized) and -2 (Ok has been clicked)

        """
        def __init__(self, handler):
            """
            Constructs the handler.
            @param handler: The handler (preferrably a member function of a class derived from the Form class).
            """
            Form.Control.__init__(self)

            # Save the handler
            self.handler = handler

            # Create a callback stub
            # We use this mechanism to create an intermediate step
            # where we can create an 'fa' adapter for use by Python
            self.arg = _FORMCHGCB_T(self.helper_cb)

        def helper_cb(self, fid, p_fa):
            # Remember the pointer to the forms_action
            self.form.p_fa = p_fa

            # Call user's handler
            r = self.handler(fid)
            return 0 if r is None else r

        def get_tag(self):
            return Form.FT_FORMCHG

        def free(self):
            Form.Control.free(self)
            # Remove reference to the handler
            # (Normally the handler is a member function in the parent form)
            self.handler = None


    class EmbeddedChooserControl(InputControl):
        """
        Embedded chooser control.
        This control links to a Chooser2 control created with the 'embedded=True'
        """
        def __init__(self,
                     chooser=None,
                     swidth=40,
                     hlp=None):
            """
            Embedded chooser control

            @param chooser: A chooser2 instance (must be constructed with 'embedded=True')
            """

            # !! Make sure a chooser instance is passed !!
            if chooser is None or not isinstance(chooser, Choose2):
                raise ValueError("Invalid chooser passed.")

            # Create an embedded chooser structure from the Choose2 instance
            if chooser.Embedded() != 1:
                raise ValueError("Failed to create embedded chooser instance.")

            # Construct input control
            Form.InputControl.__init__(self, Form.FT_ECHOOSER, "", swidth)

            # Get a pointer to the chooser_info_t and the selection vector
            # (These two parameters are the needed arguments for the AskUsingForm())
            emb, sel = _idaapi.choose2_get_embedded(chooser)

            # Get a pointer to a c_void_p constructed from an address
            p_embedded = pointer(c_void_p.from_address(emb))
            p_sel      = pointer(c_void_p.from_address(sel))

            # - Create the embedded chooser info on control creation
            # - Do not free the embeded chooser because after we get the args
            #   via Compile() the user can still call Execute() which relies
            #   on the already computed args
            self.arg   = (p_embedded, p_sel)

            # Save chooser instance
            self.chooser = chooser

            # Add a bogus 'size' attribute
            self.size = 0


        value = property(lambda self: self.chooser)
        """Returns the embedded chooser instance"""


        def AddCommand(self,
                       caption,
                       flags = _idaapi.CHOOSER_POPUP_MENU,
                       menu_index = -1,
                       icon = -1):
            """
            Adds a new embedded chooser command
            Save the returned value and later use it in the OnCommand handler

            @return: Returns a negative value on failure or the command index
            """
            if not self.form.title:
                raise ValueError("Form title is not set!")

            # Encode all information for the AddCommand() in the 'caption' parameter
            caption = "%s:%d:%s" % (self.form.title, self.id, caption)
            return self.chooser.AddCommand(caption, flags=flags, menu_index=menu_index, icon=icon, emb=2002)


        def free(self):
            """
            Frees the embedded chooser data
            """
            self.chooser.Close()
            self.chooser = None
            Form.Control.free(self)


    #
    # Class methods
    #
    def __init__(self, form, controls):
        """
        Contruct a Form class.
        This class wraps around AskUsingForm() and provides an easier / alternative syntax for describing forms.
        The form control names are wrapped inside the opening and closing curly braces and the control themselves are
        defined and instantiated via various form controls (subclasses of Form).

        @param form: The form string
        @param controls: A dictionary containing the control name as a _key_ and control object as _value_
        """
        self._reset()
        self.form = form
        """Form string"""
        self.controls = controls
        """Dictionary of controls"""
        self.__args = None

        self.title = None
        """The Form title. It will be filled when the form is compiled"""


    def Free(self):
        """
        Frees all resources associated with a compiled form.
        Make sure you call this function when you finish using the form.
        """
        for ctrl in self.__controls.values():
             ctrl.free()

        # Reset the controls
        # (Note that we are not removing the form control attributes, no need)
        self._reset()


    def _reset(self):
        """
        Resets the Form class state variables
        """
        self.__controls = {}
        self.__ctrl_id = 1


    def __getitem__(self, name):
        """Returns a control object by name"""
        return self.__controls[name]


    def Add(self, name, ctrl, mkattr = True):
        """
        Low level function. Prefer AddControls() to this function.
        This function adds one control to the form.

        @param name: Control name
        @param ctrl: Control object
        @param mkattr: Create control name / control object as a form attribute
        """
        # Assign a unique ID
        ctrl.id = self.__ctrl_id
        self.__ctrl_id += 1

        # Create attribute with control name
        if mkattr:
            setattr(self, name, ctrl)

        # Remember the control
        self.__controls[name] = ctrl

        # Link the form to the control via its form attribute
        ctrl.form = self

        # Is it a group? Add each child
        if isinstance(ctrl, Form.GroupControl):
            self._AddGroup(ctrl, mkattr)


    def FindControlById(self, id):
        """
        Finds a control instance given its id
        """
        for ctrl in self.__controls.values():
            if ctrl.id == id:
                return ctrl
        return None


    @staticmethod
    def _ParseFormTitle(form):
        """
        Parses the form's title from the form text
        """
        help_state = 0
        for i, line in enumerate(form.split("\n")):
            if line.startswith("STARTITEM ") or line.startswith("BUTTON "):
                continue
            # Skip "HELP" and remember state
            elif help_state == 0 and line == "HELP":
                help_state = 1 # Mark inside HELP
                continue
            elif help_state == 1 and line == "ENDHELP":
                help_state = 2 # Mark end of HELP
                continue
            return line.strip()

        return None


    def _AddGroup(self, Group, mkattr=True):
        """
        Internal function.
        This function expands the group item names and creates individual group item controls

        @param Group: The group class (checkbox or radio group class)
        """

        # Create group item controls for each child
        for child_name in Group.children_names:
            self.Add(
                child_name,
                # Use the class factory
                Group.ItemClass(Group.tag, Group),
                mkattr)


    def AddControls(self, controls, mkattr=True):
        """
        Adds controls from a dictionary.
        The dictionary key is the control name and the value is a Form.Control object
        @param controls: The control dictionary
        """
        for name, ctrl in controls.items():
            # Add the control
            self.Add(name, ctrl, mkattr)


    def CompileEx(self, form):
        """
        Low level function.
        Compiles (parses the form syntax and adds the control) the form string and
        returns the argument list to be passed the argument list to AskUsingForm().

        The form controls are wrapped inside curly braces: {ControlName}.

        A special operator can be used to return the ID of a given control by its name: {id:ControlName}.
        This is useful when you use the STARTITEM form keyword to set the initially focused control.

        @param form: Compiles the form and returns the arguments needed to be passed to AskUsingForm()
        """
        # First argument is the form string
        args = [None]
        ctrlcnt = 1

        # Reset all group control internal flags
        for ctrl in self.__controls.values():
            if isinstance(ctrl, Form.GroupControl):
                ctrl._reset()

        p = 0
        while True:
            i1 = form.find("{", p)
            # No more items?
            if i1 == -1:
                break

            # Check if escaped
            if (i1 != 0) and form[i1-1] == "\\":
                # Remove escape sequence and restart search
                form = form[:i1-1] + form[i1:]

                # Skip current marker
                p = i1

                # Continue search
                continue

            i2 = form.find("}", i1)
            if i2 == -1:
                raise SyntaxError("No matching closing brace '}'")

            # Parse control name
            ctrlname = form[i1+1:i2]
            if not ctrlname:
                raise ValueError("Control %d has an invalid name!" % ctrlcnt)

            # Is it the IDOF operator?
            if ctrlname.startswith("id:"):
                idfunc = True
                # Take actual ctrlname
                ctrlname = ctrlname[3:]
            else:
                idfunc = False

            # Find the control
            ctrl = self.__controls.get(ctrlname, None)
            if ctrl is None:
                raise ValueError("No matching control '%s'" % ctrlname)

            # Replace control name by tag
            if idfunc:
                tag = str(ctrl.id)
            else:
                tag = ctrl.get_tag()
            taglen = len(tag)
            form = form[:i1] + tag + form[i2+1:]

            # Set new position
            p = i1 + taglen

            # Was it an IDOF() ? No need to push parameters
            # Just ID substitution is fine
            if idfunc:
                continue


            # For GroupItem controls, there are no individual arguments
            # The argument is assigned for the group itself
            if isinstance(ctrl, Form.GroupItemControl):
                # GroupItem controls will have their position dynamically set
                ctrl.assign_pos()
            else:
                # Push argument(s)
                # (Some controls need more than one argument)
                arg = ctrl.get_arg()
                if isinstance(arg, (types.ListType, types.TupleType)):
                    # Push all args
                    args.extend(arg)
                else:
                    # Push one arg
                    args.append(arg)

            ctrlcnt += 1

        # Patch in the final form string
        args[0] = form

        self.title = self._ParseFormTitle(form)
        return args


    def Compile(self):
        """
        Compiles a form and returns the form object (self) and the argument list.
        The form object will contain object names corresponding to the form elements

        @return: It will raise an exception on failure. Otherwise the return value is ignored
        """

        # Reset controls
        self._reset()

        # Insert controls
        self.AddControls(self.controls)

        # Compile form and get args
        self.__args = self.CompileEx(self.form)

        return (self, self.__args)


    def Compiled(self):
        """
        Checks if the form has already been compiled

        @return: Boolean
        """
        return self.__args is not None


    def Execute(self):
        """
        Displays a compiled form.
        @return: 1 - ok ; 0 - cancel
        """
        if not self.Compiled():
            raise SyntaxError("Form is not compiled")

        # Call AskUsingForm()
        return AskUsingForm(*self.__args)


    def EnableField(self, ctrl, enable):
        """
        Enable or disable an input field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_enable_field(self.p_fa, ctrl.id, enable)


    def ShowField(self, ctrl, show):
        """
        Show or hide an input field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_show_field(self.p_fa, ctrl.id, show)


    def MoveField(self, ctrl, x, y, w, h):
        """
        Move/resize an input field

        @return: False - no such fiel
        """
        return _idaapi.formchgcbfa_move_field(self.p_fa, ctrl.id, x, y, w, h)


    def GetFocusedField(self):
        """
        Get currently focused input field.
        @return: None if no field is selected otherwise the control ID
        """
        id = _idaapi.formchgcbfa_get_focused_field(self.p_fa)
        return self.FindControlById(id)


    def SetFocusedField(self, ctrl):
        """
        Set currently focused input field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_set_focused_field(self.p_fa, ctrl.id)


    def RefreshField(self, ctrl):
        """
        Refresh a field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_refresh_field(self.p_fa, ctrl.id)


    def GetControlValue(self, ctrl):
        """
        Returns the control's value depending on its type
        @param ctrl: Form control instance
        @return:
            - number: color button, radio controls
            - string: file/dir input, string input and string label
            - int list: for embedded chooser control (0-based indices of selected items)
            - None: on failure
        """
        tid, sz = self.ControlToFieldTypeIdAndSize(ctrl)
        return _idaapi.formchgcbfa_get_field_value(
                    self.p_fa,
                    ctrl.id,
                    tid,
                    sz)


    def SetControlValue(self, ctrl, value):
        """
        Set the control's value depending on its type
        @param ctrl: Form control instance
        @param value:
            - embedded chooser: base a 0-base indices list to select embedded chooser items
        @return: Boolean true on success
        """
        tid, _ = self.ControlToFieldTypeIdAndSize(ctrl)
        return _idaapi.formchgcbfa_set_field_value(
                    self.p_fa,
                    ctrl.id,
                    tid,
                    value)


    @staticmethod
    def ControlToFieldTypeIdAndSize(ctrl):
        """
        Converts a control object to a tuple containing the field id
        and the associated buffer size
        """
        # Input control depend on the associate buffer size (supplied by the user)

        # Make sure you check instances types taking into account inheritance
        if isinstance(ctrl, Form.EmbeddedChooserControl):
            return (5, 0)
        # Group items or controls
        elif isinstance(ctrl, (Form.GroupItemControl, Form.GroupControl)):
            return (2, 0)
        elif isinstance(ctrl, Form.StringLabel):
            return (3, min(_idaapi.MAXSTR, ctrl.size))
        elif isinstance(ctrl, Form.ColorInput):
            return (4, 0)
        elif isinstance(ctrl, Form.InputControl):
            return (1, ctrl.size)
        else:
            raise NotImplementedError, "Not yet implemented"

# --------------------------------------------------------------------------
# Instantiate AskUsingForm function pointer
try:
    import ctypes
    # Setup the numeric argument size
    Form.NumericArgument.DefI64 = _idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL
    AskUsingForm__ = ctypes.CFUNCTYPE(ctypes.c_long)(_idaapi.py_get_AskUsingForm())
except:
    def AskUsingForm__(*args):
        warning("AskUsingForm() needs ctypes library in order to work")
        return 0


def AskUsingForm(*args):
    """
    Calls the AskUsingForm()
    @param: Compiled Arguments obtain through the Form.Compile() function
    @return: 1 = ok, 0 = cancel
    """
    old = set_script_timeout(0)
    r = AskUsingForm__(*args)
    set_script_timeout(old)
    return r


#</pycode(py_kernwin)>

#<pycode(py_plgform)>
class PluginForm(object):
    """
    PluginForm class.

    This form can be used to host additional controls. Please check the PyQt example.
    """

    FORM_MDI      = 0x01
    """start by default as MDI"""
    FORM_TAB      = 0x02
    """attached by default to a tab"""
    FORM_RESTORE  = 0x04
    """restore state from desktop config"""
    FORM_ONTOP    = 0x08
    """form should be "ontop"""
    FORM_MENU     = 0x10
    """form must be listed in the windows menu (automatically set for all plugins)"""
    FORM_CENTERED = 0x20
    """form will be centered on the screen"""
    FORM_PERSIST  = 0x40
    """form will persist until explicitly closed with Close()"""


    def __init__(self):
        """
        """
        self.__clink__ = _idaapi.plgform_new()



    def Show(self, caption, options = 0):
        """
		Creates the form if not was not created or brings to front if it was already created

        @param caption: The form caption
        @param options: One of PluginForm.FORM_ constants
        """
        options |= PluginForm.FORM_MDI|PluginForm.FORM_TAB|PluginForm.FORM_MENU|PluginForm.FORM_RESTORE
        return _idaapi.plgform_show(self.__clink__, self, caption, options)


    @staticmethod
    def FormToPyQtWidget(form, ctx = sys.modules['__main__']):
        """
        Use this method to convert a TForm* to a QWidget to be used by PyQt

        @param ctx: Context. Reference to a module that already imported SIP and QtGui modules
        """
        return ctx.sip.wrapinstance(ctx.sip.voidptr(form).__int__(), ctx.QtGui.QWidget)


    @staticmethod
    def FormToPySideWidget(form, ctx = sys.modules['__main__']):
        """
        Use this method to convert a TForm* to a QWidget to be used by PySide

        @param ctx: Context. Reference to a module that already imported QtGui module
        """
        return ctx.QtGui.QWidget.FromCObject(form)


    def OnCreate(self, form):
        """
        This event is called when the plugin form is created.
        The programmer should populate the form when this event is triggered.

        @return: None
        """
        pass


    def OnClose(self, form):
        """
        Called when the plugin form is closed

        @return: None
        """
        pass


    def Close(self, options):
        """
        Closes the form.

        @param options: Close options (FORM_SAVE, FORM_NO_CONTEXT, ...)

        @return: None
        """
        return _idaapi.plgform_close(self.__clink__)

    FORM_SAVE           = 0x1
    """save state in desktop config"""

    FORM_NO_CONTEXT     = 0x2
    """don't change the current context (useful for toolbars)"""

    FORM_DONT_SAVE_SIZE = 0x4
    """don't save size of the window"""

#</pycode(py_plgform)>

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
    if (flags & Choose2.CH_MODAL) == 0:
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
    old = set_script_timeout(0)
    n = _idaapi.choose_choose(self, self.flags, self.x0, self.y0, self.x1, self.y1, self.width)
    set_script_timeout(old)
    return n
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
        @return: Boolean
        """
        return _idaapi.pyscv_insert_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def EditLine(self, lineno, line, fgcolor=None, bgcolor=None):
        """
        Edits an existing line.
        @return: Boolean
        """
        return _idaapi.pyscv_edit_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def PatchLine(self, lineno, offs, value):
        """Patches an existing line character at the given offset. This is a low level function. You must know what you're doing"""
        return _idaapi.pyscv_patch_line(self.__this, lineno, offs, value)

    def DelLine(self, lineno):
        """
        Deletes an existing line
        @return: Boolean
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
        """Calls GetPos() and returns the current line number or -1 on failure"""
        r = self.GetPos(mouse)
        return -1 if not r else r[0]

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
