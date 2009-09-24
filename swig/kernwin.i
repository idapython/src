// Ignore the va_list functions
%ignore AskUsingForm_cv;
%ignore close_form;
%ignore vaskstr;
%ignore vasktext;
%ignore add_menu_item;
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

// Ignore the cli_t class
%ignore cli_t;

%include "typemaps.i"

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
bool idaapi py_menu_item_callback(void *userdata)
{
    PyObject *func, *args, *result;
    bool ret = 0;

    // userdata is a tuple of ( func, args )
    // func and args are borrowed references from userdata
    func = PyTuple_GET_ITEM(userdata, 0);
    args = PyTuple_GET_ITEM(userdata, 1);

    // call the python function
    result = PyEval_CallObject(func, args);

    // we cannot raise an exception in the callback, just print it.
    if (!result) {
        PyErr_Print();
        return 0;
    }

    // if the function returned a non-false value, then return 1 to ida,
    // overwise return 0
    if (PyObject_IsTrue(result)) {
        ret = 1;
    }
    Py_DECREF(result);

    return ret;
}
%}

%rename (add_menu_item) wrap_add_menu_item;
%inline %{
bool wrap_add_menu_item (
    const char *menupath,
    const char *name,
    const char *hotkey,
    int flags,
    PyObject *pyfunc,
    PyObject *args) {
    // FIXME: probably should keep track of this data, and destroy it when the menu item is removed
    PyObject *cb_data;

    if (args == Py_None) {
        Py_DECREF(Py_None);
        args = PyTuple_New( 0 );
        if (!args)
            return 0;
    }

    if(!PyTuple_Check(args)) {
        PyErr_SetString(PyExc_TypeError, "args must be a tuple or None");
        return 0;
    }

    cb_data = Py_BuildValue("(OO)", pyfunc, args);
    return add_menu_item(menupath, name, hotkey, flags, py_menu_item_callback, (void *)cb_data);
}
%}

%include "kernwin.hpp"

uint32 choose_choose(PyObject *self,
    int flags,
    int x0,int y0,
    int x1,int y1,
    int width);

PyObject *choose2_find(const char *title);
int choose2_add_command(PyObject *self, const char *caption, int flags=0, int menu_index=-1, int icon=-1);
void choose2_refresh(PyObject *self);
void choose2_close(PyObject *self);
int choose2_show(PyObject *self);
void choose2_activate(PyObject *self);

%{

//-------------------------------------------------------------------------
// Chooser2 wrapper class
//-------------------------------------------------------------------------
#include <map>

//------------------------------------------------------------------------
static PyObject *PyObject_TryGetAttrString(PyObject *object, const char *attr)
{
  if (!PyObject_HasAttrString(object, attr))
    return NULL;
  return PyObject_GetAttrString(object, attr);
}

//------------------------------------------------------------------------
// Some defines
#define POPUP_NAMES_COUNT 4
#define MAX_CHOOSER_MENU_COMMANDS 10
#define thisobj ((py_choose2_t *) obj)
#define thisdecl py_choose2_t *_this = thisobj
#define MENU_COMMAND_CB(id) static uint32 idaapi s_menu_command_##id(void *obj, uint32 n) { return thisobj->on_command(id, int(n)); }
#define DECL_MENU_COMMAND_CB(id) s_menu_command_##id
#define S_ON_EDIT_LINE       "OnEditLine"
#define S_ON_INSERT_LINE     "OnInsertLine"
#define S_ON_GET_LINE        "OnGetLine"
#define S_ON_DELETE_LINE     "OnDeleteLine"
#define S_ON_REFRESH         "OnRefresh"
#define S_ON_SELECT_LINE     "OnSelectLine"
#define S_ON_COMMAND         "OnCommand"
#define S_ON_GET_ICON        "OnGetIcon"
#ifdef CH_ATTRS
  #define S_ON_GET_LINE_ATTR   "OnGetLineAttr"
#endif
#define S_ON_GET_SIZE        "OnGetSize"
#define S_ON_CLOSE           "OnClose"
#define CHOOSE2_HAVE_DEL      0x0001
#define CHOOSE2_HAVE_INS      0x0002
#define CHOOSE2_HAVE_UPDATE   0x0004
#define CHOOSE2_HAVE_EDIT     0x0008
#define CHOOSE2_HAVE_ENTER    0x0010
#define CHOOSE2_HAVE_GETICON  0x0020
#define CHOOSE2_HAVE_GETATTR  0x0040
#define CHOOSE2_HAVE_COMMAND  0x0080
#define CHOOSE2_HAVE_ONCLOSE  0x0100

//------------------------------------------------------------------------
// Helper functions
class py_choose2_t;
typedef std::map<PyObject *, py_choose2_t *> pychoose2_to_choose2_map_t;
static pychoose2_to_choose2_map_t choosers;

py_choose2_t *choose2_find_instance(PyObject *self)
{
  pychoose2_to_choose2_map_t::iterator it = choosers.find(self);
  if (it == choosers.end())
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
  if (it != choosers.end())
    choosers.erase(it);
}

//------------------------------------------------------------------------
class py_choose2_t
{
private:
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
  static chooser_cb_t *menu_cbs[MAX_CHOOSER_MENU_COMMANDS];
  int menu_cb_idx;
  //------------------------------------------------------------------------
  // Static methods to dispatch to member functions
  //------------------------------------------------------------------------
#ifdef CH_ATTRS
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
#endif
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
    if (lineno == 0)
    {
      for (size_t i=0;i<cols.size();i++)
        qstrncpy(line_arr[i], cols[i].c_str(), MAXSTR);
      return;
    }

    // Clear buffer
    int ncols = int(cols.size());
    for (int i=ncols-1;i>=0;i--)
      line_arr[i][0] = '\0';

    // Call Python
    PyObject *list = PyObject_CallMethod(self, S_ON_GET_LINE, "l", lineno - 1);
    if (list == NULL)
      return;
    for (int i=ncols-1;i>=0;i--)
    {
      PyObject *item = PyList_GetItem(list, Py_ssize_t(i));
      if (item == NULL)
        continue;
      const char *str = PyString_AsString(item);
      if (str != NULL)
        qstrncpy(line_arr[i], str, MAXSTR);
    }
    Py_DECREF(list);
  }

  size_t on_get_size()
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_GET_SIZE, NULL);
    if (pyres == NULL)
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
    PyObject *pyres = PyObject_CallMethod(self, S_ON_CLOSE, NULL);
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
    PyObject *pyres = PyObject_CallMethod(self, S_ON_DELETE_LINE, "l", lineno - 1);
    if (pyres == NULL)
      return lineno;
    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res + 1;
  }

  int on_refresh(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_REFRESH, "l", lineno - 1);
    if (pyres == NULL)
      return lineno;
    size_t res = PyInt_AsLong(pyres);
    Py_DECREF(pyres);
    return res + 1;
  }

  void on_insert_line()
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_INSERT_LINE, NULL);
    Py_XDECREF(pyres);
  }

  void on_select_line(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_SELECT_LINE, "l", lineno - 1);
    Py_XDECREF(pyres);
  }

  void on_edit_line(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_EDIT_LINE, "l", lineno - 1);
    Py_XDECREF(pyres);
  }

  int on_command(int cmd_id, int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_COMMAND, "ll", lineno - 1, cmd_id);
    if (pyres==NULL)
      return lineno;
    size_t res = PyInt_AsLong(pyres);
    Py_XDECREF(pyres);
    return res;
  }

  int on_get_icon(int lineno)
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_GET_ICON, "l", lineno - 1);
    size_t res = PyInt_AsLong(pyres);
    Py_XDECREF(pyres);
    return res;
  }
#ifdef CH_ATTRS
  void on_get_line_attr(int lineno, chooser_item_attrs_t *attr)
  {
    PyObject *pyres = PyObject_CallMethod(self, S_ON_GET_LINE_ATTR, "l", lineno - 1);
    if (pyres == NULL)
      return;

    if (PyList_Check(pyres))
    {
      PyObject *item;
      if ((item = PyList_GetItem(pyres, 0)) != NULL)
        attr->color = PyInt_AsLong(item);
      if ((item = PyList_GetItem(pyres, 1)) != NULL)
        attr->flags = PyInt_AsLong(item);
    }
    Py_XDECREF(pyres);
  }
#endif
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
    if (frm == NULL)
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
#ifdef CH_ATTRS
    if ( (flags & CH_ATTRS) != 0 )
    {
      if ( !hook_to_notification_point(HT_UI, ui_cb, this) )
        flags &= ~CH_ATTRS;
    }
#endif
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
    if (menu_cb_idx >= MAX_CHOOSER_MENU_COMMANDS)
      return -1;
    bool ret = add_chooser_command(title.c_str(), caption, menu_cbs[menu_cb_idx], menu_index, icon, flags);
    if (!ret)
      return -1;
    return menu_cb_idx++;
  }

  int show(PyObject *self)
  {
    PyObject *attr;
    // get title
    if ( (attr = PyObject_TryGetAttrString(self, "title")) == NULL )
      return -1;
    qstring title = PyString_AsString(attr);
    Py_DECREF(attr);

    // get flags
    if ( (attr = PyObject_TryGetAttrString(self, "flags")) == NULL )
      return -1;
    int flags = PyInt_AsLong(attr);
    Py_DECREF(attr);

    // get columns
    if ( (attr = PyObject_TryGetAttrString(self, "cols")) == NULL )
      return -1;

    // get col count
    int ncols = PyList_Size(attr);

    // get cols caption and widthes
    intvec_t widths;
    cols.qclear();
    for (int i=0;i<ncols;i++)
    {
      // get list item: [name, width]
      PyObject *list = PyList_GetItem(attr, i);
      PyObject *v = PyList_GetItem(list, 0);

      // Extract string
      const char *str;
      if (v != NULL)
        str = PyString_AsString(v);
      else
        str = "";
      cols.push_back(str);

      // Extract width
      int width;
      v = PyList_GetItem(list, 1);
      if (v == NULL)
        width = strlen(str);
      else
        width = PyInt_AsLong(v);
      widths.push_back(width);
    }
    Py_DECREF(attr);

    // get *deflt
    int deflt = -1;
    if ( (attr = PyObject_TryGetAttrString(self, "deflt")) != NULL )
    {
      deflt = PyInt_AsLong(attr);
      Py_DECREF(attr);
    }

    // get *icon
    int icon = -1;
    if ( (attr = PyObject_TryGetAttrString(self, "icon")) != NULL )
    {
      icon = PyInt_AsLong(attr);
      Py_DECREF(attr);
    }

    // get *x1,y1,x2,y2
    int pts[4];
    static const char *pt_attrs[qnumber(pts)] = {"x1", "y1", "x2", "y2"};
    for (int i=0;i<qnumber(pts);i++)
    {
      if ((attr = PyObject_TryGetAttrString(self, pt_attrs[i])) == NULL)
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
#ifdef CH_ATTRS
      {S_ON_GET_LINE_ATTR, CHOOSE2_HAVE_GETATTR},
#endif
      {S_ON_GET_ICON,      CHOOSE2_HAVE_GETICON}
    };
    cb_flags = 0;
    for (int i=0;i<qnumber(callbacks);i++)
    {
      if ((attr = PyObject_TryGetAttrString(self, callbacks[i].name)) == NULL ||
        PyCallable_Check(attr) == 0)
      {
        Py_XDECREF(attr);
        // Mandatory field?
        if (callbacks[i].have == 0)
          return -1;
      }
      else
      {
        cb_flags |= callbacks[i].have;
      }
    }
    // get *popup names
    const char **popup_names = NULL;
    if ( ((attr = PyObject_TryGetAttrString(self, "popup_names")) != NULL)
      && PyList_Check(attr)
      && PyList_Size(attr) == POPUP_NAMES_COUNT )
    {
      popup_names = new const char *[POPUP_NAMES_COUNT];
      for (int i=0;i<POPUP_NAMES_COUNT;i++)
      {
        const char *str = PyString_AsString(PyList_GetItem(attr, i));
        popup_names[i] = qstrdup(str);
      }
    }
    Py_XDECREF(attr);

#ifdef CH_ATTRS
    // Adjust flags (if needed)
    if ( (cb_flags & CHOOSE2_HAVE_GETATTR) != 0 )
      flags |= CH_ATTRS;
#endif
    // Increase object reference
    Py_INCREF(self);
    this->self = self;

    // Create chooser
    int r = this->choose2(flags, ncols, &widths[0], title.c_str(), deflt, popup_names, icon, pts[0], pts[1], pts[2], pts[3]);

    // Clear temporary popup_names
    if (popup_names != NULL)
    {
      for (int i=0;i<POPUP_NAMES_COUNT;i++)
        qfree((void *)popup_names[i]);
      delete [] popup_names;
    }

    // Modal chooser return the index of the selected item
    if ( (flags & CH_MODAL) != 0 )
      r--;

    return r;
  }
  PyObject *get_self() { return self; }
  void refresh()
  {
    refresh_chooser(title.c_str());
  }
};

//------------------------------------------------------------------------
// Initialize the callback pointers
chooser_cb_t *py_choose2_t::menu_cbs[MAX_CHOOSER_MENU_COMMANDS] =
{
  DECL_MENU_COMMAND_CB(0),  DECL_MENU_COMMAND_CB(1),
  DECL_MENU_COMMAND_CB(2),  DECL_MENU_COMMAND_CB(3),
  DECL_MENU_COMMAND_CB(4),  DECL_MENU_COMMAND_CB(5),
  DECL_MENU_COMMAND_CB(6),  DECL_MENU_COMMAND_CB(7),
  DECL_MENU_COMMAND_CB(8),  DECL_MENU_COMMAND_CB(9)
};

#undef POPUP_NAMES_COUNT
#undef MAX_CHOOSER_MENU_COMMANDS
#undef thisobj
#undef thisdecl
#undef MENU_COMMAND_CB
#undef DECL_MENU_COMMAND_CB
#undef S_ON_EDIT_LINE
#undef S_ON_INSERT_LINE
#undef S_ON_GET_LINE
#undef S_ON_DELETE_LINE
#undef S_ON_REFRESH
#undef S_ON_SELECT_LINE
#undef S_ON_COMMAND
#undef S_ON_GET_ICON
#undef S_ON_GET_LINE_ATTR
#undef S_ON_GET_SIZE
#undef S_ON_CLOSE
#undef CHOOSE2_HAVE_DEL
#undef CHOOSE2_HAVE_INS
#undef CHOOSE2_HAVE_UPDATE
#undef CHOOSE2_HAVE_EDIT
#undef CHOOSE2_HAVE_ENTER
#undef CHOOSE2_HAVE_GETICON
#undef CHOOSE2_HAVE_GETATTR
#undef CHOOSE2_HAVE_COMMAND
#undef CHOOSE2_HAVE_ONCLOSE

//------------------------------------------------------------------------
int choose2_show(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if (c2 != NULL)
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
  if (c2 != NULL)
    c2->close();
}

//------------------------------------------------------------------------
void choose2_refresh(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if (c2 != NULL)
    c2->refresh();
}

//------------------------------------------------------------------------
void choose2_activate(PyObject *self)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if (c2 != NULL)
    c2->activate();
}

//------------------------------------------------------------------------
int choose2_add_command(PyObject *self, const char *caption, int flags=0, int menu_index=-1, int icon=-1)
{
  py_choose2_t *c2 = choose2_find_instance(self);
  if (c2 != NULL)
    return c2->add_command(caption, flags, menu_index, icon);
  else
    return -2;
}

//------------------------------------------------------------------------
PyObject *choose2_find(const char *title)
{
  py_choose2_t *c2 = py_choose2_t::find_chooser(title);
  if (c2 == NULL)
    return NULL;
  return c2->get_self();
}

//-------------------------------------------------------------------------
// End of Chooser2 wrapper class
//-------------------------------------------------------------------------

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
%}

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


class Choose2:
    """Choose2 wrapper class"""

    # refer to kernwin.hpp for more information on how to use these constants
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

    def __init__(self, title, cols, flags=0, popup_names=None, icon=-1, x1=-1, y1=-1, x2=-1, y2=-1):
        self.title = title
        self.flags = flags
        # a list of colums; each list item is a list of two items
    # example: [ ["Address", 10 | Choose2.CHCOL_HEX], ["Name", 30 | CHCOL_PLAIN] ]
        self.cols = cols
        self.deflt = -1
        # list of new captions to replace this list ["Insert", "Delete", "Edit", "Refresh"]
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

    def Activate():
        """Activates a visible chooser"""
        return _idaapi.choose2_activate(self)

    def Refresh():
        """Causes the refresh callback to trigger"""
        return _idaapi.choose2_refresh(self)

    def Close():
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

#    def OnClose(self):
#        # return nothing
#        pass

#    def OnEditLine(self, n):
#        # return nothing (mandatory callback)
#        pass

#    def OnInsertLine(self):
#        # return nothing
#        pass

#    def OnSelectLine(self, n):
#        # return nothing
#        pass

#    def OnGetLine(self, n):
#        # return a list [col1, col2, col3, ...] describing the n-th line
#        return ["col1", "col2", ...]

#    def OnGetSize(self):
#        # return the size (mandatory callback)
#        return len(self.the_list)

#    def OnDeleteLine(self, n):
#        # return new line number
#        return self.n

#    def OnRefresh(self, n):
#        # return new line number
#        return self.n

#    def OnCommand(self, n, cmd_id):
#        # return int ; check add_chooser_command()
#        return 0

#    def OnGetIcon(self, n):
#        # return icon number (or -1)
#        return -1

#    def OnGetLineAttr(self, n):
#        # return list [color, flags] or None; check chooser_item_attrs_t
#        pass

%}
