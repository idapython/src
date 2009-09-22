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

%{
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

    char deftitle[] = "Choose";
    char *title = NULL;

    if ((pytitle = PyObject_GetAttrString((PyObject *)self, "title")))
    {
        title = PyString_AsString(pytitle);
    }

    return choose(
        flags,
        x0, y0,
        x1, y1,
        self,
        width,
        &choose_sizer,
        &choose_getl,
        title ? title : deftitle,
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
%}
