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

// Ignore the va_list functions
%ignore AskUsingForm_cv;
%ignore close_form;
%ignore vaskstr;
%ignore vasktext;
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


%include "kernwin.hpp"

ulong choose_choose(PyObject *self,
    int flags,
    int x0,int y0,
    int x1,int y1,
    int width);

%{
ulong idaapi choose_sizer(void *self)
{
	PyObject *pyres;
	ulong res;

	pyres = PyObject_CallMethod((PyObject *)self, "sizer", "");
	res = PyInt_AsLong(pyres);
	Py_DECREF(pyres);
	return res;
}

char * idaapi choose_getl(void *self, ulong n, char *buf)
{
	PyObject *pyres;
	char *res;

	char tmp[1024];

	pyres = PyObject_CallMethod((PyObject *)self, "getl", "l", n);

	if (!pyres)
	{
		strcpy(buf, "<Empty>");
		return buf;
	}

	res = PyString_AsString(pyres);

	if (res)
	{
		strcpy(buf, res);
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

void idaapi choose_enter(void *self, ulong n)
{
	PyObject_CallMethod((PyObject *)self, "enter", "l", n);
	return;
}

ulong choose_choose(void *self,
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
		flags,                // various flags: see above for description
		x0, y0,           // x0=-1 for autoposition
		x1, y1,
		self,             // object to show
		width,               // Max width of lines
		&choose_sizer,    // Number of items
		&choose_getl,     // Description of n-th item (1..n)
						  // 0-th item if header line
		title ? title : deftitle,
		1,
		1,
		NULL,
		NULL,
		NULL,
		NULL,
		&choose_enter
	);               // number of the default icon to display
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

	def sizer(self):
		"""
		Callback: sizer - returns the length of the list
		"""
		return len(self.list)

	def getl(self, n):
		"""
		Callback: getl - get one item from the list
		"""
		if n <= len(self.list):
			return self.list[n-1]
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

