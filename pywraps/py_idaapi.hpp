#ifndef __PY_IDAAPI__
#define __PY_IDAAPI__

//<code(py_idaapi)>
//-------------------------------------------------------------------------
#define GET_THIS() py_customidamemo_t *_this = (py_customidamemo_t *) view_extract_this(self)
#define CHK_THIS()                                                      \
  GET_THIS();                                                           \
  if ( _this == nullptr )                                               \
    return;
#define CHK_THIS_OR_NULL()                                              \
  GET_THIS();                                                           \
  if ( _this == nullptr )                                               \
    return nullptr;
#define CHK_THIS_OR_NONE()                                              \
  GET_THIS();                                                           \
  if ( _this == nullptr )                                               \
    Py_RETURN_NONE


//-------------------------------------------------------------------------
void pygc_refresh(PyObject *self)
{
  CHK_THIS();
  _this->refresh();
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

//-------------------------------------------------------------------------
TWidget *pycim_get_widget(PyObject *self)
{
  CHK_THIS_OR_NULL();
  TWidget *widget = nullptr;
  if ( !get_plugin_instance()->pycim_lookup_info.find_by_py_view(&widget, _this) )
    return nullptr;
  return widget;
}

//-------------------------------------------------------------------------
void pycim_view_close(PyObject *self)
{
  CHK_THIS();
  delete _this;
}

#undef CHK_THIS_OR_NONE
#undef CHK_THIS_OR_NULL
#undef CHK_THIS
#undef GET_THIS

//-------------------------------------------------------------------------
#define NOTIFY_DISPATCHER_INSTANCE "_notify_when_dispatcher"
#define NOTIFY_DISPATCHER_DISPATCH_METHOD "dispatch"
#define NW_INITIDA 4
#define NW_TERMIDA 8
//-------------------------------------------------------------------------
static void _ida_idaapi_notify_init_term(int what)
{
  newref_t py_mod(PyImport_ImportModule("ida_idaapi"));
  if ( py_mod != nullptr )
  {
    newref_t py_obj(PyObject_GetAttrString(py_mod.o, NOTIFY_DISPATCHER_INSTANCE));
    if ( py_obj != nullptr && py_obj.o != Py_None )
      PyObject_CallMethod(py_obj.o, NOTIFY_DISPATCHER_DISPATCH_METHOD, "i", what);
  }
}

//-------------------------------------------------------------------------
static void ida_idaapi_init(void)
{
  _ida_idaapi_notify_init_term(NW_INITIDA);
}

//-------------------------------------------------------------------------
static void ida_idaapi_term(void)
{
  _ida_idaapi_notify_init_term(NW_TERMIDA);
}

//-------------------------------------------------------------------------
static void ida_idaapi_closebase(void) {}

//</code(py_idaapi)>


//<inline(py_idaapi)>
// NOTE: See also `pywraps.hpp`
#define HBF_CALL_WITH_NEW_EXEC  0x00000001
#define HBF_VOLATILE_METHOD_SET 0x00000002

//------------------------------------------------------------------------
/*
#<pydoc>
def parse_command_line(cmdline):
    """
    Parses a space separated string (quotes and escape character are supported)
    @param cmdline: The command line to parse
    @return: A list of strings or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *py_parse_command_line(const char *cmdline)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t args;
  if ( parse_command_line(&args, nullptr, cmdline, LP_PATH_WITH_ARGS) == 0 )
    Py_RETURN_NONE;
  return qstrvec2pylist(args);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_inf_structure():
    """
    Returns the global variable 'inf' (an instance of idainfo structure, see ida.hpp)
    """
    pass
#</pydoc>
*/
idainfo *get_inf_structure(void)
{
  return &inf;
}

//-------------------------------------------------------------------------
// Declarations from Python.cpp
/*
#<pydoc>
def set_script_timeout(timeout):
    """
    Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses.
    See also L{disable_script_timeout}.

    @param timeout: This value is in seconds.
                    If this value is set to zero then the script will never timeout.
    @return: Returns the old timeout value
    """
    pass
#</pydoc>
*/
idaman int ida_export set_script_timeout(int timeout);

/*
#<pydoc>
def disable_script_timeout():
    """
    Disables the script timeout and hides the script wait box.
    Calling L{set_script_timeout} will not have any effects until the script is compiled and executed again

    @return: None
    """
    pass
#</pydoc>
*/
idaman void ida_export disable_script_timeout();

/*
#<pydoc>
def enable_extlang_python(enable):
    """
    Enables or disables Python extlang.
    When enabled, all expressions will be evaluated by Python.
    @param enable: Set to True to enable, False otherwise
    """
    pass
#</pydoc>
*/
idaman void ida_export enable_extlang_python(bool enable);
idaman void ida_export enable_python_cli(bool enable);

idaman PyObject *ida_export format_basestring(PyObject *_in)
{
  // This is basically a reimplementation of str.__repr__, except that
  // we don't want to turn non-ASCII bytes into a \xNN equivalent: IDA
  // accepts UTF-8 everywhere internally (and this will end up in a
  // 'msg' call eventually.)
  qstring utf8;
  if ( !PyUnicode_as_qstring(&utf8, _in) )
    return nullptr;
  char *in_bytes = utf8.begin();
  Py_ssize_t in_len = utf8.length();

  char quote = '\'';
  if ( memchr(in_bytes, '\'', in_len) != nullptr
    && memchr(in_bytes, '"', in_len) == nullptr )
  {
    quote = '"';
  }

  struct ida_local helper_t
  {
    static void put_escaped(qstring *out, char c)
    {
      out->append('\\');
      out->append(c);
    }
  };

  qstring buf;
  buf.reserve(in_len + 10); // a few more bytes, let's assume a bit of escaping...
  buf.append(quote);
  for ( Py_ssize_t i = 0; i < in_len; ++i )
  {
    char c = in_bytes[i];
    if ( c == quote || c == '\\' )
      helper_t::put_escaped(&buf, c);
    else if ( c == '\t' )
      helper_t::put_escaped(&buf, 't');
    else if ( c == '\n' )
      helper_t::put_escaped(&buf, 'n');
    else if ( c == '\r' )
      helper_t::put_escaped(&buf, 'r');
    else if ( uchar(c) < ' ' )
      buf.cat_sprnt("\\x%02x", c);
    else
      buf.append(c);
  }
  buf.append(quote);
  return PyUnicode_FromStringAndSize(buf.c_str(), buf.length());
}

/*
#<pydoc>
def RunPythonStatement(stmt):
    """
    This is an IDC function exported from the Python plugin.
    It is used to evaluate Python statements from IDC.
    @param stmt: The statement to evaluate
    @return: 0 - on success otherwise a string containing the error
    """
    pass
#</pydoc>
*/

void pygc_refresh(PyObject *self);
PyObject *pygc_create_groups(PyObject *self, PyObject *groups_infos);
PyObject *pygc_delete_groups(PyObject *self, PyObject *groups, PyObject *new_current);
PyObject *pygc_set_groups_visibility(PyObject *self, PyObject *groups, PyObject *expand, PyObject *new_current);
TWidget *pycim_get_widget(PyObject *self);
void pycim_view_close(PyObject *self);
//</inline(py_idaapi)>

#endif
