#ifndef __PY_IDAAPI__
#define __PY_IDAAPI__

//<code(py_idaapi)>
//-------------------------------------------------------------------------
#define GET_THIS() py_customidamemo_t *_this = view_extract_this<py_customidamemo_t>(self)
#define CHK_THIS()                                                      \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    return;
#define CHK_THIS_OR_NULL()                                              \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    return NULL;
#define CHK_THIS_OR_NONE()                                              \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    Py_RETURN_NONE


//-------------------------------------------------------------------------
void pygc_refresh(PyObject *self)
{
  CHK_THIS();
  _this->refresh();
}

//-------------------------------------------------------------------------
void pygc_set_node_info(PyObject *self, PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags)
{
  CHK_THIS();
  _this->set_node_info(py_node_idx, py_node_info, py_flags);
}

//-------------------------------------------------------------------------
void pygc_set_nodes_infos(PyObject *self, PyObject *values)
{
  CHK_THIS();
  _this->set_nodes_infos(values);
}

//-------------------------------------------------------------------------
PyObject *pygc_get_node_info(PyObject *self, PyObject *py_node_idx)
{
  GET_THIS();
  if ( _this != NULL )
    return _this->get_node_info(py_node_idx);
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
void pygc_del_nodes_infos(PyObject *self, PyObject *py_nodes)
{
  CHK_THIS();
  _this->del_nodes_infos(py_nodes);
}

//-------------------------------------------------------------------------
PyObject *pygc_get_current_renderer_type(PyObject *self)
{
  GET_THIS();
  if ( _this != NULL )
    return _this->get_current_renderer_type();
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
void pygc_set_current_renderer_type(PyObject *self, PyObject *py_rt)
{
  CHK_THIS();
  _this->set_current_renderer_type(py_rt);
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
  TWidget *widget = NULL;
  if ( !pycim_lookup_info.find_by_py_view(&widget, _this) )
    return NULL;
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
//</code(py_idaapi)>


//<inline(py_idaapi)>


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
  if ( parse_command_line(&args, NULL, cmdline, LP_PATH_WITH_ARGS) == 0 )
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

//------------------------------------------------------------------------
/*
#<pydoc>
def notify_when(when, callback):
    """
    Register a callback that will be called when an event happens.
    @param when: one of NW_XXXX constants
    @param callback: This callback prototype varies depending on the 'when' parameter:
                     The general callback format:
                         def notify_when_callback(nw_code)
                     In the case of NW_OPENIDB:
                         def notify_when_callback(nw_code, is_old_database)
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool notify_when(int when, PyObject *py_callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyCallable_Check(py_callable) && add_notify_when(when, py_callable);
}

void pygc_refresh(PyObject *self);
void pygc_set_node_info(PyObject *self, PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags);
void pygc_set_nodes_infos(PyObject *self, PyObject *values);
PyObject *pygc_get_node_info(PyObject *self, PyObject *py_node_idx);
void pygc_del_nodes_infos(PyObject *self, PyObject *py_nodes);
PyObject *pygc_get_current_renderer_type(PyObject *self);
void pygc_set_current_renderer_type(PyObject *self, PyObject *py_rt);
PyObject *pygc_create_groups(PyObject *self, PyObject *groups_infos);
PyObject *pygc_delete_groups(PyObject *self, PyObject *groups, PyObject *new_current);
PyObject *pygc_set_groups_visibility(PyObject *self, PyObject *groups, PyObject *expand, PyObject *new_current);
TWidget *pycim_get_widget(PyObject *self);
void pycim_view_close(PyObject *self);
//</inline(py_idaapi)>

#endif
