#ifndef __PYWRAPS_CLI__
#define __PYWRAPS_CLI__

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

//--------------------------------------------------------------------------

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
//---------------------------------------------------------------------------
#endif // __PYWRAPS_CLI__
