#ifndef __PY_IDA_CUSTDATA__
#define __PY_IDA_CUSTDATA__

//<code(py_bytes)>

//------------------------------------------------------------------------
class py_custom_data_type_t
{
  data_type_t dt;
  qstring dt_name, dt_menu_name, dt_hotkey, dt_asm_keyword;
  int dtid; // The data format id
  PyObject *py_self; // Associated Python object

  // may create data? NULL means always may
  static bool idaapi s_may_create_at(
    void *ud,                       // user-defined data
    ea_t ea,                        // address of the future item
    size_t nbytes)                  // size of the future item
  {
    py_custom_data_type_t *_this = (py_custom_data_type_t *)ud;

    PYW_GIL_GET;
    newref_t py_result(
            PyObject_CallMethod(
                    _this->py_self,
                    (char *)S_MAY_CREATE_AT,
                    PY_FMT64 PY_FMT64,
                    pyul_t(ea),
                    pyul_t(nbytes)));

    PyW_ShowCbErr(S_MAY_CREATE_AT);
    return py_result != NULL && PyObject_IsTrue(py_result.o);
  }

  // !=NULL means variable size datatype
  static asize_t idaapi s_calc_item_size(
    // This function is used to determine
    // size of the (possible) item at 'ea'
    void *ud,                       // user-defined data
    ea_t ea,                        // address of the item
    asize_t maxsize)               // maximal size of the item
  {
    PYW_GIL_GET;
    // Returns: 0-no such item can be created/displayed
    // this callback is required only for varsize datatypes
    py_custom_data_type_t *_this = (py_custom_data_type_t *)ud;
    newref_t py_result(
            PyObject_CallMethod(
                    _this->py_self,
                    (char *)S_CALC_ITEM_SIZE,
                    PY_FMT64 PY_FMT64,
                    pyul_t(ea),
                    pyul_t(maxsize)));

    if ( PyW_ShowCbErr(S_CALC_ITEM_SIZE) || py_result == NULL )
      return 0;

    uint64 num = 0;
    PyW_GetNumber(py_result.o, &num);
    return asize_t(num);
  }

public:
  const char *get_name() const
  {
    return dt_name.c_str();
  }

  py_custom_data_type_t()
  {
    dtid = -1;
    py_self = NULL;
  }

  int register_dt(PyObject *py_obj)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    // Already registered?
    if ( dtid >= 0 )
      return dtid;

    memset(&dt, 0, sizeof(dt));
    dt.cbsize = sizeof(dt);
    dt.ud = this;

    do
    {
      ref_t py_attr;

      // name
      if ( !PyW_GetStringAttr(py_obj, S_NAME, &dt_name) )
        break;

      dt.name = dt_name.c_str();

      // menu_name (optional)
      if ( PyW_GetStringAttr(py_obj, S_MENU_NAME, &dt_menu_name) )
        dt.menu_name = dt_menu_name.c_str();

      // asm_keyword (optional)
      if ( PyW_GetStringAttr(py_obj, S_ASM_KEYWORD, &dt_asm_keyword) )
        dt.asm_keyword = dt_asm_keyword.c_str();

      // hotkey (optional)
      if ( PyW_GetStringAttr(py_obj, S_HOTKEY, &dt_hotkey) )
        dt.hotkey = dt_hotkey.c_str();

      // value_size
      py_attr = PyW_TryGetAttrString(py_obj, S_VALUE_SIZE);
      if ( py_attr != NULL && PyInt_Check(py_attr.o) )
        dt.value_size = PyInt_AsLong(py_attr.o);
      py_attr = ref_t();

      // props
      py_attr = PyW_TryGetAttrString(py_obj, S_PROPS);
      if ( py_attr != NULL && PyInt_Check(py_attr.o) )
        dt.props = PyInt_AsLong(py_attr.o);
      py_attr = ref_t();

      // may_create_at
      py_attr = PyW_TryGetAttrString(py_obj, S_MAY_CREATE_AT);
      if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
        dt.may_create_at = s_may_create_at;
      py_attr = ref_t();

      // calc_item_size
      py_attr = PyW_TryGetAttrString(py_obj, S_CALC_ITEM_SIZE);
      if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
        dt.calc_item_size = s_calc_item_size;
      py_attr = ref_t();

      // Now try to register
      dtid = register_custom_data_type(&dt);
      if ( dtid < 0 )
        break;

      // Hold reference to the PyObject
      Py_INCREF(py_obj);
      py_self = py_obj;

      py_attr = newref_t(PyInt_FromLong(dtid));
      PyObject_SetAttrString(py_obj, S_ID, py_attr.o);
    } while ( false );
    return dtid;
  }

  bool unregister_dt()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    if ( dtid < 0 )
      return true;

    if ( !unregister_custom_data_type(dtid) )
      return false;

    // Release reference of Python object
    Py_XDECREF(py_self);
    py_self = NULL;
    dtid = -1;
    return true;
  }

  ~py_custom_data_type_t()
  {
    unregister_dt();
  }
};
typedef std::map<int, py_custom_data_type_t *> py_custom_data_type_map_t;
static py_custom_data_type_map_t py_dt_map;

//------------------------------------------------------------------------
class py_custom_data_format_t
{
private:
  data_format_t df;
  int dfid;
  PyObject *py_self;
  qstring df_name, df_menu_name, df_hotkey;

  static bool idaapi s_print(       // convert to colored string
    void *ud,                       // user-defined data
    qstring *out,                   // output buffer. may be NULL
    const void *value,              // value to print. may not be NULL
    asize_t size,                   // size of value in bytes
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number
    int dtid)                       // custom data type id
  {
    PYW_GIL_GET;

    // Build a string from the buffer
    newref_t py_value(PyString_FromStringAndSize(
                              (const char *)value,
                              Py_ssize_t(size)));
    if ( py_value == NULL )
      return false;

    py_custom_data_format_t *_this = (py_custom_data_format_t *) ud;
    newref_t py_result(PyObject_CallMethod(
                               _this->py_self,
                               (char *)S_PRINTF,
                               "O" PY_FMT64 "ii",
                               py_value.o,
                               pyul_t(current_ea),
                               operand_num,
                               dtid));

    // Error while calling the function?
    if ( PyW_ShowCbErr(S_PRINTF) || py_result == NULL )
      return false;

    bool ok = false;
    if ( PyString_Check(py_result.o) )
    {
      Py_ssize_t len;
      char *buf;
      if ( out != NULL && PyString_AsStringAndSize(py_result.o, &buf, &len) != -1 )
      {
        out->qclear();
        out->append(buf, len);
      }
      ok = true;
    }
    return ok;
  }

  static bool idaapi s_scan(        // convert from uncolored string
    void *ud,                       // user-defined data
    bytevec_t *value,               // output buffer. may be NULL
    const char *input,              // input string. may not be NULL
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number (-1 if unknown)
    qstring *errstr)                // buffer for error message
  {
    PYW_GIL_GET;

    py_custom_data_format_t *_this = (py_custom_data_format_t *) ud;
    newref_t py_result(
            PyObject_CallMethod(
                    _this->py_self,
                    (char *)S_SCAN,
                    "s" PY_FMT64,
                    input,
                    pyul_t(current_ea),
                    operand_num));

    // Error while calling the function?
    if ( PyW_ShowCbErr(S_SCAN) || py_result == NULL)
      return false;

    bool ok = false;
    do
    {
      // We expect a tuple(bool, string|None)
      if ( !PyTuple_Check(py_result.o) || PyTuple_Size(py_result.o) != 2 )
        break;

      borref_t py_bool(PyTuple_GetItem(py_result.o, 0));
      borref_t py_val(PyTuple_GetItem(py_result.o, 1));

      // Get return code from Python
      ok = PyObject_IsTrue(py_bool.o);

      // We expect None or the value (depending on probe)
      if ( ok )
      {
        // Probe-only? Then okay, no need to extract the 'value'
        if ( value == NULL )
          break;

        Py_ssize_t len;
        char *buf;
        if ( PyString_AsStringAndSize(py_val.o, &buf, &len) != -1 )
        {
          value->qclear();
          value->append(buf, len);
        }
      }
      // An error occured?
      else
      {
        // Make sure the user returned (False, String)
        if ( py_bool.o != Py_False || !PyString_Check(py_val.o) )
        {
          *errstr = "Invalid return value returned from the Python callback!";
          break;
        }
        // Get the error message
        *errstr = PyString_AsString(py_val.o);
      }
    } while ( false );
    return ok;
  }

  static void idaapi s_analyze(     // analyze custom data format occurrence
    void *ud,                       // user-defined data
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num)                // current operand number
    // this callback can be used to create
    // xrefs from the current item.
    // this callback may be missing.
  {
    PYW_GIL_GET;

    py_custom_data_format_t *_this = (py_custom_data_format_t *) ud;
    newref_t py_result(
            PyObject_CallMethod(
                    _this->py_self,
                    (char *)S_ANALYZE,
                    PY_FMT64 "i",
                    pyul_t(current_ea),
                    operand_num));

    PyW_ShowCbErr(S_ANALYZE);
  }
public:
  py_custom_data_format_t()
  {
    dfid = -1;
    py_self = NULL;
  }

  const char *get_name() const
  {
    return df_name.c_str();
  }

  int register_df(int dtid, PyObject *py_obj)
  {
    // Already registered?
    if ( dfid >= 0 )
      return dfid;

    memset(&df, 0, sizeof(df));
    df.cbsize = sizeof(df);
    df.ud = this;

    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      ref_t py_attr;

      // name
      if ( !PyW_GetStringAttr(py_obj, S_NAME, &df_name) )
        break;
      df.name = df_name.c_str();

      // menu_name (optional)
      if ( PyW_GetStringAttr(py_obj, S_MENU_NAME, &df_menu_name) )
        df.menu_name = df_menu_name.c_str();

      // props
      py_attr = PyW_TryGetAttrString(py_obj, S_PROPS);
      if ( py_attr != NULL && PyInt_Check(py_attr.o) )
        df.props = PyInt_AsLong(py_attr.o);

      // hotkey
      if ( PyW_GetStringAttr(py_obj, S_HOTKEY, &df_hotkey) )
        df.hotkey = df_hotkey.c_str();

      // value_size
      py_attr = PyW_TryGetAttrString(py_obj, S_VALUE_SIZE);
      if ( py_attr != NULL && PyInt_Check(py_attr.o) )
        df.value_size = PyInt_AsLong(py_attr.o);

      // text_width
      py_attr = PyW_TryGetAttrString(py_obj, S_TEXT_WIDTH);
      if ( py_attr != NULL && PyInt_Check(py_attr.o) )
        df.text_width = PyInt_AsLong(py_attr.o);

      // print cb
      py_attr = PyW_TryGetAttrString(py_obj, S_PRINTF);
      if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
        df.print = s_print;

      // scan cb
      py_attr = PyW_TryGetAttrString(py_obj, S_SCAN);
      if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
        df.scan = s_scan;

      // analyze cb
      py_attr = PyW_TryGetAttrString(py_obj, S_ANALYZE);
      if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
        df.analyze = s_analyze;

      // Now try to register
      dfid = register_custom_data_format(dtid, &df);
      if ( dfid < 0 )
        break;

      // Hold reference to the PyObject
      Py_INCREF(py_obj);
      py_self = py_obj;

      // Update the format ID
      py_attr = newref_t(PyInt_FromLong(dfid));
      PyObject_SetAttrString(py_obj, S_ID, py_attr.o);
    } while ( false );
    return dfid;
  }

  bool unregister_df(int dtid)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    // Never registered?
    if ( dfid < 0 )
      return true;

    if ( !unregister_custom_data_format(dtid, dfid) )
      return false;

    // Release reference of Python object
    Py_XDECREF(py_self);
    py_self = NULL;
    dfid = -1;
    return true;
  }

  ~py_custom_data_format_t()
  {
  }
};

//------------------------------------------------------------------------
// Helper class to bind <dtid, dfid> pairs to py_custom_data_format_t
class py_custom_data_format_list_t
{
  struct py_custom_data_format_entry_t
  {
    int dtid;
    int dfid;
    py_custom_data_format_t *df;
  };
  typedef qvector<py_custom_data_format_entry_t> ENTRY;
  ENTRY entries;
public:
  typedef ENTRY::iterator POS;
  void add(int dtid, int dfid, py_custom_data_format_t *df)
  {
    py_custom_data_format_entry_t &e = entries.push_back();
    e.dtid = dtid;
    e.dfid = dfid;
    e.df   = df;
  }
  py_custom_data_format_t *find(int dtid, int dfid, POS *loc = NULL)
  {
    for ( POS it=entries.begin(), it_end = entries.end(); it!=it_end; ++it )
    {
      if ( it->dfid == dfid && it->dtid == dtid )
      {
        if ( loc != NULL )
          *loc = it;
        return it->df;
      }
    }
    return NULL;
  }
  void erase(POS &pos)
  {
    entries.erase(pos);
  }
};
static py_custom_data_format_list_t py_df_list;

//------------------------------------------------------------------------
static PyObject *py_data_type_to_py_dict(const data_type_t *dt)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  return Py_BuildValue("{s:" PY_FMT64 ",s:i,s:i,s:s,s:s,s:s,s:s}",
    S_VALUE_SIZE, pyul_t(dt->value_size),
    S_PROPS, dt->props,
    S_CBSIZE, dt->cbsize,
    S_NAME, dt->name == NULL ? "" : dt->name,
    S_MENU_NAME, dt->menu_name == NULL ? "" : dt->menu_name,
    S_HOTKEY, dt->hotkey == NULL ? "" : dt->hotkey,
    S_ASM_KEYWORD, dt->asm_keyword == NULL ? "" : dt->asm_keyword);
}

//------------------------------------------------------------------------
static PyObject *py_data_format_to_py_dict(const data_format_t *df)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  return Py_BuildValue("{s:i,s:i,s:i,s:" PY_FMT64 ",s:s,s:s,s:s}",
    S_PROPS, df->props,
    S_CBSIZE, df->cbsize,
    S_TEXT_WIDTH, df->text_width,
    S_VALUE_SIZE, pyul_t(df->value_size),
    S_NAME, df->name == NULL ? "" : df->name,
    S_MENU_NAME, df->menu_name == NULL ? "" : df->menu_name,
    S_HOTKEY, df->hotkey == NULL ? "" : df->hotkey);
}
//</code(py_bytes)>

//------------------------------------------------------------------------
//<inline(py_bytes)>

//------------------------------------------------------------------------
/*
#<pydoc>
def register_custom_data_type(dt):
    """
    Registers a custom data type.
    @param dt: an instance of the data_type_t class
    @return:
        < 0 if failed to register
        > 0 data type id
    """
    pass
#</pydoc>
*/
// Given a py.data_format_t object, this function will register a datatype
static int py_register_custom_data_type(PyObject *py_dt)
{
  py_custom_data_type_t *inst = new py_custom_data_type_t();
  int r = inst->register_dt(py_dt);
  if ( r < 0 )
  {
    delete inst;
    return r;
  }
  // Insert the instance to the map
  py_dt_map[r] = inst;
  return r;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def unregister_custom_data_type(dtid):
    """
    Unregisters a custom data type.
    @param dtid: the data type id
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_unregister_custom_data_type(int dtid)
{
  py_custom_data_type_map_t::iterator it = py_dt_map.find(dtid);

  // Maybe the user is trying to unregister a C api dt?
  if ( it == py_dt_map.end() )
    return unregister_custom_data_type(dtid);

  py_custom_data_type_t *inst = it->second;
  bool ok = inst->unregister_dt();

  // Perhaps it was automatically unregistered because the idb was close?
  if ( !ok )
  {
    // Is this type still registered with IDA?
    // If not found then mark the context for deletion
    ok = find_custom_data_type(inst->get_name()) < 0;
  }

  if ( ok )
  {
    py_dt_map.erase(it);
    delete inst;
  }
  return ok;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def register_custom_data_format(dtid, df):
    """
    Registers a custom data format with a given data type.
    @param dtid: data type id
    @param df: an instance of data_format_t
    @return:
        < 0 if failed to register
        > 0 data format id
    """
    pass
#</pydoc>
*/
static int py_register_custom_data_format(int dtid, PyObject *py_df)
{
  py_custom_data_format_t *inst = new py_custom_data_format_t();
  int r = inst->register_df(dtid, py_df);
  if ( r < 0 )
  {
    delete inst;
    return r;
  }
  // Insert the instance
  py_df_list.add(dtid, r, inst);
  return r;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def unregister_custom_data_format(dtid, dfid):
    """
    Unregisters a custom data format
    @param dtid: data type id
    @param dfid: data format id
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_unregister_custom_data_format(int dtid, int dfid)
{
  py_custom_data_format_list_t::POS pos;
  py_custom_data_format_t *inst = py_df_list.find(dtid, dfid, &pos);
  // Maybe the user is trying to unregister a C api data format?
  if ( inst == NULL )
    return unregister_custom_data_format(dtid, dfid);

  bool ok = inst->unregister_df(dtid);

  // Perhaps it was automatically unregistered because the type was unregistered?
  if ( !ok )
  {
    // Is this format still registered with IDA?
    // If not, mark the context for deletion
    ok = find_custom_data_format(inst->get_name()) < 0;
  }

  if ( ok )
  {
    py_df_list.erase(pos);
    delete inst;
  }
  return ok;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def get_custom_data_format(dtid, dfid):
    """
    Returns a dictionary populated with the data format values or None on failure.
    @param dtid: data type id
    @param dfid: data format id
    """
    pass
#</pydoc>
*/
// Get definition of a registered custom data format and returns a dictionary
static PyObject *py_get_custom_data_format(int dtid, int fid)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  const data_format_t *df = get_custom_data_format(dtid, fid);
  if ( df == NULL )
    Py_RETURN_NONE;
  return py_data_format_to_py_dict(df);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def get_custom_data_type(dtid):
    """
    Returns a dictionary populated with the data type values or None on failure.
    @param dtid: data type id
    """
    pass
#</pydoc>
*/
// Get definition of a registered custom data format and returns a dictionary
static PyObject *py_get_custom_data_type(int dtid)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  const data_type_t *dt = get_custom_data_type(dtid);
  if ( dt == NULL )
    Py_RETURN_NONE;
  return py_data_type_to_py_dict(dt);
}

//</inline(py_bytes)>

#endif
