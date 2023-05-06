#ifndef __PY_IDA_BYTES_CUSTDATA__
#define __PY_IDA_BYTES_CUSTDATA__

//<code(py_bytes_custdata)>

//-------------------------------------------------------------------------
class py_custom_data_type_t;
static qvector<py_custom_data_type_t *> py_custom_data_types;

//-------------------------------------------------------------------------
class py_custom_data_type_t : public data_type_t
{
  qstring dt_name, dt_menu_name, dt_hotkey, dt_asm_keyword;
  int dtid; // The data format id
  PyObject *py_self;

  // may create data? nullptr means always may
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
                    PY_BV_EA PY_BV_SZ,
                    bvea_t(ea),
                    bvsz_t(nbytes)));

    PyW_ShowCbErr(S_MAY_CREATE_AT);
    return py_result && PyObject_IsTrue(py_result.o);
  }

  // !=nullptr means variable size datatype
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
                    PY_BV_EA PY_BV_ASIZE,
                    bvea_t(ea),
                    bvasize_t(maxsize)));

    if ( PyW_ShowCbErr(S_CALC_ITEM_SIZE) || !py_result )
      return 0;

    uint64 num = 0;
    PyW_GetNumber(py_result.o, &num);
    return asize_t(num);
  }

public:
  py_custom_data_type_t(
          PyObject *py_dt,
          const char *name,
          asize_t value_size,
          const char *menu_name,
          const char *hotkey,
          const char *asm_keyword,
          int props)
  {
    memset(this, 0, sizeof(data_type_t));
    cbsize = sizeof(data_type_t);
    dt_name = name;
    dt_menu_name = menu_name;
    dt_hotkey = hotkey;
    dt_asm_keyword = asm_keyword;
    this->name = dt_name.begin();
    this->menu_name = dt_menu_name.begin();
    this->hotkey = dt_hotkey.begin();
    this->asm_keyword = dt_asm_keyword.begin();
    this->value_size = value_size;
    this->props = props;
    dtid = -1;
    py_custom_data_types.add_unique(this);
    py_self = py_dt;
  }

  ~py_custom_data_type_t()
  {
    do_unregister();
    py_custom_data_types.del(this);
  }

  int get_dtid() const { return dtid; }

  int do_register()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    // Already registered?
    if ( dtid >= 0 )
      return -1;

    ud = this;

    ref_t py_attr;

    // may_create_at
    py_attr = PyW_TryGetAttrString(py_self, S_MAY_CREATE_AT);
    if ( py_attr != nullptr && PyCallable_Check(py_attr.o) )
      may_create_at = s_may_create_at;

    // calc_item_size
    py_attr = PyW_TryGetAttrString(py_self, S_CALC_ITEM_SIZE);
    if ( py_attr != nullptr && PyCallable_Check(py_attr.o) )
      calc_item_size = s_calc_item_size;

    // Now try to register
    dtid = register_custom_data_type(this);
    if ( dtid >= 0 )
      Py_INCREF(py_self);
    return dtid;
  }

  bool do_unregister()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    bool ok = unregister_custom_data_type(dtid);
    if ( ok )
    {
      // when this is called at IDAPython-shutdown-time, this will cause the
      // dtor to be called, which in turn will call this 'do_unregister' a
      // second time, but this is no problem since the dtid has already been
      // unregistered and thus we won't end up in this Py_XDECREF block.
      dtid = -1; // modify the object now, otherwise it may get deleted
      Py_XDECREF(py_self);
    }
    return ok;
  }
};

//-------------------------------------------------------------------------
py_custom_data_type_t *py_custom_data_type_cast(data_type_t *inst)
{
  // The following code seems to not work with gcc. Compiler bug? Not sure, but no time ATM
  // py_custom_data_type_t *py_inst = (py_custom_data_type_t *) inst;
  // py_custom_data_types.has(py_inst) ? py_inst : nullptr;
  if ( py_custom_data_types.has((py_custom_data_type_t *) inst) )
    return (py_custom_data_type_t *) inst;
  else
    return 0;
}

//-------------------------------------------------------------------------
static int py_custom_data_type_t_get_id(data_type_t *_dt)
{
  py_custom_data_type_t *dt = py_custom_data_type_cast(_dt);
  return dt != nullptr ? dt->get_dtid() : -1;
}

//-------------------------------------------------------------------------
//                              data_format_t
//-------------------------------------------------------------------------
class py_custom_data_format_t;
static qvector<py_custom_data_format_t *> py_custom_data_formats;

//-------------------------------------------------------------------------
class py_custom_data_format_t : public data_format_t
{
private:
  int dfid;
  PyObject *py_self;
  qstring df_name, df_menu_name, df_hotkey;

  static bool idaapi s_print(           // convert to colored string
        void *ud,                       // user-defined data
        qstring *out,                   // output buffer. may be nullptr
        const void *value,              // value to print. may not be nullptr
        asize_t size,                   // size of value in bytes
        ea_t current_ea,                // current address (BADADDR if unknown)
        int operand_num,                // current operand number
        int dtid)                       // custom data type id
  {
    PYW_GIL_GET;

    // Build a string from the buffer
    newref_t py_value(PyBytes_FromStringAndSize(
                              (const char *)value,
                              Py_ssize_t(size)));
    if ( !py_value )
      return false;

    py_custom_data_format_t *_this = (py_custom_data_format_t *) ud;
    newref_t py_result(PyObject_CallMethod(
                               _this->py_self,
                               (char *)S_PRINTF,
                               "O" PY_BV_EA "ii",
                               py_value.o,
                               bvea_t(current_ea),
                               operand_num,
                               dtid));

    // Error while calling the function?
    if ( PyW_ShowCbErr(S_PRINTF) || !py_result )
      return false;

    bool ok = false;
    if ( PyUnicode_Check(py_result.o) )
    {
      if ( out != nullptr )
        PyUnicode_as_qstring(out, py_result.o);
      ok = true;
    }
    return ok;
  }

  static bool idaapi s_scan(            // convert from uncolored string
        void *ud,                       // user-defined data
        bytevec_t *value,               // output buffer. may be nullptr
        const char *input,              // input string. may not be nullptr
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
                    "s" PY_BV_EA "i",
                    input,
                    bvea_t(current_ea),
                    operand_num));

    // Error while calling the function?
    if ( PyW_ShowCbErr(S_SCAN) || !py_result )
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
      ok = PyObject_IsTrue(py_bool.o) != 0;

      // We expect None or the value (depending on probe)
      if ( ok )
      {
        // Probe-only? Then okay, no need to extract the 'value'
        if ( value == nullptr )
          break;

        Py_ssize_t len;
        char *buf;
        if ( PyBytes_AsStringAndSize(py_val.o, &buf, &len) != -1 )
        {
          value->qclear();
          value->append(buf, len);
        }
      }
      // An error occurred?
      else
      {
        // Make sure the user returned (False, String)
        if ( py_bool.o != Py_False || !PyUnicode_Check(py_val.o) )
        {
          *errstr = "Invalid return value returned from the Python callback!";
          break;
        }
        // Get the error message
        PyUnicode_as_qstring(errstr, py_val.o);
      }
    } while ( false );
    return ok;
  }

  static void idaapi s_analyze(         // analyze custom data format occurrence
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
                    PY_BV_EA "i",
                    bvea_t(current_ea),
                    operand_num));

    PyW_ShowCbErr(S_ANALYZE);
  }
public:
  py_custom_data_format_t(
        PyObject *py_df,
        const char *name,
        asize_t value_size,
        const char *menu_name,
        int props,
        const char *hotkey,
        int32 text_width)
  {
    memset(this, 0, sizeof(data_format_t));
    cbsize = sizeof(data_format_t);
    df_name = name;
    df_menu_name = menu_name;
    df_hotkey = hotkey;
    this->name = df_name.begin();
    this->menu_name = df_menu_name.begin();
    this->hotkey = df_hotkey.begin();
    this->value_size = value_size;
    this->props = props;
    this->text_width = text_width;
    dfid = -1;
    py_custom_data_formats.add_unique(this);
    py_self = py_df;
  }

  ~py_custom_data_format_t()
  {
    do_unregister();
    py_custom_data_formats.del(this);
  }

  int get_dfid() const { return dfid; }

  int do_register()
  {
    // Already registered?
    if ( dfid >= 0 )
      return -1;

    ud = this;

    PYW_GIL_CHECK_LOCKED_SCOPE();
    ref_t py_attr;

    // print cb
    py_attr = PyW_TryGetAttrString(py_self, S_PRINTF);
    if ( py_attr != nullptr && PyCallable_Check(py_attr.o) )
      print = s_print;

    // scan cb
    py_attr = PyW_TryGetAttrString(py_self, S_SCAN);
    if ( py_attr != nullptr && PyCallable_Check(py_attr.o) )
      scan = s_scan;

    // analyze cb
    py_attr = PyW_TryGetAttrString(py_self, S_ANALYZE);
    if ( py_attr != nullptr && PyCallable_Check(py_attr.o) )
      analyze = s_analyze;

    // Now try to register
    dfid = register_custom_data_format(this);
    if ( dfid >= 0 )
      Py_INCREF(py_self);
    return dfid;
  }

  bool do_unregister()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    bool ok = unregister_custom_data_format(dfid);
    if ( ok )
    {
      // see comment in py_custom_data_type_t::do_unregister()
      dfid = -1;
      Py_XDECREF(py_self);
    }
    return ok;
  }
};

//-------------------------------------------------------------------------
py_custom_data_format_t *py_custom_data_format_cast(data_format_t *inst)
{
  if ( py_custom_data_formats.has((py_custom_data_format_t *) inst) )
    return (py_custom_data_format_t *) inst;
  else
    return 0;
}

//-------------------------------------------------------------------------
static int py_custom_data_format_t_get_id(data_format_t *_df)
{
  py_custom_data_format_t *df = py_custom_data_format_cast(_df);
  return df != nullptr ? df->get_dfid() : -1;
}

//-------------------------------------------------------------------------
static void clear_custom_data_types_and_formats()
{
  PYW_GIL_GET;
  for ( ssize_t i=py_custom_data_types.size()-1; i >= 0; --i )
    py_custom_data_types[i]->do_unregister();
  for ( ssize_t i=py_custom_data_formats.size()-1; i >= 0; --i )
    py_custom_data_formats[i]->do_unregister();
}
//</code(py_bytes_custdata)>

//------------------------------------------------------------------------
//<inline(py_bytes_custdata)>

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
// Given a py_data_type_t object, this function will register a datatype
static int py_register_custom_data_type(PyObject *py_dt)
{
  ref_t py_attr = PyW_TryGetAttrString(py_dt, "this");
  if ( py_attr == nullptr )
    return -1;

  py_custom_data_type_t *inst = nullptr;
  int cvt = SWIG_ConvertPtr(py_attr.o, (void **) &inst, SWIGTYPE_p_data_type_t, 0);
  if ( !SWIG_IsOK(cvt) || py_custom_data_type_cast(inst) == nullptr )
    return -1;
  return inst->do_register();
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
  const data_type_t *_dt = get_custom_data_type(dtid);
  if ( _dt == nullptr )
    return false;

  py_custom_data_type_t *dt = py_custom_data_type_cast((data_type_t *) _dt);
  bool ok = dt != nullptr;
  if ( ok )
    ok = dt->do_unregister();
  else
    ok = unregister_custom_data_type(dtid); // C API dt
  return ok;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def register_custom_data_format(df):
    """
    Registers a custom data format with a given data type.
    @param df: an instance of data_format_t
    @return:
        < 0 if failed to register
        > 0 data format id
    """
    pass
#</pydoc>
*/
static int py_register_custom_data_format(PyObject *py_df)
{
  ref_t py_attr = PyW_TryGetAttrString(py_df, "this");
  if ( py_attr == nullptr )
    return -1;

  py_custom_data_format_t *inst = nullptr;
  int cvt = SWIG_ConvertPtr(py_attr.o, (void **) &inst, SWIGTYPE_p_data_format_t, 0);
  if ( !SWIG_IsOK(cvt) || py_custom_data_format_cast(inst) == nullptr )
    return -1;

  return inst->do_register();
}

//------------------------------------------------------------------------
/*
#<pydoc>
def unregister_custom_data_format(dfid):
    """
    Unregisters a custom data format
    @param dfid: data format id
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_unregister_custom_data_format(int dfid)
{
  const data_format_t *_df = get_custom_data_format(dfid);
  if ( _df == nullptr )
    return false;

  py_custom_data_format_t *df = py_custom_data_format_cast((data_format_t *) _df);
  bool ok = df != nullptr;
  if ( ok )
    ok = df->do_unregister();
  else
    ok = unregister_custom_data_format(dfid); // C API df
  return ok;
}

//</inline(py_bytes_custdata)>

#endif // __PY_IDA_BYTES_CUSTDATA__
