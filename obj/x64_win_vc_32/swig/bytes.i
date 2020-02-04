%module(docstring="IDA Plugin SDK API wrapper: bytes",directors="1",threads="1") ida_bytes
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_BYTES
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_BYTES
  #define HAS_DEP_ON_INTERFACE_BYTES
#endif
#ifndef HAS_DEP_ON_INTERFACE_RANGE
  #define HAS_DEP_ON_INTERFACE_RANGE
#endif
%include "header.i"
%{
#include <bytes.hpp>
%}

%import "range.i"

// Unexported and kernel-only declarations
%ignore testf_t;
%ignore next_that;
%ignore prev_that;
%ignore adjust_visea;
%ignore prev_visea;
%ignore next_visea;
%ignore visit_patched_bytes;
%ignore is_first_visea;
%ignore is_last_visea;
%ignore is_visible_finally;
%ignore setFlbits;
%ignore clrFlbits;
%ignore get_ascii_char;
%ignore del_opinfo;
%ignore del_one_opinfo;
%ignore get_repeatable_cmt;
%ignore get_any_indented_cmt;
%ignore del_code_comments;
%ignore coagulate;

%ignore FlagsInit;
%ignore FlagsTerm;
%ignore FlagsReset;
%ignore flush_flags;
%ignore get_flags_linput;
%ignore data_type_t::data_type_t();
%ignore data_type_t::cbsize;
%ignore data_type_t::ud;
%ignore data_type_t::may_create_at;
%ignore data_type_t::calc_item_size;
%ignore data_format_t::data_format_t();
%ignore data_format_t::cbsize;
%ignore data_format_t::ud;
%ignore data_format_t::print;
%ignore data_format_t::scan;
%ignore data_format_t::analyze;

%ignore get_bytes;
%ignore get_strlit_contents;
%ignore get_hex_string;
%ignore bin_search2;
%ignore bin_search; // we redefine our own, w/ 2 params swapped, so we can apply the typemaps below
%rename (bin_search) py_bin_search;

%ignore get_8bit;
%rename (get_8bit) py_get_8bit;

%ignore get_octet;
%rename (get_octet) py_get_octet;

%ignore compiled_binpat_t;
%ignore compiled_binpat_vec_t;
%ignore parse_binpat_str;

// TODO: This could be fixed (if needed)
%ignore set_dbgmem_source;

%typemap(argout) opinfo_t *buf {
  if ( result != NULL )
  {
    // kludge: discard newly-constructed object; return input
    Py_XDECREF($result);
    $result = $input;
    Py_INCREF($result);
  }
}

%ignore unregister_custom_data_format;
%rename (unregister_custom_data_format) py_unregister_custom_data_format;
%ignore register_custom_data_format;
%rename (register_custom_data_format) py_register_custom_data_format;
%ignore unregister_custom_data_type;
%rename (unregister_custom_data_type) py_unregister_custom_data_type;
%ignore register_custom_data_type;
%rename (register_custom_data_type) py_register_custom_data_type;
%ignore print_strlit_type;
%rename (print_strlit_type) py_print_strlit_type;

%{
//<code(py_bytes)>
//------------------------------------------------------------------------
static bool idaapi py_testf_cb(flags_t flags, void *ud)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_flags(PyLong_FromUnsignedLong(flags));
  newref_t result(PyObject_CallFunctionObjArgs((PyObject *) ud, py_flags.o, NULL));
  return result != NULL && PyObject_IsTrue(result.o);
}

//------------------------------------------------------------------------
// Wraps the (next|prev)that()
static ea_t py_npthat(ea_t ea, ea_t bound, PyObject *py_callable, bool next)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCallable_Check(py_callable) )
    return BADADDR;
  else
    return (next ? next_that : prev_that)(ea, bound, py_testf_cb, py_callable);
}

//---------------------------------------------------------------------------
static int idaapi py_visit_patched_bytes_cb(
        ea_t ea,
        qoff64_t fpos,
        uint64 o,
        uint64 v,
        void *ud)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_result(
          PyObject_CallFunction(
                  (PyObject *)ud,
                  PY_BV_EA "LKK",
                  bvea_t(ea),
                  fpos,
                  o,
                  v));
  PyW_ShowCbErr("visit_patched_bytes");
  return (py_result != NULL && IDAPyInt_Check(py_result.o)) ? IDAPyInt_AsLong(py_result.o) : 0;
}

//-------------------------------------------------------------------------
static void ida_bytes_term(void) {}

//-------------------------------------------------------------------------
static void clear_custom_data_types_and_formats();
static void ida_bytes_closebase(void)
{
  clear_custom_data_types_and_formats();
}

//-------------------------------------------------------------------------
static bool py_do_get_bytes(
        PyObject **out_py_bytes,
        PyObject **out_py_mask,
        ea_t ea,
        unsigned int size,
        int gmb_flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool has_mask = out_py_mask != NULL;
  do
  {
    if ( size <= 0 )
      break;

    // Allocate memory via Python
    newref_t py_bytes(IDAPyStr_FromUTF8AndSize(NULL, Py_ssize_t(size)));
    if ( py_bytes == NULL )
      break;

    bytevec_t mask;
    if ( has_mask )
      mask.resize((size + 7) / 8, 0);

    // Read bytes
    int code = get_bytes(IDAPyBytes_AsString(py_bytes.o),
                         size,
                         ea,
                         gmb_flags,
                         has_mask ? mask.begin() : NULL);
    if ( code < 0 )
      break;

    // note: specify size, as '0' bytes would otherwise cut the mask short
    if ( has_mask )
    {
      newref_t py_mask(IDAPyStr_FromUTF8AndSize(
                               (const char *) mask.begin(),
                               mask.size()));
      if ( py_mask == NULL )
        break;
      py_mask.incref();
      *out_py_mask = py_mask.o;
    }

    py_bytes.incref();
    *out_py_bytes = py_bytes.o;
    return true;
  } while ( false );
  return false;
}

//</code(py_bytes)>
%}

%{
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
                    PY_BV_EA PY_BV_SZ,
                    bvea_t(ea),
                    bvsz_t(nbytes)));

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
                    PY_BV_EA PY_BV_ASIZE,
                    bvea_t(ea),
                    bvasize_t(maxsize)));

    if ( PyW_ShowCbErr(S_CALC_ITEM_SIZE) || py_result == NULL )
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
    if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
      may_create_at = s_may_create_at;

    // calc_item_size
    py_attr = PyW_TryGetAttrString(py_self, S_CALC_ITEM_SIZE);
    if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
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
      Py_XDECREF(py_self);
      dtid = -1;
    }
    return ok;
  }
};

//-------------------------------------------------------------------------
py_custom_data_type_t *py_custom_data_type_cast(data_type_t *inst)
{
  // The following code seems to not work with gcc. Compiler bug? Not sure, but no time ATM
  // py_custom_data_type_t *py_inst = (py_custom_data_type_t *) inst;
  // py_custom_data_types.has(py_inst) ? py_inst : NULL;
  if ( py_custom_data_types.has((py_custom_data_type_t *) inst) )
    return (py_custom_data_type_t *) inst;
  else
    return 0;
}

//-------------------------------------------------------------------------
static int py_custom_data_type_t_get_id(data_type_t *_dt)
{
  py_custom_data_type_t *dt = py_custom_data_type_cast(_dt);
  return dt != NULL ? dt->get_dtid() : -1;
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

  static bool idaapi s_print(             // convert to colored string
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
    newref_t py_value(IDAPyStr_FromUTF8AndSize(
                              (const char *)value,
                              Py_ssize_t(size)));
    if ( py_value == NULL )
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
    if ( PyW_ShowCbErr(S_PRINTF) || py_result == NULL )
      return false;

    bool ok = false;
    if ( IDAPyStr_Check(py_result.o) )
    {
      Py_ssize_t len;
      char *buf;
      if ( out != NULL && IDAPyBytes_AsMemAndSize(py_result.o, &buf, &len) != -1 )
      {
        out->qclear();
        out->append(buf, len);
      }
      ok = true;
    }
    return ok;
  }

  static bool idaapi s_scan(              // convert from uncolored string
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
                    "s" PY_BV_EA "i",
                    input,
                    bvea_t(current_ea),
                    operand_num));

    // Error while calling the function?
    if ( PyW_ShowCbErr(S_SCAN) || py_result == NULL )
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
        if ( IDAPyBytes_AsMemAndSize(py_val.o, &buf, &len) != -1 )
        {
          value->qclear();
          value->append(buf, len);
        }
      }
      // An error occurred?
      else
      {
        // Make sure the user returned (False, String)
        if ( py_bool.o != Py_False || !IDAPyStr_Check(py_val.o) )
        {
          *errstr = "Invalid return value returned from the Python callback!";
          break;
        }
        // Get the error message
        *errstr = IDAPyBytes_AsString(py_val.o);
      }
    } while ( false );
    return ok;
  }

  static void idaapi s_analyze(           // analyze custom data format occurrence
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
    if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
      print = s_print;

    // scan cb
    py_attr = PyW_TryGetAttrString(py_self, S_SCAN);
    if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
      scan = s_scan;

    // analyze cb
    py_attr = PyW_TryGetAttrString(py_self, S_ANALYZE);
    if ( py_attr != NULL && PyCallable_Check(py_attr.o) )
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
      Py_XDECREF(py_self);
      dfid = -1;
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
  return df != NULL ? df->get_dfid() : -1;
}

//-------------------------------------------------------------------------
static void clear_custom_data_types_and_formats()
{
  PYW_GIL_GET;
  for ( size_t n = py_custom_data_types.size(); n > 0; --n )
    py_custom_data_types[n-1]->do_unregister();
  for ( size_t n = py_custom_data_formats.size(); n > 0; --n )
    py_custom_data_formats[n-1]->do_unregister();
}
//</code(py_bytes_custdata)>
%}

%extend data_type_t
{
  data_type_t(
          PyObject *self,
          const char *name,
          asize_t value_size=0,
          const char *menu_name=NULL,
          const char *hotkey=NULL,
          const char *asm_keyword=NULL,
          int props=0)
  {
    py_custom_data_type_t *inst = new py_custom_data_type_t(
            self,
            name,
            value_size,
            menu_name,
            hotkey,
            asm_keyword,
            props);
    return inst;
  }

  ~data_type_t()
  {
    delete (py_custom_data_type_t *) $self;
  }

  int __get_id() { return py_custom_data_type_t_get_id($self); }

  %pythoncode
  {
    id = property(__get_id)
    __real__init__ = __init__
    def __init__(self, *args):
        self.__real__init__(self, *args) # pass 'self' as part of args
#ifdef BC695
    if _BC695:
        def __init__(self, name, value_size = 0, menu_name = None, hotkey = None, asm_keyword = None, props = 0):
            args = (name, value_size, menu_name, hotkey, asm_keyword, props)
            self.__real__init__(self, *args) # pass 'self' as part of args
#endif
  }
}

%extend data_format_t
{
  data_format_t(
          PyObject *self,
          const char *name,
          asize_t value_size=0,
          const char *menu_name=NULL,
          int props=0,
          const char *hotkey=NULL,
          int32 text_width=0)
  {
    py_custom_data_format_t *inst = new py_custom_data_format_t(
            self,
            name,
            value_size,
            menu_name,
            props,
            hotkey,
            text_width);
    return inst;
  }

  ~data_format_t()
  {
    delete (py_custom_data_format_t *) $self;
  }

  int __get_id() { return py_custom_data_format_t_get_id($self); }

  %pythoncode
  {
    id = property(__get_id)
    __real__init__ = __init__
    def __init__(self, *args):
        self.__real__init__(self, *args) # pass 'self' as part of args
#ifdef BC695
    if _BC695:
        def __init__(self, name, value_size = 0, menu_name = None, props = 0, hotkey = None, text_width = 0):
            args = (name, value_size, menu_name, props, hotkey, text_width)
            self.__real__init__(self, *args) # pass 'self' as part of args
#endif
  }
}

//<typemaps(bytes)>
%typemap(check) (rangeset_t  * zranges, const  range_t  * range)
{
if ( $1 == NULL )
  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$1_type'");
}
%typemap(check) (opinfo_t  * buf, ea_t ea, int n, flags_t flags)
{
if ( $1 == NULL )
  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$1_type'");
}
//</typemaps(bytes)>

%include "bytes.hpp"

%apply (char *STRING, int LENGTH) { (const uchar *image, size_t len) };
%apply (char *) { (const uchar *mask) };

%clear(void *buf, ssize_t size);

%clear(const void *buf, size_t size);
%clear(void *buf, ssize_t size);
%clear(opinfo_t *);

%rename (visit_patched_bytes) py_visit_patched_bytes;
%rename (next_that) py_next_that;
%rename (prev_that) py_prev_that;

%rename (get_bytes) py_get_bytes;
%rename (get_bytes_and_mask) py_get_bytes_and_mask;
%rename (get_strlit_contents) py_get_strlit_contents;

%inline %{
//<inline(py_bytes)>

//------------------------------------------------------------------------
/*
#<pydoc>
def visit_patched_bytes(ea1, ea2, callable):
    """
    Enumerates patched bytes in the given range and invokes a callable
    @param ea1: start address
    @param ea2: end address
    @param callable: a Python callable with the following prototype:
                     callable(ea, fpos, org_val, patch_val).
                     If the callable returns non-zero then that value will be
                     returned to the caller and the enumeration will be
                     interrupted.
    @return: Zero if the enumeration was successful or the return
             value of the callback if enumeration was interrupted.
    """
    pass
#</pydoc>
*/
static int py_visit_patched_bytes(ea_t ea1, ea_t ea2, PyObject *py_callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCallable_Check(py_callable) )
    return 0;
  else
    return visit_patched_bytes(ea1, ea2, py_visit_patched_bytes_cb, py_callable);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def next_that(ea, maxea, callable):
    """
    Find next address with a flag satisfying the function 'testf'.
    Start searching from address 'ea'+1 and inspect bytes up to 'maxea'.
    maxea is not included in the search range.

    @param callable: a Python callable with the following prototype:
                     callable(flags). Return True to stop enumeration.
    @return: the found address or BADADDR.
    """
    pass
#</pydoc>
*/
static ea_t py_next_that(ea_t ea, ea_t maxea, PyObject *callable)
{
  return py_npthat(ea, maxea, callable, true);
}

//---------------------------------------------------------------------------
static ea_t py_prev_that(ea_t ea, ea_t minea, PyObject *callable)
{
  return py_npthat(ea, minea, callable, false);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def get_bytes(ea, size):
    """
    Get the specified number of bytes of the program.
    @param ea: program address
    @param size: number of bytes to return
    @return: the bytes (as a str), or None in case of failure
    """
    pass
#</pydoc>
*/
static PyObject *py_get_bytes(ea_t ea, unsigned int size, int gmb_flags=GMB_READALL)
{
  PyObject *py_bytes = NULL;
  if ( py_do_get_bytes(&py_bytes, NULL, ea, size, gmb_flags) )
    return py_bytes;
  else
    Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
/*
#<pydoc>
def get_bytes_and_mask(ea, size, mask):
    """
    Get the specified number of bytes of the program, and a bitmask
    specifying what bytes are defined and what bytes are not.
    @param ea: program address
    @param size: number of bytes to return
    @return: a tuple (bytes, mask), or None in case of failure.
             Both 'bytes' and 'mask' are 'str' instances.
    """
    pass
#</pydoc>
*/
static PyObject *py_get_bytes_and_mask(ea_t ea, unsigned int size, int gmb_flags=GMB_READALL)
{
  PyObject *py_bytes = NULL;
  PyObject *py_mask = NULL;
  if ( py_do_get_bytes(&py_bytes, &py_mask, ea, size, gmb_flags) )
    return Py_BuildValue("(OO)", py_bytes, py_mask);
  else
    Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
/*
#<pydoc>
# Conversion options for get_strlit_contents():
STRCONV_ESCAPE   = 0x00000001 # convert non-printable characters to C escapes (\n, \xNN, \uNNNN)

def get_strlit_contents(ea, len, type, flags = 0):
  """
  Get bytes contents at location, possibly converted.
  It works even if the string has not been created in the database yet.

  Note that this will <b>always</b> return a simple string of bytes
  (i.e., a 'str' instance), and not a string of unicode characters.

  If you want auto-conversion to unicode strings (that is: real strings),
  you should probably be using the idautils.Strings class.

  @param ea: linear address of the string
  @param len: length of the string in bytes (including terminating 0)
  @param type: type of the string. Represents both the character encoding,
               <u>and</u> the 'type' of string at the given location.
  @param flags: combination of STRCONV_..., to perform output conversion.
  @return: a bytes-filled str object.
  """
  pass
#</pydoc>
*/
static PyObject *py_get_strlit_contents(
        ea_t ea,
        PyObject *py_len,
        int32 type,
        int flags = 0)
{
  uint64 len;
  if ( !PyW_GetNumber(py_len, &len) )
    Py_RETURN_NONE;
  if ( len == BADADDR )
    len = uint64(-1);
  qstring buf;
  if ( len != uint64(-1) && ea_t(ea + len) < ea
    || get_strlit_contents(&buf, ea, len, type, NULL, flags) < 0 )
  {
    Py_RETURN_NONE;
  }
  if ( type == STRTYPE_C && buf.length() > 0 && buf.last() == '\0' )
    buf.remove_last();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_buf(IDAPyStr_FromUTF8AndSize(buf.begin(), buf.length()));
  py_buf.incref();
  return py_buf.o;
}

//-------------------------------------------------------------------------
static ea_t py_bin_search(
        ea_t start_ea,
        ea_t end_ea,
        const uchar *image,
        size_t len,
        const uchar *mask,
        int step,
        int flags)
{
  if ( step != /* old value of BIN_SEARCH_FORWARD*/ 1
    && step != /* new value of BIN_SEARCH_FORWARD */ 0 )
  {
    flags |= BIN_SEARCH_BACKWARD;
  }
  bytevec_t lmask;
  if ( mask != NULL )
  {
    if ( *mask == 0xFF )
    {
      // a value of '0xFF' in the first byte meant "all bytes defined". We
      // can thus turn that into a NULL mask.
      mask = NULL;
    }
    else
    {
      // some bytes defined, some bytes aren't. Those that are have a value
      // 1 in the mask. We must turn them into 0xFF's
      lmask.resize(len);
      for ( size_t i = 0; i < len; ++i )
        lmask[i] = mask[i] != 0 ? 0xFF : 0;
      mask = lmask.begin();
    }
  }
  return bin_search2(start_ea, end_ea, image, mask, len, flags);
}

//-------------------------------------------------------------------------
static PyObject *py_print_strlit_type(int32 strtype, int flags=0)
{
  qstring s, t;
  if ( !print_strlit_type(&s, strtype, &t, flags) )
    Py_RETURN_NONE;
  return Py_BuildValue("(ss)", s.c_str(), t.c_str());
}

//-------------------------------------------------------------------------
static PyObject *py_get_octet(ea_t ea, uint64 v, int nbit)
{
  uchar octet = get_octet(&ea, &v, &nbit);
  return Py_BuildValue("(i" PY_BV_EA "Ki)", int(uint32(octet)), bvea_t(ea), v, nbit);
}

//-------------------------------------------------------------------------
static PyObject *py_get_8bit(ea_t ea, uint32 v, int nbit)
{
  uchar octet = get_8bit(&ea, &v, &nbit);
  return Py_BuildValue("(i" PY_BV_EA "ki)", int(uint32(octet)), bvea_t(ea), v, nbit);
}
//</inline(py_bytes)>
%}

%pythoncode %{
#<pycode(py_bytes)>
#</pycode(py_bytes)>
%}

%inline %{
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
  if ( py_attr == NULL )
    return -1;

  py_custom_data_type_t *inst = NULL;
  int cvt = SWIG_ConvertPtr(py_attr.o, (void **) &inst, SWIGTYPE_p_data_type_t, 0);
  if ( !SWIG_IsOK(cvt) || py_custom_data_type_cast(inst) == NULL )
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
  if ( _dt == NULL )
    return false;

  py_custom_data_type_t *dt = py_custom_data_type_cast((data_type_t *) _dt);
  bool ok = dt != NULL;
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
  if ( py_attr == NULL )
    return -1;

  py_custom_data_format_t *inst = NULL;
  int cvt = SWIG_ConvertPtr(py_attr.o, (void **) &inst, SWIGTYPE_p_data_format_t, 0);
  if ( !SWIG_IsOK(cvt) || py_custom_data_format_cast(inst) == NULL )
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
  if ( _df == NULL )
    return false;

  py_custom_data_format_t *df = py_custom_data_format_cast((data_format_t *) _df);
  bool ok = df != NULL;
  if ( ok )
    ok = df->do_unregister();
  else
    ok = unregister_custom_data_format(dfid); // C API df
  return ok;
}

//</inline(py_bytes_custdata)>
%}

%pythoncode %{
#<pycode(py_bytes_custdata)>
DTP_NODUP = 0x0001
# -----------------------------------------------------------------------
def __walk_types_and_formats(formats, type_action, format_action, installing):
    broken = False
    for f in formats:
        if len(f) == 1:
            if not format_action(f[0], 0):
                broken = True
                break
        else:
            dt  = f[0]
            dfs = f[1:]
            # install data type before installing formats
            if installing and not type_action(dt):
                broken = True
                break
            # process formats using the correct dt.id
            for df in dfs:
                if not format_action(df, dt.id):
                    broken = True
                    break
            # uninstall data type after uninstalling formats
            if not installing and not type_action(dt):
                broken = True
                break
    return not broken

# -----------------------------------------------------------------------
def register_data_types_and_formats(formats):
    """
    Registers multiple data types and formats at once.
    To register one type/format at a time use register_custom_data_type/register_custom_data_format

    It employs a special table of types and formats described below:

    The 'formats' is a list of tuples. If a tuple has one element then it is the format to be registered with dtid=0
    If the tuple has more than one element, then tuple[0] is the data type and tuple[1:] are the data formats. For example:
    many_formats = [
      (pascal_data_type(), pascal_data_format()),
      (simplevm_data_type(), simplevm_data_format()),
      (makedword_data_format(),),
      (simplevm_data_format(),)
    ]
    The first two tuples describe data types and their associated formats.
    The last two tuples describe two data formats to be used with built-in data types.
    The data format may be attached to several data types. The id of the
    data format is stored in the first data_format_t object. For example:
    assert many_formats[1][1] != -1
    assert many_formats[2][0] != -1
    assert many_formats[3][0] == -1
    """
    def __reg_format(df, dtid):
        dfid = register_custom_data_format(df);
        if dfid == -1:
            dfid = find_custom_data_format(df.name);
            if dfid == -1:
              return False
        attach_custom_data_format(dtid, dfid)
        if dtid == 0:
            print("Registered format '%s' with built-in types, ID=%d" % (df.name, dfid))
        else:
            print("   Registered format '%s', ID=%d (dtid=%d)" % (df.name, dfid, dtid))
        return True

    def __reg_type(dt):
        register_custom_data_type(dt)
        print("Registered type '%s', ID=%d" % (dt.name, dt.id))
        return dt.id != -1
    ok = __walk_types_and_formats(formats, __reg_type, __reg_format, True)
    return 1 if ok else -1

# -----------------------------------------------------------------------
def unregister_data_types_and_formats(formats):
    """As opposed to register_data_types_and_formats(), this function
    unregisters multiple data types and formats at once.
    """
    def __unreg_format(df, dtid):
        print("%snregistering format '%s'" % ("U" if dtid == 0 else "   u", df.name))
        unregister_custom_data_format(df.id)
        return True

    def __unreg_type(dt):
        print("Unregistering type '%s', ID=%d" % (dt.name, dt.id))
        unregister_custom_data_type(dt.id)
        return True
    ok = __walk_types_and_formats(formats, __unreg_type, __unreg_format, False)
    return 1 if ok else -1

#--------------------------------------------------------------------------
#
#
#<pydoc>
#class data_type_t(object):
#    """
#    The following optional callback methods can be implemented
#    in a data_type_t subclass
#    """
#
#    def may_create_at(ea, nbytes):
#        """May create data?
#        No such callback means: always succeed (i.e., no restriction where
#        such a data type can be created.)
#        @param ea: candidate address for the data item
#        @param nbytes: candidate size for the data item
#        @return: True/False
#        """
#        return True
#
#    def calc_item_size(ea, maxsize):
#        """This callback is used to determine size of the (possible)
#        item at `ea`.
#        No such callback means that datatype is of fixed size `value_size`.
#        (thus, this callback is required only for varsize datatypes.)
#        @param ea: address of the item
#        @param maxsize: maximum size of the item
#        @return: 0 - no such item can be created/displayed
#        """
#        return 0
#
#
#class data_format_t(object):
#    """
#    The following callback methods can be implemented
#    in a data_format_t subclass
#    """
#
#    def printf(value, current_ea, operand_num, dtid):
#        """Convert `value` to colored string using custom format.
#        @param value: value to print (of type 'str', sequence of bytes)
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number
#        @param dtid: custom data type id
#        @return: string representing data
#        """
#        return None
#
#    def scan(input, current_ea, operand_num):
#        """Convert uncolored string (user input) to the value.
#        This callback is called from the debugger when an user enters a
#        new value for a register with a custom data representation (e.g.,
#        an MMX register.)
#        @param input: input string
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number (-1 if unknown)
#        @return: tuple(bool, string)
#                 (True, output value) or
#                 (False, error message)
#        """
#        return (False, "Not implemented")
#
#    def analyze(current_ea, operand_num):
#        """Analyze custom data format occurrence.
#        This callback is called in 2 cases:
#        - after emulating an instruction (after a call of
#          'ev_emu_insn') if its operand is marked as "custom data
#          representation"
#        - when emulating data (this is done using a call of
#          'ev_out_data' with analyze_only == true). This is the right
#          place to create cross references from the current item.
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number
#        """
#        pass
#
#
#</pydoc>
#</pycode(py_bytes_custdata)>
%}
%pythoncode %{
if _BC695:
    ACFOPT_ASCII=0
    ACFOPT_CONVMASK=0
    ACFOPT_ESCAPE=STRCONV_ESCAPE
    ACFOPT_UTF16=0
    ACFOPT_UTF8=0
    DOUNK_DELNAMES=DELIT_DELNAMES
    DOUNK_EXPAND=DELIT_EXPAND
    DOUNK_NOTRUNC=DELIT_NOTRUNC
    DOUNK_SIMPLE=DELIT_SIMPLE
    FF_ASCI=FF_STRLIT
    FF_DWRD=FF_DWORD
    FF_OWRD=FF_OWORD
    FF_QWRD=FF_QWORD
    FF_STRU=FF_STRUCT
    FF_TBYT=FF_TBYTE
    FF_VAR=0
    FF_YWRD=FF_YWORD
    FF_ZWRD=FF_ZWORD
    GFE_NOVALUE=0
    add_hidden_area=add_hidden_range
    asciflag=strlit_flag
    delValue=del_value
    del_hidden_area=del_hidden_range
    do16bit=create_16bit_data
    do32bit=create_32bit_data
    doAlign=create_align
    doByte=create_byte
    doCustomData=create_custdata
    doDouble=create_double
    doDwrd=create_dword
    doExtra=ida_idaapi._BC695.false_p
    doFloat=create_float
    doImmd=set_immd
    doOwrd=create_oword
    doPackReal=create_packed_real
    doQwrd=create_qword
    doStruct=create_struct
    doTbyt=create_tbyte
    doWord=create_word
    doYwrd=create_yword
    doZwrd=create_zword
    do_data_ex=create_data
    do_unknown=del_items
    def do_unknown_range(ea, size, flags):
        return del_items(ea, flags, size) # swap 2 last args
    dwrdflag=dword_flag
    f_hasRef=f_has_xref
    f_isASCII=f_is_strlit
    f_isAlign=f_is_align
    f_isByte=f_is_byte
    f_isCode=f_is_code
    f_isCustom=f_is_custom
    f_isData=f_is_data
    f_isDouble=f_is_double
    f_isDwrd=f_is_dword
    f_isFloat=f_is_float
    f_isHead=f_is_head
    f_isNotTail=f_is_not_tail
    f_isOwrd=f_is_oword
    f_isPackReal=f_is_pack_real
    f_isQwrd=f_is_qword
    f_isStruct=f_is_struct
    f_isTail=f_is_tail
    f_isTbyt=f_is_tbyte
    f_isWord=f_is_word
    f_isYwrd=f_is_yword
    getDefaultRadix=get_default_radix
    getFlags=get_full_flags
    get_long=get_dword
    get_full_byte=get_wide_byte
    get_full_word=get_wide_word
    get_full_long=get_wide_dword
    get_original_long=get_original_dword
    put_long=put_dword
    patch_long=patch_dword
    add_long=add_dword
    getRadix=get_radix
    get_ascii_contents=get_strlit_contents
    get_ascii_contents2=get_strlit_contents
    get_flags_novalue=get_flags
    get_hidden_area=get_hidden_range
    get_hidden_area_num=get_hidden_range_num
    get_hidden_area_qty=get_hidden_range_qty
    def get_many_bytes(ea, size):
        return get_bytes(ea, size)
    def get_many_bytes_ex(ea, size):
        return get_bytes_and_mask(ea, size)
    get_max_ascii_length=get_max_strlit_length
    get_next_hidden_area=get_next_hidden_range
    get_prev_hidden_area=get_prev_hidden_range
    get_zero_areas=get_zero_ranges
    getn_hidden_area=getn_hidden_range
    hasExtra=has_extra_cmts
    hasRef=has_xref
    hasValue=has_value
    hidden_area_t=hidden_range_t
    isASCII=is_strlit
    isAlign=is_align
    isByte=is_byte
    isChar=is_char
    isChar0=is_char0
    isChar1=is_char1
    isCode=is_code
    isCustFmt=is_custfmt
    isCustFmt0=is_custfmt0
    isCustFmt1=is_custfmt1
    isCustom=is_custom
    isData=is_data
    isDefArg=is_defarg
    isDefArg0=is_defarg0
    isDefArg1=is_defarg1
    isDouble=is_double
    isDwrd=is_dword
    isEnabled=is_mapped
    isEnum=is_enum
    isEnum0=is_enum0
    isEnum1=is_enum1
    isFloat=is_float
    isFloat0=is_float0
    isFloat1=is_float1
    isFlow=is_flow
    isFltnum=is_fltnum
    isFop=is_forced_operand
    isFunc=is_func
    isHead=is_head
    isImmd=has_immd
    isLoaded=is_loaded
    isNotTail=is_not_tail
    isNum=is_numop
    isNum0=is_numop0
    isNum1=is_numop1
    isOff=is_off
    isOff0=is_off0
    isOff1=is_off1
    isOwrd=is_oword
    isPackReal=is_pack_real
    isQwrd=is_qword
    isSeg=is_seg
    isSeg0=is_seg0
    isSeg1=is_seg1
    isStkvar=is_stkvar
    isStkvar0=is_stkvar0
    isStkvar1=is_stkvar1
    isStroff=is_stroff
    isStroff0=is_stroff0
    isStroff1=is_stroff1
    isStruct=is_struct
    isTail=is_tail
    isTbyt=is_tbyte
    isUnknown=is_unknown
    isVoid=is_suspop
    isWord=is_word
    isYwrd=is_yword
    isZwrd=is_zword
    make_ascii_string=create_strlit
    noExtra=ida_idaapi._BC695.false_p
    noType=clr_op_type
    owrdflag=oword_flag
    patch_many_bytes=patch_bytes
    print_ascii_string_type=print_strlit_type
    put_many_bytes=put_bytes
    qwrdflag=qword_flag
    tbytflag=tbyte_flag
    update_hidden_area=update_hidden_range
    ywrdflag=yword_flag
    zwrdflag=zword_flag
    def get_opinfo(*args):
        import ida_nalt
        if isinstance(args[3], ida_nalt.opinfo_t): # 6.95: ea, n, flags, buf
            ea, n, flags, buf = args
        else:                                      # 7.00: buf, ea, n, flags
            buf, ea, n, flags = args
        return _ida_bytes.get_opinfo(buf, ea, n, flags)
    def doASCI(ea, length):
        import ida_netnode
        return create_data(ea, FF_STRLIT, length, ida_netnode.BADNODE)
    FF_3BYTE=FF_BYTE
    chunksize=chunk_size
    chunkstart=chunk_start
    do3byte=ida_idaapi._BC695.false_p
    f_is3byte=ida_idaapi._BC695.false_p
    freechunk=free_chunk
    get_3byte=ida_idaapi._BC695.false_p
    is3byte=ida_idaapi._BC695.false_p
    nextaddr=next_addr
    nextchunk=next_chunk
    nextthat=next_that
    prevaddr=prev_addr
    prevchunk=prev_chunk
    prevthat=prev_that
    tribyteflag=byte_flag
    alignflag=align_flag
    binflag=bin_flag
    byteflag=byte_flag
    charflag=char_flag
    codeflag=code_flag
    custflag=cust_flag
    custfmtflag=custfmt_flag
    decflag=dec_flag
    doubleflag=double_flag
    enumflag=enum_flag
    floatflag=float_flag
    fltflag=flt_flag
    hexflag=hex_flag
    numflag=num_flag
    octflag=oct_flag
    offflag=off_flag
    packrealflag=packreal_flag
    segflag=seg_flag
    stkvarflag=stkvar_flag
    stroffflag=stroff_flag
    struflag=stru_flag
    wordflag=word_flag
    invalidate_visea_cache=ida_idaapi._BC695.false_p
    @bc695redef
    def op_stroff(*args):
        insn, n, path, path_len, delta = args
        import ida_ua
        if not isinstance(insn, ida_ua.insn_t):
            tmp = ida_ua.insn_t()
            ida_ua.decode_insn(tmp, insn)
            insn = tmp
        return _ida_bytes.op_stroff(insn, n, path, path_len, delta)

%}
%init %{
{
  module_callbacks_t module_lfc;
  module_lfc.closebase = ida_bytes_closebase;
  module_lfc.term = ida_bytes_term;
  register_module_lifecycle_callbacks(module_lfc);
}
%}
