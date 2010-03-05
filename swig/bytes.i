// Make get_any_cmt() work
%apply unsigned char *OUTPUT { color_t *cmttype };

// For get_enum_id()
%apply unsigned char *OUTPUT { uchar *serial };

// Unexported and kernel-only declarations
%ignore FlagsEnable;
%ignore FlagsDisable;
%ignore testf_t;
%ignore nextthat;
%ignore prevthat;
%ignore adjust_visea;
%ignore prev_visea;
%ignore next_visea;
%ignore is_first_visea;
%ignore is_last_visea;
%ignore is_visible_finally;
%ignore invalidate_visea_cache;
%ignore fluFlags;
%ignore setFlbits;
%ignore clrFlbits;
%ignore get_8bit;
%ignore get_ascii_char;
%ignore del_opinfo;
%ignore del_one_opinfo;
%ignore doCode;
%ignore get_repeatable_cmt;
%ignore get_any_indented_cmt;
%ignore del_code_comments;
%ignore doFlow;
%ignore noFlow;
%ignore doRef;
%ignore noRef;
%ignore doExtra;
%ignore noExtra;
%ignore coagulate;
%ignore coagulate_dref;
%ignore get_item_head;
%ignore init_hidden_areas;
%ignore save_hidden_areas;
%ignore term_hidden_areas;
%ignore check_move_args;
%ignore movechunk;
%ignore lock_dbgmem_config;
%ignore unlock_dbgmem_config;
%ignore set_op_type_no_event;
%ignore shuffle_tribytes;
%ignore set_enum_id;
%ignore validate_tofs;
%ignore ida_vpagesize;
%ignore ida_vpages;
%ignore ida_npagesize;
%ignore ida_npages;
%ignore fpnum_digits;
%ignore fpnum_length;
%ignore FlagsInit;
%ignore FlagsTerm;
%ignore FlagsReset;
%ignore init_flags;
%ignore term_flags;
%ignore reset_flags;
%ignore flush_flags;

// TODO: These could be fixed if someone needs them.
%ignore get_many_bytes;
%ignore set_dbgmem_source;

%include "bytes.hpp"

%clear(void *buf, ssize_t size);

%clear(const void *buf, size_t size);
%clear(void *buf, ssize_t size);
%clear(opinfo_t *);

%rename (nextthat) py_nextthat;
%rename (prevthat) py_prevthat;
%rename (get_many_bytes) py_get_many_bytes;

%{
//<code(py_bytes)>
//------------------------------------------------------------------------
static bool idaapi py_testf_cb(flags_t flags, void *ud)
{
  PyObject *py_flags = PyLong_FromUnsignedLong(flags);
  PyObject *result = PyObject_CallFunctionObjArgs((PyObject *) ud, py_flags, NULL);
  bool ret = result != NULL && PyObject_IsTrue(result);
  Py_XDECREF(result);
  Py_XDECREF(py_flags);
  return ret;
}

//------------------------------------------------------------------------
// Wraps the (next|prev)that()
static ea_t py_npthat(ea_t ea, ea_t bound, PyObject *py_callable, bool next)
{
  if (!PyCallable_Check(py_callable))
    return BADADDR;
  return (next ? nextthat : prevthat)(ea, bound, py_testf_cb, py_callable);
}
//</code(py_bytes)>
%}

%inline %{
//<inline(py_bytes)>

//------------------------------------------------------------------------
static ea_t py_nextthat(ea_t ea, ea_t maxea, PyObject *callable)
{
  return py_npthat(ea, maxea, callable, true);
}

static ea_t py_prevthat(ea_t ea, ea_t minea, PyObject *callable)
{
  return py_npthat(ea, minea, callable, false);
}

//------------------------------------------------------------------------
// Get the specified number of bytes of the program into the buffer.
static PyObject *py_get_many_bytes(ea_t ea, int size)
{
  do 
  {
    if (size <= 0)
      break;
    // Allocate memory
    char *buf = (char *) qalloc(size);
    if (buf == NULL)
      break;

    // Read bytes
    bool ok = get_many_bytes(ea, buf, size);

    // If ok, create a python string
    PyObject *py_buf;
    if (ok)
      py_buf = PyString_FromStringAndSize(buf, size);

    // Free buffer
    qfree(buf);
    
    // Return buffer to Python
    if (ok)
      return py_buf;
  } while (false);
  Py_RETURN_NONE;
}
//</inline(py_bytes)>
%}
