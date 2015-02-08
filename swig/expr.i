%ignore extfun_t;
%ignore funcset_t;
%ignore extlang_t;
%ignore extlang;
%ignore extlangs_t;
%ignore extlangs;
%ignore register_extlang;
%ignore IDCFuncs;
%ignore set_idc_func;
%ignore set_idc_dtor;
%ignore set_idc_method;
%ignore set_idc_getattr;
%ignore set_idc_setattr;
%ignore set_idc_func_ex;
%ignore run_statements_idc;
%ignore VarLong;
%ignore VarNum;
%ignore extlang_get_attr_exists;
%ignore extlang_create_object_exists;
%ignore create_script_object;
%ignore set_script_attr;
%ignore set_attr_exists;
%ignore get_script_attr;
%ignore extlang_get_attr_exists;
%ignore extlang_compile_file;
%ignore get_extlangs;
%ignore create_idc_object;
%ignore run_script_func;
%ignore VarString;
%ignore VarFloat;
%ignore VarFree;
%ignore calcexpr_long;
%ignore Run;
%ignore ExecuteLine;
%ignore ExecuteFile;
%ignore set_idc_func_body;
%ignore get_idc_func_body;
%ignore idc_stacksize;
%ignore idc_calldepth;
%ignore expr_printf;
%ignore expr_uprintf;
%ignore expr_sprintf;
%ignore expr_printfer;
%ignore init_idc;
%ignore term_idc;
%ignore create_default_idc_classes;
%ignore notify_extlang_changed;
%ignore insn_to_idc;
%ignore find_builtin_idc_func;
%ignore idc_mutex;
%ignore idc_lx;
%ignore idc_vars;
%ignore idc_resolve_label;
%ignore idc_resolver_ea;
%ignore setup_lowcnd_regfuncs;
%cstring_output_maxstr_none(char *errbuf, size_t errbufsize);

%ignore CompileEx;
%rename (CompileEx) CompileEx_wrap;
%ignore Compile;
%rename (Compile) Compile_wrap;
%ignore calcexpr;
%rename (calcexpr) calcexpr_wrap;
%ignore calc_idc_expr;
%rename (calc_idc_expr) calc_idc_expr_wrap;
%ignore CompileLine(const char *line, char *errbuf, size_t errbufsize, uval_t (idaapi*_getname)(const char *name)=NULL);
%ignore CompileLineEx;
%ignore CompileLine;
%rename (CompileLine) CompileLine_wrap;
%{
//<code(py_expr)>
struct py_idcfunc_ctx_t
{
  PyObject *py_func;
  qstring name;
  int nargs;
  py_idcfunc_ctx_t(PyObject *py_func, const char *name, int nargs): py_func(py_func), name(name), nargs(nargs)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_INCREF(py_func);
  }
  ~py_idcfunc_ctx_t()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_DECREF(py_func);
  }
};

//---------------------------------------------------------------------------
static error_t py_call_idc_func(
  void *_ctx,
  idc_value_t *argv,
  idc_value_t *r)
{
  // Convert IDC arguments to Python list
  py_idcfunc_ctx_t *ctx = (py_idcfunc_ctx_t *)_ctx;
  int cvt;
  char errbuf[MAXSTR];

  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_vec_t pargs;
  if ( !pyw_convert_idc_args(argv, ctx->nargs, pargs, true, errbuf, sizeof(errbuf)) )
  {
    // Error during conversion? Create an IDC exception
    return PyW_CreateIdcException(r, errbuf);
  }

  // Call the Python function
  newref_t py_result(PyObject_CallObject(
                             ctx->py_func,
                             pargs.empty() ? NULL : pargs[0].o));

  error_t err;
  if ( PyW_GetError(errbuf, sizeof(errbuf)) )
  {
    err = PyW_CreateIdcException(r, errbuf);
  }
  else
  {
    // Convert the result to IDC
    r->clear();
    cvt = pyvar_to_idcvar(py_result, r);
    if ( cvt < CIP_OK )
      err = PyW_CreateIdcException(r, "ERROR: bad return value");
    else
      err = eOk;
  }

  return err;
}

//</code(py_expr)>
%}

%inline %{
//<inline(py_expr)>

//---------------------------------------------------------------------------
static size_t py_get_call_idc_func()
{
  return (size_t)py_call_idc_func;
}

//---------------------------------------------------------------------------
// Internal function:
// - capture the python callable
// - return a C context as a numeric value
static size_t pyw_register_idc_func(
  const char *name,
  const char *args,
  PyObject *py_fp)
{
  return (size_t)new py_idcfunc_ctx_t(py_fp, name, strlen(args));
}

//---------------------------------------------------------------------------
// Internal function:
// - free the C context
static bool pyw_unregister_idc_func(size_t ctxptr)
{
  // Unregister the function
  py_idcfunc_ctx_t *ctx = (py_idcfunc_ctx_t *)ctxptr;
  bool ok = set_idc_func_ex(ctx->name.c_str(), NULL, NULL, 0);
  
  // Delete the context
  delete ctx;

  return ok;
}

//---------------------------------------------------------------------------
static bool py_set_idc_func_ex(
  const char *name,
  size_t fp_ptr,
  const char *args,
  int flags)
{
  return set_idc_func_ex(name, (idc_func_t *)fp_ptr, args, flags);
}

//---------------------------------------------------------------------------
// Compile* functions return false when error so the return
// value must be negated for the error string to be returned
bool CompileEx_wrap(
    const char *file, 
    bool del_macros,
    char *errbuf, size_t errbufsize)
{
  return !CompileEx(file, del_macros, errbuf, errbufsize);
}

bool Compile_wrap(const char *file, char *errbuf, size_t errbufsize)
{
  return !Compile(file, errbuf, errbufsize);
}

bool calcexpr_wrap(
    ea_t where,
    const char *line,
    idc_value_t *rv,
    char *errbuf, size_t errbufsize)
{
  return !calcexpr(where, line, rv, errbuf, errbufsize);
}

bool calc_idc_expr_wrap(
      ea_t where,
      const char *line,
      idc_value_t *rv,
      char *errbuf, size_t errbufsize)
{
  return !calc_idc_expr(where, line, rv, errbuf, errbufsize);
}

bool CompileLine_wrap(const char *line, char *errbuf, size_t errbufsize)
{
  return !CompileLineEx(line, errbuf, errbufsize);
}

//</inline(py_expr)>
%}

%include "expr.hpp"

%pythoncode %{

#<pycode(py_expr)>
try:
    import types
    import ctypes
    # Callback for IDC func callback (On Windows, we use stdcall)
    # typedef error_t idaapi idc_func_t(idc_value_t *argv,idc_value_t *r);
    _IDCFUNC_CB_T = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)

    # A trampoline function that is called from idcfunc_t that will
    # call the Python callback with the argv and r properly serialized to python
    call_idc_func__ = ctypes.CFUNCTYPE(ctypes.c_long)(_idaapi.py_get_call_idc_func())
except:
    def call_idc_func__(*args):
        warning("IDC extensions need ctypes library in order to work")
        return 0
    try:
        _IDCFUNC_CB_T = CFUNCTYPE(c_int, c_void_p, c_void_p)
    except:
        _IDCFUNC_CB_T = None


# --------------------------------------------------------------------------
EXTFUN_BASE  = 0x0001
"""requires open database"""
EXTFUN_NORET = 0x0002
"""does not return. the interpreter may clean up its state before calling it."""
EXTFUN_SAFE  = 0x0004
"""thread safe function. may be called"""

# --------------------------------------------------------------------------
class _IdcFunction(object):
    """
    Internal class that calls pyw_call_idc_func() with a context
    """
    def __init__(self, ctxptr):
        self.ctxptr = ctxptr
        # Take a reference to the ctypes callback
        # (note: this will create a circular reference)
        self.cb   = _IDCFUNC_CB_T(self)

    fp_ptr = property(lambda self: ctypes.cast(self.cb, ctypes.c_void_p).value)

    def __call__(self, args, res):
        return call_idc_func__(self.ctxptr, args, res)


# --------------------------------------------------------------------------
# Dictionary to remember IDC function names along with the context pointer
# retrieved by using the internal pyw_register_idc_func()
__IDC_FUNC_CTXS = {}

# --------------------------------------------------------------------------
def set_idc_func_ex(name, fp=None, args=(), flags=0):
    """
    Extends the IDC language by exposing a new IDC function that is backed up by a Python function
    This function also unregisters the IDC function if 'fp' was passed as None

    @param name: IDC function name to expose
    @param fp: Python callable that will receive the arguments and return a tuple.
               If this argument is None then the IDC function is unregistered
    @param args: Arguments. A tuple of idaapi.VT_XXX constants
    @param flags: IDC function flags. A combination of EXTFUN_XXX constants

    @return: Boolean.
    """
    global __IDC_FUNC_CTXS

    # Get the context
    f = __IDC_FUNC_CTXS.get(name, None)

    # Unregistering?
    if fp is None:
        # Not registered?
        if f is None:
            return False

        # Break circular reference
        del f.cb

        # Delete the name from the dictionary
        del __IDC_FUNC_CTXS[name]

        # Delete the context and unregister the function
        return _idaapi.pyw_unregister_idc_func(f.ctxptr)

    # Registering a function that is already registered?
    if f is not None:
        # Unregister it first
        set_idc_func_ex(name, None)

    # Convert the tupple argument info to a string
    args = "".join([chr(x) for x in args])

    # Create a context
    ctxptr = _idaapi.pyw_register_idc_func(name, args, fp)
    if ctxptr == 0:
        return False

    # Bind the context with the IdcFunc object
    f = _IdcFunction(ctxptr)

    # Remember the Python context
    __IDC_FUNC_CTXS[name] = f

    # Register IDC function with a callback
    return _idaapi.py_set_idc_func_ex(
                name,
                f.fp_ptr,
                args,
                flags)

#</pycode(py_expr)>
%}