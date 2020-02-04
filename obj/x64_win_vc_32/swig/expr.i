%module(docstring="IDA Plugin SDK API wrapper: expr",directors="1",threads="1") ida_expr
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_EXPR
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_EXPR
  #define HAS_DEP_ON_INTERFACE_EXPR
#endif
%include "header.i"
%ignore ext_idcfunc_t;
%ignore idcfuncs_t;
%ignore extlang_t;
%ignore extlang_object_t;
%ignore extlang_ptr_t;
%ignore extlangs_t;
%ignore extlangs;
%ignore install_extlang;
%ignore remove_extlang;
%ignore select_extlang;
%ignore get_extlang;
%ignore get_current_extlang;
%ignore find_extlang;
%ignore find_extlang_by_ext;
%ignore find_extlang_by_name;
%ignore find_extlang_by_index;
%ignore find_extlang_kind_t;
%ignore for_all_extlangs;
%ignore extlang_visitor_t;
%ignore set_idc_dtor;
%ignore set_idc_method;
%ignore set_idc_getattr;
%ignore set_idc_setattr;
%ignore add_idc_func;
%ignore del_idc_func;
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
%ignore VarFloat;
%ignore VarFree;
%ignore eval_expr_long;
%ignore call_idc_func;
%ignore eval_idc_snippet;
%ignore set_idc_func_body;
%ignore get_idc_func_body;
%ignore idc_vars;
%ignore setup_lowcnd_regfuncs;
%ignore syntax_highlighter_t;
%ignore get_idptype_and_data;
%ignore idc_resolver_t;
%ignore idc_value_t::_set_long;
%ignore idc_value_t::_set_float;
%ignore idc_value_t::_set_int64;
%ignore idc_value_t::_set_pvoid;
%ignore idc_value_t::_set_string;

%ignore eval_expr;
%rename (eval_expr) py_eval_expr;
%ignore eval_idc_expr;
%rename (eval_idc_expr) py_eval_idc_expr;
%ignore compile_idc_file;
%rename (compile_idc_file) py_compile_idc_file;
%ignore compile_idc_text;
%rename (compile_idc_text) py_compile_idc_text;

%cstring_output_buf_and_size_returning_charptr(
        1,
        char *buf,
        size_t bufsize,
        const char *file); // get_idc_filename

%nonnul_argument_prototype(
        bool py_compile_idc_file(const char *nonnul_line, qstring *errbuf),
        const char *nonnul_line);
%nonnul_argument_prototype(
        bool py_compile_idc_text(const char *nonnul_line, qstring *errbuf),
        const char *nonnul_line);
%{
//<code(py_expr)>
struct py_idcfunc_ctx_t
{
  ref_t py_func;
  qstring name;
  int nargs;
  py_idcfunc_ctx_t(PyObject *_py_func, const char *name, int nargs)
    : py_func(borref_t(_py_func)),
      name(name),
      nargs(nargs)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
  }
  ~py_idcfunc_ctx_t()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
  }
};

//---------------------------------------------------------------------------
static error_t py_call_idc_func(
        void *_ctx,
        idc_value_t *argv,
        idc_value_t *r)
{
  PYW_GIL_GET;

  // Convert IDC arguments to Python list
  py_idcfunc_ctx_t *ctx = (py_idcfunc_ctx_t *)_ctx;

  ref_vec_t pargs;
  qstring errbuf;
  if ( !pyw_convert_idc_args(argv, ctx->nargs, pargs, PYWCVTF_AS_TUPLE, &errbuf) )
  {
    // Error during conversion? Create an IDC exception
    return PyW_CreateIdcException(r, errbuf.c_str());
  }

  // Call the Python function
  newref_t py_result = PyObject_CallObject(
                             ctx->py_func.o,
                             pargs.empty() ? NULL : pargs[0].o);

  int cvt;
  error_t err;
  if ( PyW_GetError(&errbuf) )
  {
    err = PyW_CreateIdcException(r, errbuf.c_str());
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
  bool ok = del_idc_func(ctx->name.c_str());

  // Delete the context
  delete ctx;

  return ok;
}

//-------------------------------------------------------------------------
typedef qvector<idc_value_t> idc_values_t;

//-------------------------------------------------------------------------
static bool pyw_convert_defvals(idc_values_t *out, PyObject *py_seq)
{
  if ( !PySequence_Check(py_seq) )
    return false;
  for ( Py_ssize_t i = 0, n = PySequence_Size(py_seq); i < n; ++i )
  {
    newref_t py_var(PySequence_GetItem(py_seq, i));
    idc_value_t &idc_var = out->push_back();
    if ( pyvar_to_idcvar(py_var, &idc_var, NULL) != CIP_OK )
      return false;
  }
  return true;
}

//---------------------------------------------------------------------------
static bool py_add_idc_func(
        const char *name,
        size_t fp_ptr,
        const char *args,
        const idc_values_t &defvals,
        int flags)
{
  ext_idcfunc_t desc = { name, (idc_func_t *)fp_ptr, args, defvals.begin(), (int)defvals.size(), flags };
  return add_idc_func(desc);
}

//---------------------------------------------------------------------------
// compile_idc_* functions return false when error so the return
// value must be negated for the error string to be returned
bool py_compile_idc_file(
        const char *file,
        qstring *errbuf)
{
  return !compile_idc_file(file, errbuf);
}

bool py_compile_idc_text(
        const char *line,
        qstring *errbuf)
{
  return !compile_idc_text(line, errbuf);
}

bool py_eval_expr(
        idc_value_t *rv,
        ea_t where,
        const char *line,
        qstring *errbuf)
{
  return !eval_expr(rv, where, line, errbuf);
}

bool py_eval_idc_expr(
        idc_value_t *rv,
        ea_t where,
        const char *line,
        qstring *errbuf)
{
  return !eval_idc_expr(rv, where, line, errbuf);
}

//</inline(py_expr)>
%}

%include "expr.hpp"

%extend idc_value_t
{
  %pythoncode {
    str = property(lambda self: self.c_str(), lambda self, v: self.set_string(v))
  }
}

%uncomparable_elements_qvector(idc_value_t, idc_values_t);

%pythoncode %{
#<pycode(py_expr)>
try:
    import types
    import ctypes
    # Callback for IDC func callback (On Windows, we use stdcall)
    # typedef error_t idaapi idc_func_t(idc_value_t *argv,idc_value_t *r);
    try:
        _IDCFUNC_CB_T = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    except:
        _IDCFUNC_CB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)

    # A trampoline function that is called from idcfunc_t that will
    # call the Python callback with the argv and r properly serialized to python
    call_idc_func__ = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(_ida_expr.py_get_call_idc_func())
except:
    def call_idc_func__(*args):
        warning("IDC extensions need ctypes library in order to work")
        return 0
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
        self.cb = _IDCFUNC_CB_T(self)

    fp_ptr = property(lambda self: ctypes.cast(self.cb, ctypes.c_void_p).value)

    def __call__(self, args, res):
        return call_idc_func__(self.ctxptr, args, res)


# --------------------------------------------------------------------------
# Dictionary to remember IDC function names along with the context pointer
# retrieved by using the internal pyw_register_idc_func()
__IDC_FUNC_CTXS = {}

def del_idc_func(name):
    """
    Unregisters the specified IDC function

    @param name: IDC function name to unregister

    @return: Boolean
    """
    global __IDC_FUNC_CTXS

    # Get the context
    f = __IDC_FUNC_CTXS.get(name, None)

    if f is None:
        return False # Not registered

    # Break circular reference
    del f.cb

    # Delete the name from the dictionary
    del __IDC_FUNC_CTXS[name]

    # Delete the context and unregister the function
    return _ida_expr.pyw_unregister_idc_func(f.ctxptr)

# --------------------------------------------------------------------------
def add_idc_func(name, fp, args, defvals=None, flags=0):
    """
    Extends the IDC language by exposing a new IDC function that is backed up by a Python function

    @param name: IDC function name to expose
    @param fp: Python callable that will receive the arguments and return a tuple.
    @param args: Arguments. A tuple of idaapi.VT_XXX constants
    @param flags: IDC function flags. A combination of EXTFUN_XXX constants

    @return: Boolean
    """
    global __IDC_FUNC_CTXS

    # Get the context
    f = __IDC_FUNC_CTXS.get(name, None)

    # Registering a function that is already registered?
    if f is not None:
        # Unregister it first
        del_idc_func(name)

    # Convert the tupple argument info to a string
    args = "".join([chr(x) for x in args])

    # make sure we don't have an obvious discrepancy between
    # the number of args, and the provided default values
    if len(defvals) > len(args):
        return False

    vdefvals = idc_values_t()
    if not _ida_expr.pyw_convert_defvals(vdefvals, defvals):
        return False

    # Create a context
    ctxptr = _ida_expr.pyw_register_idc_func(name, args, fp)
    if ctxptr == 0:
        return False

    # Bind the context with the IdcFunc object
    f = _IdcFunction(ctxptr)

    # Remember the Python context
    __IDC_FUNC_CTXS[name] = f

    # Register IDC function with a callback
    return _ida_expr.py_add_idc_func(
                name,
                f.fp_ptr,
                args,
                vdefvals,
                flags)

#</pycode(py_expr)>
%}
%pythoncode %{
if _BC695:
    Compile=compile_idc_file
    CompileEx=compile_idc_file
    CompileLine=compile_idc_text
    VT_STR2=VT_STR
    VarCopy=copy_idcv
    VarDelAttr=del_idcv_attr
    VarDeref=deref_idcv
    VarFirstAttr=first_idcv_attr
    def VarGetAttr(obj, attr, res, may_use_getattr=False):
        return get_idcv_attr(res, obj, attr, may_use_getattr)
    VarGetClassName=get_idcv_class_name
    VarGetSlice=get_idcv_slice
    VarInt64=idcv_int64
    VarLastAttr=last_idcv_attr
    VarMove=move_idcv
    VarNextAttr=next_idcv_attr
    VarObject=idcv_object
    VarPrevAttr=prev_idcv_attr
    VarPrint=print_idcv
    VarRef=create_idcv_ref
    VarSetAttr=set_idcv_attr
    VarSetSlice=set_idcv_slice
    VarString2=idcv_string
    VarSwap=swap_idcvs
    def calc_idc_expr(where, expr, res):
        return eval_idc_expr(res, where, expr)
    def calcexpr(where, expr, res):
        return eval_expr(res, where, expr)
    def dosysfile(complain_if_no_file, fname):
        return exec_system_script(fname, complain_if_no_file)
    def execute(line):
        return eval_idc_snippet(None, line)
    py_set_idc_func_ex=py_add_idc_func
    def set_idc_func_ex(name, fp=None, args=(), flags=0):
        return add_idc_func(name, fp, args, (), flags)

%}