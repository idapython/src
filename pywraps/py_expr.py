# --------------------------------------------------------------------------
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
def add_idc_func(name, fp, args, defvals=(), flags=0):
    """
    Extends the IDC language by exposing a new IDC function that is backed up by a Python function

    @param name: IDC function name to expose
    @param fp: Python callable that will receive the arguments and return a tuple.
    @param args: Arguments. A tuple of idaapi.VT_XXX constants
    @param defvals: default argument values (optional)
    @param flags: IDC function flags. A combination of EXTFUN_XXX constants (optional)

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

#<pycode_BC695(py_expr)>
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
#</pycode_BC695(py_expr)>
