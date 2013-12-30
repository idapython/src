#ifndef __PY_EXPR__
#define __PY_EXPR__

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
#endif
