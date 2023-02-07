#ifndef __PY_EXPR__
#define __PY_EXPR__

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
  newref_t py_result(PyObject_CallObject(
                             ctx->py_func.o,
                             pargs.empty() ? nullptr : pargs[0].o));

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
  if ( out == nullptr || !PySequence_Check(py_seq) )
    return false;
  for ( Py_ssize_t i = 0, n = PySequence_Size(py_seq); i < n; ++i )
  {
    newref_t py_var(PySequence_GetItem(py_seq, i));
    idc_value_t &idc_var = out->push_back();
    if ( pyvar_to_idcvar(py_var, &idc_var, nullptr) != CIP_OK )
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
#endif
