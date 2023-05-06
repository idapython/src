#ifndef __PY_UA__
#define __PY_UA__

//-------------------------------------------------------------------------
//<code(py_ua)>
//</code(py_ua)>

//-------------------------------------------------------------------------
//<inline(py_ua)>
/*
#<pydoc>
def decode_preceding_insn(ea):
    """
    Decodes the preceding instruction. Please check ua.hpp / decode_preceding_insn()
    @param ea: current ea
    @param out: instruction storage
    @return: tuple(preceeding_ea or BADADDR, farref = Boolean)
    """
    pass
#</pydoc>
*/
PyObject *py_decode_preceding_insn(insn_t *out, ea_t ea)
{
  bool farref;
  ea_t r = decode_preceding_insn(out, ea, &farref);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return Py_BuildValue("(" PY_BV_EA "i)", bvea_t(r), farref ? 1 : 0);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def construct_macro(insn):
    """
    See ua.hpp's construct_macro().
    """
    pass
#</pydoc>
*/
bool py_construct_macro(insn_t &insn, bool enable, PyObject *build_macro)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( !PyCallable_Check(build_macro) )
    return false;

  static qstack<ref_t> macro_builders;

  macro_builders.push(newref_t(build_macro));
  struct ida_local lambda_t
  {
    static bool idaapi call_build_macro(insn_t &insn, bool may_go_forward)
    {
      PyObject *py_builder = macro_builders.top().o;
      ref_t py_res;
      if ( ref_t py_mod = ref_t(PyW_TryImportModule(SWIG_name)) )
      {
        if ( ref_t py_insn = ref_t(try_create_swig_wrapper(py_mod, "insn_t", &insn)) )
        {
          py_res = newref_t(
                  PyObject_CallFunction(
                          py_builder,
                          "OO",
                          py_insn.o,
                          may_go_forward ? Py_True : Py_False));
          PyW_ShowCbErr("build_macro");
        }
      }
      return py_res.o == Py_True;
    }
  };
  bool res = construct_macro(insn, enable, lambda_t::call_build_macro);
  macro_builders.pop();
  return res;
}

//-------------------------------------------------------------------------
static int py_get_dtype_by_size(asize_t size)
{
  return int(get_dtype_by_size(size));
}

//-------------------------------------------------------------------------
PyObject *py_get_immvals(ea_t ea, int n, flags64_t F=0)
{
  uvalvec_t storage;
  storage.resize(2 * UA_MAXOP);
  if ( F == 0 )
    F = get_flags(ea);
  size_t cnt = get_immvals(storage.begin(), ea, n, F);
  storage.resize(cnt);
  ref_t result(PyW_UvalVecToPyList(storage));
  result.incref();
  return result.o;
}

//-------------------------------------------------------------------------
PyObject *py_get_printable_immvals(ea_t ea, int n, flags64_t F=0)
{
  uvalvec_t storage;
  storage.resize(2 * UA_MAXOP);
  if ( F == 0 )
    F = get_flags(ea);
  size_t cnt = get_printable_immvals(storage.begin(), ea, n, F);
  storage.resize(cnt);
  ref_t result(PyW_UvalVecToPyList(storage));
  result.incref();
  return result.o;
}

//-------------------------------------------------------------------------
#define DEFINE_WRAP_TYPE_FROM_PTRVAL(Type)              \
  static Type *Type##__from_ptrval__(size_t ptrval)     \
  {                                                     \
    return (Type *) ptrval;                             \
  }

DEFINE_WRAP_TYPE_FROM_PTRVAL(insn_t);
DEFINE_WRAP_TYPE_FROM_PTRVAL(op_t);
DEFINE_WRAP_TYPE_FROM_PTRVAL(outctx_base_t);
DEFINE_WRAP_TYPE_FROM_PTRVAL(outctx_t);

#undef DEFINE_WRAP_TYPE_FROM_PTRVAL

//</inline(py_ua)>

#endif
