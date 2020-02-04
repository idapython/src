%module(docstring="IDA Plugin SDK API wrapper: frame",directors="1",threads="1") ida_frame
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_FRAME
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_FRAME
  #define HAS_DEP_ON_INTERFACE_FRAME
#endif
#ifndef HAS_DEP_ON_INTERFACE_RANGE
  #define HAS_DEP_ON_INTERFACE_RANGE
#endif
%include "header.i"
%{
#include <frame.hpp>
%}

%import "range.i"

%ignore add_frame_spec_member;
%ignore del_stkvars;
%ignore calc_frame_offset;
%ignore set_llabel;
%ignore get_llabel_ea;
%ignore get_llabel;

%ignore get_stkvar;
%rename (get_stkvar) py_get_stkvar;

%ignore calc_frame_offset;
%ignore add_stkvar;

%ignore delete_wrong_frame_info;

%template(xreflist_t) qvector<xreflist_entry_t>;

%inline %{
//<inline(py_frame)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_stkvar(op, v):
    """
    Get pointer to stack variable
    @param op: reference to instruction operand
    @param v: immediate value in the operand (usually op.addr)
    @return:
        - None on failure
        - tuple(member_t, actval)
          where actval: actual value used to fetch stack variable
    """
    pass
#</pydoc>
*/
PyObject *py_get_stkvar(const insn_t &insn, const op_t &op, sval_t v)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  sval_t actval;
  member_t *member = get_stkvar(&actval, insn, op, v);
  if ( member == NULL )
    Py_RETURN_NONE;

  return Py_BuildValue("(O" PY_BV_SVAL ")",
                       SWIG_NewPointerObj(SWIG_as_voidptr(member), SWIGTYPE_p_member_t, 0),
                       bvsval_t(actval));
}
//</inline(py_frame)>
%}

%include "frame.hpp"
%pythoncode %{
if _BC695:
    add_auto_stkpnt2=add_auto_stkpnt
    # in fact, we cannot simulate add_stkvar[23] here, because we simply
    # don't have the insn_t object -- and no way of retrieving it, either,
    # since cmd is gone
    @bc695redef
    def get_stkvar(*args):
        if len(args) == 2:
            import ida_ua
            insn, op, v = ida_ua.cmd, args[0], args[1]
        else:
            insn, op, v = args
        return _ida_frame.get_stkvar(insn, op, v)
    @bc695redef
    def get_frame_part(*args):
        import ida_funcs
        if isinstance(args[0], ida_funcs.func_t): # 6.95: pfn, part, range
            rnge, pfn, part = args[2], args[0], args[1]
        else:                                     # 7.00: range, pfn, part
            rnge, pfn, part = args
        return _ida_frame.get_frame_part(rnge, pfn, part)

%}