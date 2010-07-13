%ignore insn_t;
%ignore op_t;
%ignore cmd;
%ignore ua_out;
%ignore showAsChar;
%ignore out_real;
%ignore init_output_buffer;
%ignore term_output_buffer;
%ignore OutValue;
%ignore OutImmChar;
%ignore out_name_expr;
%ignore ua_stkvar2;
%ignore ua_add_off_drefs;
%ignore ua_add_off_drefs2;
%ignore out_snprintf;
%ignore set_output_ptr;
%ignore get_output_ptr;
%ignore out_insert;
%ignore get_immval;
%ignore get_spoiled_reg;
%ignore construct_macro;
%ignore decode_preceding_insn;
%ignore init_ua;
%ignore term_ua;
%ignore term_uaterm_ua;
%ignore get_equal_items;
%ignore get_equal_itemsget_equal_items;
%ignore ua_use_fixup;

%ignore get_immval;
%ignore ua_stkvar;

%include "ua.hpp"

%rename (init_output_buffer) py_init_output_buffer;
%rename (term_output_buffer) py_term_output_buffer;
%rename (OutValue) py_OutValue;
%rename (OutImmChar) py_OutImmChar;
%rename (out_name_expr) py_out_name_expr;
%rename (ua_stkvar2) py_ua_stkvar2;
%rename (ua_add_off_drefs) py_ua_add_off_drefs;
%rename (ua_add_off_drefs2) py_ua_add_off_drefs2;
%rename (decode_preceding_insn) py_decode_preceding_insn;

%inline %{
//<inline(py_ua)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def init_output_buffer(size = MAXSTR):
    """
    This function initialize an output buffer with the given size.
    It should be called before using any out_xxxx() functions.
    @return: It returns a string. This string should then be passed to MakeLine().
             This function could return None if it failed to create a buffer with the given size.
    """
    pass
#</pydoc>
*/
PyObject *py_init_output_buffer(size_t size = MAXSTR)
{
  // Let Python allocate a writable string buffer for us
  PyObject *py_str = PyString_FromStringAndSize(NULL, size);
  if ( py_str == NULL )
    Py_RETURN_NONE;
  init_output_buffer(PyString_AsString(py_str), size);
  return py_str;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def term_output_buffer():
    """Use this function to terminate an output buffer."""
    pass
#</pydoc>
*/
void py_term_output_buffer()
{
  term_output_buffer();
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def decode_preceding_insn(ea):
    """
    Decodes the preceding instruction. Please check ua.hpp / decode_preceding_insn()
    @param ea: current ea
    @return: tuple(preceeding_ea or BADADDR, farref = Boolean)
    """
    pass
#</pydoc>
*/
PyObject *py_decode_preceding_insn(ea_t ea)
{
  bool farref;
  ea_t r = decode_preceding_insn(ea, &farref);
  return Py_BuildValue("(" PY_FMT64 "i)", pyul_t(r), farref ? 1 : 0);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def OutValue(op, outflags = 0):
    """
    Output immediate value
    @param op: operand (of type op_t)
    @return: flags of the output value
             -1: value is output with COLOR_ERROR
             0:  value is output as a number or character or segment
    """
    pass
#</pydoc>
*/
flags_t py_OutValue(PyObject *x, int outflags=0)
{
  op_t *op = op_t_get_clink(x);
  if ( op == NULL )
    return 0;

  return OutValue(*op, outflags);
}

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
PyObject *py_get_stkvar(PyObject *py_op, PyObject *py_v)
{
  op_t *op = op_t_get_clink(py_op);
  uint64 v;
  if ( op == NULL || !PyW_GetNumber(py_v, &v) )
    Py_RETURN_NONE;

  sval_t actval;
  member_t *member = get_stkvar(*op, sval_t(v), &actval);
  if ( member == NULL )
    Py_RETURN_NONE;

  return Py_BuildValue("(O" PY_SFMT64 ")",
    SWIG_NewPointerObj(SWIG_as_voidptr(member), SWIGTYPE_p_member_t, 0),
    pyl_t(actval));
}

//-------------------------------------------------------------------------
/*
header: frame.hpp
#<pydoc>
def add_stkvar3(op, v, flags):
    """
    Automatically add stack variable if doesn't exist
    Processor modules should use ua_stkvar2()
    @param op: reference to instruction operand
    @param v: immediate value in the operand (usually op.addr)
    @param flags: combination of STKVAR_... constants
    @return: Boolean
    """
    pass
#</pydoc>
*/
bool py_add_stkvar3(PyObject *py_op, PyObject *py_v, int flags)
{
  op_t *op = op_t_get_clink(py_op);
  uint64 v;
  return ( op == NULL || !PyW_GetNumber(py_v, &v) || !add_stkvar3(*op, sval_t(v), flags)) ? false : true;
}

//-------------------------------------------------------------------------
/*
header: frame.hpp
// Calculate offset of stack variable in the frame structure
//      pfn - pointer to function (can't be NULL!)
//      x   - reference to instruction operand
//      v   - value of variable offset in the instruction
// returns: offset of stack variable in the frame structure (0..n)

ea_t calc_frame_offset(func_t *pfn, const op_t *x, sval_t v);
*/

//-------------------------------------------------------------------------
/*
header: typeinf.hpp
#<pydoc>
def apply_type_to_stkarg(op, v, type, name):
    """
    Apply type information to a stack variable

    @param op: reference to instruction operand
    @param v: immediate value in the operand (usually op.addr)
    @param type: type string. Retrieve from idc.ParseType("type string", flags)[1]
    @param name: stack variable name

    @return: Boolean
    """
    pass
#</pydoc>
*/
bool py_apply_type_to_stkarg(
    PyObject *py_op,
    PyObject *py_uv,
    PyObject *py_type,
    const char *name)
{
  uint64 v;
  op_t *op = op_t_get_clink(py_op);
  if ( op == NULL || !PyW_GetNumber(py_uv, &v) || !PyString_Check(py_type))
    return false;
  else
    return apply_type_to_stkarg(*op, uval_t(v), (type_t *) PyString_AsString(py_type), name);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def OutImmChar(op, outflags = 0):
    """
    Output operand value as a commented character constant
    @param op: operand (of type op_t)
    @return: None
    """
    pass
#</pydoc>
*/
static void py_OutImmChar(PyObject *x)
{
  op_t *op = op_t_get_clink(x);
  if ( op != NULL )
    OutImmChar(*op);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ua_stkvar2(op, outflags = 0):
    """
    Create or modify a stack variable in the function frame.
    Please check ua.hpp / ua_stkvar2()
    @param op: operand (of type op_t)
    @return: None
    """
    pass
#</pydoc>
*/
static bool py_ua_stkvar2(PyObject *x, adiff_t v, int flags)
{
  op_t *op = op_t_get_clink(x);
  return op == NULL ? false : ua_stkvar2(*op, v, flags);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ua_add_off_drefs(op, type):
    """
    Add xrefs for offset operand of the current instruction
    Please check ua.hpp / ua_add_off_drefs()
    @param op: operand (of type op_t)
    @return: None
    """
    pass
#</pydoc>
*/
ea_t py_ua_add_off_drefs(PyObject *py_op, dref_t type)
{
  op_t *op = op_t_get_clink(py_op);
  return op == NULL ? BADADDR : ua_add_off_drefs(*op, type);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ua_add_off_drefs2(op, type, outf):
    """
    Add xrefs for offset operand of the current instruction
    Please check ua.hpp / ua_add_off_drefs2()
    @return: ea_t
    """
    pass
#</pydoc>
*/
ea_t py_ua_add_off_drefs2(PyObject *py_op, dref_t type, int outf)
{
  op_t *op = op_t_get_clink(py_op);
  return op == NULL ? BADADDR : ua_add_off_drefs2(*op, type, outf);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def out_name_expr(op, ea, off):
    """
    Output a name expression
    @param op: operand (of type op_t)
    @param ea: address of expression
    @param off: the value of name expression. this parameter is used only to
                check that the name expression will have the wanted value.
                You may pass BADADDR for this parameter.
    @return: true if the name expression has been produced
    """
    pass
#</pydoc>
*/
bool py_out_name_expr(
  PyObject *py_op,
  ea_t ea,
  PyObject *py_off)
{
  op_t *op = op_t_get_clink(py_op);
  uint64 v(0);
  adiff_t off;
  if ( PyW_GetNumber(py_off, &v) )
    off = adiff_t(v);
  else
    off = BADADDR;
  return op == NULL ? false : out_name_expr(*op, ea, off);
}

//-------------------------------------------------------------------------
static bool op_t_assign(PyObject *self, PyObject *other)
{
  op_t *lhs = op_t_get_clink(self);
  op_t *rhs = op_t_get_clink(other);
  if (lhs == NULL || rhs == NULL)
    return false;

  *lhs = *rhs;
  return true;
}

//-------------------------------------------------------------------------
static bool insn_t_assign(PyObject *self, PyObject *other)
{
  insn_t *lhs = insn_t_get_clink(self);
  insn_t *rhs = insn_t_get_clink(other);
  if (lhs == NULL || rhs == NULL)
    return false;

  *lhs = *rhs;
  return true;
}

//-------------------------------------------------------------------------
static PyObject *insn_t_get_op_link(PyObject *py_insn_lnk, int i)
{
  if ( i < 0 || i >= UA_MAXOP || !PyCObject_Check(py_insn_lnk) )
    Py_RETURN_NONE;

  // Extract C link
  insn_t *insn = (insn_t *)PyCObject_AsVoidPtr(py_insn_lnk);

  // Return a link to the operand
  return PyCObject_FromVoidPtr(&insn->Operands[i], NULL);
}

//-------------------------------------------------------------------------
static PyObject *insn_t_create()
{
  insn_t *insn = new insn_t();
  return PyCObject_FromVoidPtr(insn, NULL);
}

//-------------------------------------------------------------------------
static PyObject *op_t_create()
{
  op_t *op = new op_t();
  return PyCObject_FromVoidPtr(op, NULL);
}

//-------------------------------------------------------------------------
static bool op_t_destroy(PyObject *py_obj)
{
  if ( !PyCObject_Check(py_obj) )
    return false;

  op_t *op = (op_t *) PyCObject_AsVoidPtr(py_obj);
  delete op;

  return true;
}

//-------------------------------------------------------------------------
static bool insn_t_destroy(PyObject *py_obj)
{
  if ( !PyCObject_Check(py_obj) )
    return false;

  insn_t *insn = (insn_t *) PyCObject_AsVoidPtr(py_obj);
  delete insn;

  return true;
}

//-------------------------------------------------------------------------
// Returns a C link to the global 'cmd' variable
static PyObject *py_get_global_cmd_link()
{
  return PyCObject_FromVoidPtr(&::cmd, NULL);
}

//-------------------------------------------------------------------------
PyObject *insn_t_is_canon_insn(int itype)
{
  if ( ph.is_canon_insn(itype) )
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

//-------------------------------------------------------------------------
PyObject *insn_t_get_canon_feature(int itype)
{
  return Py_BuildValue("I", ph.is_canon_insn(itype) ? ph.instruc[itype-ph.instruc_start].feature : 0);
}

//-------------------------------------------------------------------------
PyObject *insn_t_get_canon_mnem(int itype)
{
  if ( ph.is_canon_insn(itype) )
    return Py_BuildValue("s", ph.instruc[itype-ph.instruc_start].name);
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
static PyObject *insn_t_get_cs(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->cs);
}

static void insn_t_set_cs(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PyW_GetNumber(value, &v);
  link->cs = ea_t(v);
}

static PyObject *insn_t_get_ip(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->ip);
}

static void insn_t_set_ip(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PyW_GetNumber(value, &v);
  link->ip = ea_t(v);
}

static PyObject *insn_t_get_ea(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->ea);
}

static void insn_t_set_ea(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PyW_GetNumber(value, &v);
  link->ea = ea_t(v);
}

static PyObject *insn_t_get_itype(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("H", link->itype);
}

static void insn_t_set_itype(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  link->itype = (uint16)PyInt_AsLong(value);
}

static PyObject *insn_t_get_size(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("H", link->size);
}

static void insn_t_set_size(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  link->size = (uint16)PyInt_AsLong(value);
}

static PyObject *insn_t_get_auxpref(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("H", link->auxpref);
}

static void insn_t_set_auxpref(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  link->auxpref = (uint16)PyInt_AsLong(value);
}

static PyObject *insn_t_get_segpref(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->segpref);
}

static void insn_t_set_segpref(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  link->segpref = (char)PyInt_AsLong(value);
}

static PyObject *insn_t_get_insnpref(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->insnpref);
}

static void insn_t_set_insnpref(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  link->insnpref = (char)PyInt_AsLong(value);
}

static PyObject *insn_t_get_flags(PyObject *self)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->flags);
}

static void insn_t_set_flags(PyObject *self, PyObject *value)
{
  insn_t *link = insn_t_get_clink(self);
  if ( link == NULL )
    return;
  link->flags = (char)PyInt_AsLong(value);
}

//-------------------------------------------------------------------------
static PyObject *op_t_get_n(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->n);
}

static void op_t_set_n(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->n = (char)PyInt_AsLong(value);
}

static PyObject *op_t_get_type(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("B", link->type);
}

static void op_t_set_type(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->type = (optype_t)PyInt_AsLong(value);
}

static PyObject *op_t_get_offb(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->offb);
}

static void op_t_set_offb(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->offb = (char)PyInt_AsLong(value);
}

static PyObject *op_t_get_offo(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->offo);
}

static void op_t_set_offo(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->offo = (char)PyInt_AsLong(value);
}

static PyObject *op_t_get_flags(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("B", link->flags);
}

static void op_t_set_flags(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->flags = (uchar)PyInt_AsLong(value);
}

static PyObject *op_t_get_dtyp(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->dtyp);
}

static void op_t_set_dtyp(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->dtyp = (char)PyInt_AsLong(value);
}

static PyObject *op_t_get_reg_phrase(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("H", link->reg);
}
static void op_t_set_reg_phrase(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->reg = (uint16)PyInt_AsLong(value);
}

static PyObject *op_t_get_value(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("I", link->value);
}

static void op_t_set_value(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->value = PyInt_AsLong(value);
}

static PyObject *op_t_get_addr(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->addr);
}

static void op_t_set_addr(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PyW_GetNumber(value, &v);
  link->addr = ea_t(v);
}

static PyObject *op_t_get_specval(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->specval);
}

static void op_t_set_specval(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PyW_GetNumber(value, &v);
  link->specval = ea_t(v);
}

static PyObject *op_t_get_specflag1(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->specflag1);
}

static void op_t_set_specflag1(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->specflag1 = (char)PyInt_AsLong(value);
}

static PyObject *op_t_get_specflag2(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->specflag2);
}

static void op_t_set_specflag2(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->specflag2 = (char)PyInt_AsLong(value);
}

static PyObject *op_t_get_specflag3(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->specflag3);
}

static void op_t_set_specflag3(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->specflag3 = (char)PyInt_AsLong(value);
}

static PyObject *op_t_get_specflag4(PyObject *self)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", link->specflag4);
}

static void op_t_set_specflag4(PyObject *self, PyObject *value)
{
  op_t *link = op_t_get_clink(self);
  if ( link == NULL )
    return;
  link->specflag4 = (char)PyInt_AsLong(value);
}

//</inline(py_ua)>
%}

%{
//<code(py_ua)>
//-------------------------------------------------------------------------
insn_t *insn_t_get_clink(PyObject *self)
{
  // Must have the link attribute
  if ( !PyObject_HasAttrString(self, S_CLINK_NAME) )
    return NULL;

  insn_t *insn;
  PyObject *attr = PyObject_GetAttrString(self, S_CLINK_NAME);
  if ( PyCObject_Check(attr) )
    insn = (insn_t *) PyCObject_AsVoidPtr(attr);
  else
    insn = NULL;
  Py_DECREF(attr);
  return insn;
}

//-------------------------------------------------------------------------
op_t *op_t_get_clink(PyObject *self)
{
  // Must have the link attribute
  if ( !PyObject_HasAttrString(self, S_CLINK_NAME) )
    return NULL;
  op_t *r;
  PyObject *attr = PyObject_GetAttrString(self, S_CLINK_NAME);
  if ( PyCObject_Check(attr) )
    r = (op_t *) PyCObject_AsVoidPtr(attr);
  else
    r = NULL;
  Py_DECREF(attr);
  return r;
}

//</code(py_ua)>
%}

%pythoncode %{
#<pycode(py_ua)>

# -----------------------------------------------------------------------
class op_t(py_clinked_object_t):
    """Class representing operands"""
    def __init__(self, lnk = None):
        py_clinked_object_t.__init__(self, lnk)

    def _create_clink(self):
        return _idaapi.op_t_create()

    def _del_clink(self, lnk):
        return _idaapi.op_t_destroy(lnk)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _idaapi.op_t_assign(self, other)

#<pydoc>
#    def copy(self):
#        """Returns a new copy of this class"""
#        pass
#</pydoc>

    def __eq__(self, other):
        """Checks if two register operands are equal by checking the register number and its dtype"""
        return (self.reg == other.reg) and (self.dtyp == other.dtyp)

    def is_reg(self, r):
        """Checks if the register operand is the given processor register"""
        return self.type == idaapi.o_reg and self == r

    def has_reg(self, r):
        """Checks if the operand accesses the given processor register"""
        return self.reg == r.reg

    #
    # Autogenerated
    #
    def __get_n__(self):
        return _idaapi.op_t_get_n(self)
    def __set_n__(self, v):
        _idaapi.op_t_set_n(self, v)
    def __get_type__(self):
        return _idaapi.op_t_get_type(self)
    def __set_type__(self, v):
        _idaapi.op_t_set_type(self, v)
    def __get_offb__(self):
        return _idaapi.op_t_get_offb(self)
    def __set_offb__(self, v):
        _idaapi.op_t_set_offb(self, v)
    def __get_offo__(self):
        return _idaapi.op_t_get_offo(self)
    def __set_offo__(self, v):
        _idaapi.op_t_set_offo(self, v)
    def __get_flags__(self):
        return _idaapi.op_t_get_flags(self)
    def __set_flags__(self, v):
        _idaapi.op_t_set_flags(self, v)
    def __get_dtyp__(self):
        return _idaapi.op_t_get_dtyp(self)
    def __set_dtyp__(self, v):
        _idaapi.op_t_set_dtyp(self, v)
    def __get_reg_phrase__(self):
        return _idaapi.op_t_get_reg_phrase(self)
    def __set_reg_phrase__(self, v):
        _idaapi.op_t_set_reg_phrase(self, v)
    def __get_value__(self):
        return _idaapi.op_t_get_value(self)
    def __set_value__(self, v):
        _idaapi.op_t_set_value(self, v)
    def __get_addr__(self):
        return _idaapi.op_t_get_addr(self)
    def __set_addr__(self, v):
        _idaapi.op_t_set_addr(self, v)
    def __get_specval__(self):
        return _idaapi.op_t_get_specval(self)
    def __set_specval__(self, v):
        _idaapi.op_t_set_specval(self, v)
    def __get_specflag1__(self):
        return _idaapi.op_t_get_specflag1(self)
    def __set_specflag1__(self, v):
        _idaapi.op_t_set_specflag1(self, v)
    def __get_specflag2__(self):
        return _idaapi.op_t_get_specflag2(self)
    def __set_specflag2__(self, v):
        _idaapi.op_t_set_specflag2(self, v)
    def __get_specflag3__(self):
        return _idaapi.op_t_get_specflag3(self)
    def __set_specflag3__(self, v):
        _idaapi.op_t_set_specflag3(self, v)
    def __get_specflag4__(self):
        return _idaapi.op_t_get_specflag4(self)
    def __set_specflag4__(self, v):
        _idaapi.op_t_set_specflag4(self, v)

    n = property(__get_n__, __set_n__)
    type = property(__get_type__, __set_type__)
    offb = property(__get_offb__, __set_offb__)
    offo = property(__get_offo__, __set_offo__)
    flags = property(__get_flags__, __set_flags__)
    dtyp = property(__get_dtyp__, __set_dtyp__)
    reg = property(__get_reg_phrase__, __set_reg_phrase__)
    phrase = property(__get_reg_phrase__, __set_reg_phrase__)
    value = property(__get_value__, __set_value__)
    addr = property(__get_addr__, __set_addr__)
    specval = property(__get_specval__, __set_specval__)
    specflag1 = property(__get_specflag1__, __set_specflag1__)
    specflag2 = property(__get_specflag2__, __set_specflag2__)
    specflag3 = property(__get_specflag3__, __set_specflag3__)
    specflag4 = property(__get_specflag4__, __set_specflag4__)

# -----------------------------------------------------------------------
class insn_t(py_clinked_object_t):
    """Class representing instructions"""
    def __init__(self, lnk = None):
        py_clinked_object_t.__init__(self, lnk)

        # Create linked operands
        self.Operands = []
        for i in xrange(0, UA_MAXOP):
            self.Operands.append(op_t(insn_t_get_op_link(self.clink, i)))

        # Convenience operand reference objects
        self.Op1 = self.Operands[0]
        self.Op2 = self.Operands[1]
        self.Op3 = self.Operands[2]
        self.Op4 = self.Operands[3]
        self.Op5 = self.Operands[4]
        self.Op6 = self.Operands[5]

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _idaapi.insn_t_assign(self, other)

#<pydoc>
#    def copy(self):
#        """Returns a new copy of this class"""
#        pass
#</pydoc>

    def _create_clink(self):
        return _idaapi.insn_t_create()

    def _del_clink(self, lnk):
        return _idaapi.insn_t_destroy(lnk)

    def __getitem__(self, idx):
        """
        Operands can be accessed directly as indexes
        @return op_t: Returns an operand of type op_t
        """
        return self.Operands[idx]

    def is_macro(self):
        return self.flags & INSN_MACRO != 0

    def is_canon_insn(self):
        return _idaapi.insn_t_is_canon_insn(self.itype)

    def get_canon_feature(self):
        return _idaapi.insn_t_get_canon_feature(self.itype)

    def get_canon_mnem(self):
        return _idaapi.insn_t_get_canon_mnem(self.itype)

    #
    # Autogenerated
    #
    def __get_cs__(self):
        return _idaapi.insn_t_get_cs(self)
    def __set_cs__(self, v):
        _idaapi.insn_t_set_cs(self, v)
    def __get_ip__(self):
        return _idaapi.insn_t_get_ip(self)
    def __set_ip__(self, v):
        _idaapi.insn_t_set_ip(self, v)
    def __get_ea__(self):
        return _idaapi.insn_t_get_ea(self)
    def __set_ea__(self, v):
        _idaapi.insn_t_set_ea(self, v)
    def __get_itype__(self):
        return _idaapi.insn_t_get_itype(self)
    def __set_itype__(self, v):
        _idaapi.insn_t_set_itype(self, v)
    def __get_size__(self):
        return _idaapi.insn_t_get_size(self)
    def __set_size__(self, v):
        _idaapi.insn_t_set_size(self, v)
    def __get_auxpref__(self):
        return _idaapi.insn_t_get_auxpref(self)
    def __set_auxpref__(self, v):
        _idaapi.insn_t_set_auxpref(self, v)
    def __get_segpref__(self):
        return _idaapi.insn_t_get_segpref(self)
    def __set_segpref__(self, v):
        _idaapi.insn_t_set_segpref(self, v)
    def __get_insnpref__(self):
        return _idaapi.insn_t_get_insnpref(self)
    def __set_insnpref__(self, v):
        _idaapi.insn_t_set_insnpref(self, v)
    def __get_flags__(self):
        return _idaapi.insn_t_get_flags(self)
    def __set_flags__(self, v):
        _idaapi.insn_t_set_flags(self, v)

    cs = property(__get_cs__, __set_cs__)
    ip = property(__get_ip__, __set_ip__)
    ea = property(__get_ea__, __set_ea__)
    itype = property(__get_itype__, __set_itype__)
    size = property(__get_size__, __set_size__)
    auxpref = property(__get_auxpref__, __set_auxpref__)
    segpref = property(__get_segpref__, __set_segpref__)
    insnpref = property(__get_insnpref__, __set_insnpref__)
    flags = property(__get_flags__, __set_flags__)


#----------------------------------------------------------------------------
#               P R O C E S S O R  M O D U L E S  C O N S T A N T S
#----------------------------------------------------------------------------

# ----------------------------------------------------------------------
# processor_t related constants

CUSTOM_CMD_ITYPE    = 0x8000
REG_SPOIL           = 0x80000000

REAL_ERROR_FORMAT   = -1   #  not supported format for current .idp
REAL_ERROR_RANGE    = -2   #  number too big (small) for store (mem NOT modifyed)
REAL_ERROR_BADDATA  = -3   #  illegal real data for load (IEEE data not filled)

#
#  Check whether the operand is relative to stack pointer or frame pointer.
#  This function is used to determine how to output a stack variable
#  This function may be absent. If it is absent, then all operands
#  are sp based by default.
#  Define this function only if some stack references use frame pointer
#  instead of stack pointer.
#  returns flags:
OP_FP_BASED   = 0x00000000   #  operand is FP based
OP_SP_BASED   = 0x00000001   #  operand is SP based
OP_SP_ADD     = 0x00000000   #  operand value is added to the pointer
OP_SP_SUB     = 0x00000002   #  operand value is substracted from the pointer

# processor_t.id
PLFM_386        = 0x0       # Intel 80x86
PLFM_Z80        = 0x1       # 8085, Z80
PLFM_I860       = 0x2       # Intel 860
PLFM_8051       = 0x3       # 8051
PLFM_TMS        = 0x4       # Texas Instruments TMS320C5x
PLFM_6502       = 0x5       # 6502
PLFM_PDP        = 0x6       # PDP11
PLFM_68K        = 0x7       # Motoroal 680x0
PLFM_JAVA       = 0x8       # Java
PLFM_6800       = 0x9       # Motorola 68xx
PLFM_ST7        = 0x10      # SGS-Thomson ST7
PLFM_MC6812     = 0x11      # Motorola 68HC12
PLFM_MIPS       = 0x12      # MIPS
PLFM_ARM        = 0x13      # Advanced RISC Machines
PLFM_TMSC6      = 0x14      # Texas Instruments TMS320C6x
PLFM_PPC        = 0x15      # PowerPC
PLFM_80196      = 0x16      # Intel 80196
PLFM_Z8         = 0x17      # Z8
PLFM_SH         = 0x18      # Renesas (formerly Hitachi) SuperH
PLFM_NET        = 0x19      # Microsoft Visual Studio.Net
PLFM_AVR        = 0x20      # Atmel 8-bit RISC processor(s)
PLFM_H8         = 0x21      # Hitachi H8/300, H8/2000
PLFM_PIC        = 0x22      # Microchip's PIC
PLFM_SPARC      = 0x23      # SPARC
PLFM_ALPHA      = 0x24      # DEC Alpha
PLFM_HPPA       = 0x25      # Hewlett-Packard PA-RISC
PLFM_H8500      = 0x26      # Hitachi H8/500
PLFM_TRICORE    = 0x27      # Tasking Tricore
PLFM_DSP56K     = 0x28      # Motorola DSP5600x
PLFM_C166       = 0x29      # Siemens C166 family
PLFM_ST20       = 0x30      # SGS-Thomson ST20
PLFM_IA64       = 0x31      # Intel Itanium IA64
PLFM_I960       = 0x32      # Intel 960
PLFM_F2MC       = 0x33      # Fujistu F2MC-16
PLFM_TMS320C54  = 0x34      # Texas Instruments TMS320C54xx
PLFM_TMS320C55  = 0x35      # Texas Instruments TMS320C55xx
PLFM_TRIMEDIA   = 0x36      # Trimedia
PLFM_M32R       = 0x37      # Mitsubishi 32bit RISC
PLFM_NEC_78K0   = 0x38      # NEC 78K0
PLFM_NEC_78K0S  = 0x39      # NEC 78K0S
PLFM_M740       = 0x40      # Mitsubishi 8bit
PLFM_M7700      = 0x41      # Mitsubishi 16bit
PLFM_ST9        = 0x42      # ST9+
PLFM_FR         = 0x43      # Fujitsu FR Family
PLFM_MC6816     = 0x44      # Motorola 68HC16
PLFM_M7900      = 0x45      # Mitsubishi 7900
PLFM_TMS320C3   = 0x46      # Texas Instruments TMS320C3
PLFM_KR1878     = 0x47      # Angstrem KR1878
PLFM_AD218X     = 0x48      # Analog Devices ADSP 218X
PLFM_OAKDSP     = 0x49      # Atmel OAK DSP
PLFM_TLCS900    = 0x50      # Toshiba TLCS-900
PLFM_C39        = 0x51      # Rockwell C39
PLFM_CR16       = 0x52      # NSC CR16
PLFM_MN102L00   = 0x53      # Panasonic MN10200
PLFM_TMS320C1X  = 0x54      # Texas Instruments TMS320C1x
PLFM_NEC_V850X  = 0x55      # NEC V850 and V850ES/E1/E2
PLFM_SCR_ADPT   = 0x56      # Processor module adapter for processor modules written in scripting languages
PLFM_EBC        = 0x57      # EFI Bytecode
PLFM_MSP430     = 0x58      # Texas Instruments MSP430

#
# processor_t.flag
#
PR_SEGS        = 0x000001    #  has segment registers?
PR_USE32       = 0x000002    #  supports 32-bit addressing?
PR_DEFSEG32    = 0x000004    #  segments are 32-bit by default
PR_RNAMESOK    = 0x000008    #  allow to user register names for location names
PR_ADJSEGS     = 0x000020    #  IDA may adjust segments moving their starting/ending addresses.
PR_DEFNUM      = 0x0000C0    #  default number representation:
PRN_HEX        = 0x000000    #       hex
PRN_OCT        = 0x000040    #       octal
PRN_DEC        = 0x000080    #       decimal
PRN_BIN        = 0x0000C0    #       binary
PR_WORD_INS    = 0x000100    #  instruction codes are grouped 2bytes in binrary line prefix
PR_NOCHANGE    = 0x000200    #  The user can't change segments and code/data attributes (display only)
PR_ASSEMBLE    = 0x000400    #  Module has a built-in assembler and understands IDP_ASSEMBLE
PR_ALIGN       = 0x000800    #  All data items should be aligned properly
PR_TYPEINFO    = 0x001000    #  the processor module supports
                             #     type information callbacks
                             #     ALL OF THEM SHOULD BE IMPLEMENTED!
                             #     (the ones >= decorate_name)
PR_USE64       = 0x002000    #  supports 64-bit addressing?
PR_SGROTHER    = 0x004000    #  the segment registers don't contain
                             #     the segment selectors, something else
PR_STACK_UP    = 0x008000    #  the stack grows up
PR_BINMEM      = 0x010000    #  the processor module provides correct
                             #     segmentation for binary files
                             #     (i.e. it creates additional segments)
                             #     The kernel will not ask the user
                             #     to specify the RAM/ROM sizes
PR_SEGTRANS    = 0x020000    #  the processor module supports
                             #     the segment translation feature
                             #     (it means it calculates the code
                             #     addresses using the codeSeg() function)
PR_CHK_XREF    = 0x040000    #  don't allow near xrefs between segments
                             #     with different bases
PR_NO_SEGMOVE  = 0x080000    #  the processor module doesn't support move_segm()
                             #     (i.e. the user can't move segments)
PR_FULL_HIFXP  = 0x100000    #  REF_VHIGH operand value contains full operand
                             #     not only the high bits. Meaningful if ph.high_fixup_bits
PR_USE_ARG_TYPES = 0x200000  #  use ph.use_arg_types callback
PR_SCALE_STKVARS = 0x400000  #  use ph.get_stkvar_scale callback
PR_DELAYED     = 0x800000    #  has delayed jumps and calls
PR_ALIGN_INSN  = 0x1000000   #  allow ida to create alignment instructions
                             #     arbirtrarily. Since these instructions
                             #     might lead to other wrong instructions
                             #     and spoil the listing, IDA does not create
                             #     them by default anymore
PR_PURGING     = 0x2000000   #  there are calling conventions which may
                             #     purge bytes from the stack
PR_CNDINSNS    = 0x4000000   #  has conditional instructions
PR_USE_TBYTE   = 0x8000000   #  BTMT_SPECFLT means _TBYTE type
PR_DEFSEG64    = 0x10000000  #  segments are 64-bit by default


# ----------------------------------------------------------------------
#
# Misc constants
#
UA_MAXOP   = 6
"""The maximum number of operands in the insn_t structure"""

# Create 'cmd' into the global scope
cmd = insn_t(_idaapi.py_get_global_cmd_link())
"""cmd is a global variable of type insn_t. It is contains information about the last decoded instruction.
This variable is also filled by processor modules when they decode instructions."""

# ----------------------------------------------------------------------
# instruc_t related constants

#
# instruc_t.feature
#
CF_STOP = 0x00001 #  Instruction doesn't pass execution to the next instruction
CF_CALL = 0x00002 #  CALL instruction (should make a procedure here)
CF_CHG1 = 0x00004 #  The instruction modifies the first operand
CF_CHG2 = 0x00008 #  The instruction modifies the second operand
CF_CHG3 = 0x00010 #  The instruction modifies the third operand
CF_CHG4 = 0x00020 #  The instruction modifies 4 operand
CF_CHG5 = 0x00040 #  The instruction modifies 5 operand
CF_CHG6 = 0x00080 #  The instruction modifies 6 operand
CF_USE1 = 0x00100 #  The instruction uses value of the first operand
CF_USE2 = 0x00200 #  The instruction uses value of the second operand
CF_USE3 = 0x00400 #  The instruction uses value of the third operand
CF_USE4 = 0x00800 #  The instruction uses value of the 4 operand
CF_USE5 = 0x01000 #  The instruction uses value of the 5 operand
CF_USE6 = 0x02000 #  The instruction uses value of the 6 operand
CF_JUMP = 0x04000 #  The instruction passes execution using indirect jump or call (thus needs additional analysis)
CF_SHFT = 0x08000 #  Bit-shift instruction (shl,shr...)
CF_HLL  = 0x10000 #  Instruction may be present in a high level language function.

# ----------------------------------------------------------------------
# op_t related constants

#
# op_t.type
#                  Description                          Data field
o_void     =  0 #  No Operand                           ----------
o_reg      =  1 #  General Register (al,ax,es,ds...)    reg
o_mem      =  2 #  Direct Memory Reference  (DATA)      addr
o_phrase   =  3 #  Memory Ref [Base Reg + Index Reg]    phrase
o_displ    =  4 #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
o_imm      =  5 #  Immediate Value                      value
o_far      =  6 #  Immediate Far Address  (CODE)        addr
o_near     =  7 #  Immediate Near Address (CODE)        addr
o_idpspec0 =  8 #  IDP specific type
o_idpspec1 =  9 #  IDP specific type
o_idpspec2 = 10 #  IDP specific type
o_idpspec3 = 11 #  IDP specific type
o_idpspec4 = 12 #  IDP specific type
o_idpspec5 = 13 #  IDP specific type
o_last     = 14 #  first unused type

#
# op_t.dtyp
#
dt_byte = 0 #  8 bit
dt_word = 1 #  16 bit
dt_dword = 2 #  32 bit
dt_float = 3 #  4 byte
dt_double = 4 #  8 byte
dt_tbyte = 5 #  variable size (ph.tbyte_size)
dt_packreal = 6 #  packed real format for mc68040
dt_qword = 7 #  64 bit
dt_byte16 = 8 #  128 bit
dt_code = 9 #  ptr to code (not used?)
dt_void = 10 #  none
dt_fword = 11 #  48 bit
dt_bitfild = 12 #  bit field (mc680x0)
dt_string = 13 #  pointer to asciiz string
dt_unicode = 14 #  pointer to unicode string
dt_3byte = 15 #  3-byte data
dt_ldbl = 16 #  long double (which may be different from tbyte)

#
# op_t.flags
#
OF_NO_BASE_DISP = 0x80 #  o_displ: base displacement doesn't exist meaningful only for o_displ type if set, base displacement (x.addr) doesn't exist.
OF_OUTER_DISP = 0x40 #  o_displ: outer displacement exists meaningful only for o_displ type if set, outer displacement (x.value) exists.
PACK_FORM_DEF = 0x20 #  !o_reg + dt_packreal: packed factor defined
OF_NUMBER = 0x10 # can be output as number only if set, the operand can be converted to a number only
OF_SHOW = 0x08 #  should the operand be displayed? if clear, the operand is hidden and should not be displayed

#
# insn_t.flags
#
INSN_MACRO  = 0x01   # macro instruction
INSN_MODMAC = 0x02   # macros: may modify the database to make room for the macro insn

#
# Set IDP options constants
#
IDPOPT_STR        =  1    # string constant
IDPOPT_NUM        =  2    # number
IDPOPT_BIT        =  3    # bit, yes/no
IDPOPT_FLT        =  4    # float
IDPOPT_I64        =  5    # 64bit number

IDPOPT_OK         =  0    # ok
IDPOPT_BADKEY     =  1    # illegal keyword
IDPOPT_BADTYPE    =  2    # illegal type of value
IDPOPT_BADVALUE   =  3    # illegal value (bad range, for example)

# ----------------------------------------------------------------------
class processor_t(pyidc_opaque_object_t):
    """Base class for all processor module scripts"""
    def __init__(self):
        # Take a reference to 'cmd'
        self.cmd = cmd

    def get_idpdesc(self):
        """
        This function must be present and should return the list of
        short processor names similar to the one in ph.psnames.
        This method can be overridden to return to the kernel a different IDP description.
        """
        return self.plnames[0] + ':' + ':'.join(self.psnames)

    def get_uFlag(self):
        """Use this utility function to retrieve the 'uFlag' global variable"""
        return _idaapi.cvar.uFlag

    def get_auxpref(self):
        """This function returns cmd.auxpref value"""
        return self.cmd.auxpref

#</pycode(py_ua)>
%}
