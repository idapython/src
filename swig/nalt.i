%ignore nmSerEA;
%ignore nmSerN;
%ignore maxSerialName;
%ignore get_import_module_name;
%rename (get_import_module_name) py_get_import_module_name;
%ignore NALT_EA;
%ignore enum_import_names;
%rename (enum_import_names) py_enum_import_names;
%ignore custom_refinfo_handler_t;
%ignore custom_refinfo_handlers_t;
%ignore register_custom_refinfo;
%ignore unregister_custom_refinfo;
%ignore get_custom_refinfos;

%template (ids_array) wrapped_array_t<tid_t,32>;

%extend strpath_t {
  wrapped_array_t<tid_t,32> __getIds() {
    return wrapped_array_t<tid_t,32>($self->ids);
  }

  %pythoncode {
    ids = property(__getIds)
  }
}

%include "nalt.hpp"

%{
//<code(py_nalt)>

//-------------------------------------------------------------------------
// callback for enumerating imports
// ea:   import address
// name: import name (NULL if imported by ordinal)
// ord:  import ordinal (0 for imports by name)
// param: user parameter passed to enum_import_names()
// return: 1-ok, 0-stop enumeration
static int idaapi py_import_enum_cb(
  ea_t ea,
  const char *name,
  uval_t ord,
  void *param)
{
  // If no name, try to get the name associated with the 'ea'. It may be coming from IDS
  char name_buf[MAXSTR];
  if ( name == NULL )
    name = get_true_name(BADADDR, ea, name_buf, sizeof(name_buf));

  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_name;
  if ( name == NULL )
    py_name = borref_t(Py_None);
  else
    py_name = newref_t(PyString_FromString(name));

  newref_t py_ord(Py_BuildValue(PY_FMT64, pyul_t(ord)));
  newref_t py_ea(Py_BuildValue(PY_FMT64, pyul_t(ea)));
  newref_t py_result(
          PyObject_CallFunctionObjArgs(
                  (PyObject *)param,
                  py_ea.o,
                  py_name.o,
                  py_ord.o,
                  NULL));
  return py_result != NULL && PyObject_IsTrue(py_result.o) ? 1 : 0;
}

//-------------------------------------------------------------------------
switch_info_ex_t *switch_info_ex_t_get_clink(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyObject_HasAttrString(self, S_CLINK_NAME) )
    return NULL;

  switch_info_ex_t *r;
  newref_t attr(PyObject_GetAttrString(self, S_CLINK_NAME));
  return PyCObject_Check(attr.o) ? ((switch_info_ex_t *) PyCObject_AsVoidPtr(attr.o)) : NULL;
}
//</code(py_nalt)>
%}

%rename (get_switch_info_ex)  py_get_switch_info_ex;
%rename (set_switch_info_ex)  py_set_switch_info_ex;
%rename (del_switch_info_ex)  py_del_switch_info_ex;
%rename (create_switch_xrefs) py_create_switch_xrefs;
%rename (create_switch_table) py_create_switch_table;
%rename (calc_switch_cases)   py_calc_switch_cases;

%inline %{
//<inline(py_nalt)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_import_module_name(path, fname, callback):
    """
    Returns the name of an imported module given its index
    @return: None or the module name
    """
    pass
#</pydoc>
*/
static PyObject *py_get_import_module_name(int mod_index)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  char buf[MAXSTR];
  if ( !get_import_module_name(mod_index, buf, sizeof(buf)) )
    Py_RETURN_NONE;

  return PyString_FromString(buf);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_switch_info_ex(ea):
    """
    Returns the a switch_info_ex_t structure containing the information about the switch.
    Please refer to the SDK sample 'uiswitch'
    @return: None or switch_info_ex_t instance
    """
    pass
#</pydoc>
*/
PyObject *py_get_switch_info_ex(ea_t ea)
{
  switch_info_ex_t *ex = new switch_info_ex_t();
  ref_t py_obj;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ::get_switch_info_ex(ea, ex, sizeof(switch_info_ex_t)) <= 0
    || (py_obj = create_idaapi_linked_class_instance(S_PY_SWIEX_CLSNAME, ex)) == NULL )
  {
    delete ex;
    Py_RETURN_NONE;
  }
  py_obj.incref();
  return py_obj.o;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def create_switch_xrefs(insn_ea, si):
    """
    This function creates xrefs from the indirect jump.

    Usually there is no need to call this function directly because the kernel
    will call it for switch tables

    Note: Custom switch information are not supported yet.

    @param insn_ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass
#</pydoc>
*/
idaman bool ida_export py_create_switch_xrefs(
  ea_t insn_ea,
  PyObject *py_swi)
{
  switch_info_ex_t *swi = switch_info_ex_t_get_clink(py_swi);
  if ( swi == NULL )
    return false;

  create_switch_xrefs(insn_ea, swi);
  return true;
}

//-------------------------------------------------------------------------
struct cases_and_targets_t
{
  casevec_t cases;
  eavec_t targets;
};

//-------------------------------------------------------------------------
/*
#<pydoc>
def calc_switch_cases(insn_ea, si):
    """
    Get information about a switch's cases.

    The returned information can be used as follows:

        for idx in xrange(len(results.cases)):
            cur_case = results.cases[idx]
            for cidx in xrange(len(cur_case)):
                print "case: %d" % cur_case[cidx]
            print "  goto 0x%x" % results.targets[idx]

    @param insn_ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: a structure with 2 members: 'cases', and 'targets'.
    """
    pass
#</pydoc>
*/
idaman cases_and_targets_t *ida_export py_calc_switch_cases(
  ea_t insn_ea,
  PyObject *py_swi)
{
  switch_info_ex_t *swi = switch_info_ex_t_get_clink(py_swi);
  if ( swi == NULL )
    return NULL;

  cases_and_targets_t *ct = new cases_and_targets_t;
  if ( !calc_switch_cases(insn_ea, swi, &ct->cases, &ct->targets) )
  {
    delete ct;
    return NULL;
  }

  return ct;
}


//-------------------------------------------------------------------------
/*
#<pydoc>
def create_switch_table(insn_ea, si):
    """
    Create switch table from the switch information

    @param insn_ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass
#</pydoc>
*/
idaman bool ida_export py_create_switch_table(
  ea_t insn_ea,
  PyObject *py_swi)
{
  switch_info_ex_t *swi = switch_info_ex_t_get_clink(py_swi);
  if ( swi == NULL )
    return false;

  create_switch_table(insn_ea, swi);
  return true;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def set_switch_info_ex(ea, switch_info_ex):
    """
    Saves the switch information in the database
    Please refer to the SDK sample 'uiswitch'
    @return: Boolean
    """
    pass
#</pydoc>
*/
bool py_set_switch_info_ex(ea_t ea, PyObject *py_swi)
{
  switch_info_ex_t *swi = switch_info_ex_t_get_clink(py_swi);
  if ( swi == NULL )
    return false;

  set_switch_info_ex(ea, swi);
  return true;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def del_switch_info_ex(ea):
    """
    Deletes stored switch information
    """
    pass
#</pydoc>
*/
void py_del_switch_info_ex(ea_t ea)
{
  del_switch_info_ex(ea);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def enum_import_names(mod_index, callback):
    """
    Enumerate imports from a specific module.
    Please refer to ex_imports.py example.

    @param mod_index: The module index
    @param callback: A callable object that will be invoked with an ea, name (could be None) and ordinal.
    @return: 1-finished ok, -1 on error, otherwise callback return value (<=0)
    """
    pass
#</pydoc>
*/
static int py_enum_import_names(int mod_index, PyObject *py_cb)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCallable_Check(py_cb) )
    return -1;
  return enum_import_names(mod_index, py_import_enum_cb, py_cb);
}

//-------------------------------------------------------------------------
static PyObject *switch_info_ex_t_create()
{
  switch_info_ex_t *inst = new switch_info_ex_t();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyCObject_FromVoidPtr(inst, NULL);
}

//---------------------------------------------------------------------------
static bool switch_info_ex_t_destroy(PyObject *py_obj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCObject_Check(py_obj) )
    return false;
  switch_info_ex_t *inst = (switch_info_ex_t *) PyCObject_AsVoidPtr(py_obj);
  delete inst;
  return true;
}

static bool switch_info_ex_t_assign(PyObject *self, PyObject *other)
{
  switch_info_ex_t *lhs = switch_info_ex_t_get_clink(self);
  switch_info_ex_t *rhs = switch_info_ex_t_get_clink(other);
  if (lhs == NULL || rhs == NULL)
    return false;

  *lhs = *rhs;
  return true;
}

//-------------------------------------------------------------------------
// Auto generated - begin
//

static PyObject *switch_info_ex_t_get_regdtyp(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("b", (char)link->regdtyp);
}
static void switch_info_ex_t_set_regdtyp(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  link->regdtyp = (char)PyInt_AsLong(value);
}

static PyObject *switch_info_ex_t_get_flags2(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("i", link->flags2);
}
static void switch_info_ex_t_set_flags2(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  link->flags2 = (int)PyInt_AsLong(value);
}

static PyObject *switch_info_ex_t_get_jcases(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("i", link->jcases);
}
static void switch_info_ex_t_set_jcases(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  link->jcases = (int)PyInt_AsLong(value);
}

static PyObject *switch_info_ex_t_get_regnum(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("i", (int)link->regnum);
}
static void switch_info_ex_t_set_regnum(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  link->regnum = (int)PyInt_AsLong(value);
}

static PyObject *switch_info_ex_t_get_flags(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("H", (ushort)link->flags);
}
static void switch_info_ex_t_set_flags(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  link->flags = (uint16)PyInt_AsLong(value);
}

static PyObject *switch_info_ex_t_get_ncases(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue("H", (uint16)link->ncases);
}
static void switch_info_ex_t_set_ncases(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  link->ncases = (ushort)PyInt_AsLong(value);
}

static PyObject *switch_info_ex_t_get_defjump(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->defjump);
}
static void switch_info_ex_t_set_defjump(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  uint64 v(0); PyW_GetNumber(value, &v);
  link->defjump = (pyul_t)v;
}

static PyObject *switch_info_ex_t_get_jumps(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->jumps);
}
static void switch_info_ex_t_set_jumps(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  uint64 v(0); PyW_GetNumber(value, &v);
  link->jumps = (pyul_t)v;
}

static PyObject *switch_info_ex_t_get_elbase(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->elbase);
}
static void switch_info_ex_t_set_elbase(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyW_GetNumber(value, &v);
  link->elbase = (pyul_t)v;
}

static PyObject *switch_info_ex_t_get_startea(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->startea);
}
static void switch_info_ex_t_set_startea(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyW_GetNumber(value, &v);
  link->startea = (pyul_t)v;
}

static PyObject *switch_info_ex_t_get_custom(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->custom);
}
static void switch_info_ex_t_set_custom(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyW_GetNumber(value, &v);
  link->custom = (pyul_t)v;
}

static PyObject *switch_info_ex_t_get_ind_lowcase(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->ind_lowcase);
}
static void switch_info_ex_t_set_ind_lowcase(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyW_GetNumber(value, &v);
  link->ind_lowcase = (pyul_t)v;
}

static PyObject *switch_info_ex_t_get_values_lowcase(PyObject *self)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_FMT64, (pyul_t)link->values);
}
static void switch_info_ex_t_set_values_lowcase(PyObject *self, PyObject *value)
{
  switch_info_ex_t *link = switch_info_ex_t_get_clink(self);
  if ( link == NULL )
    return;
  uint64 v(0);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyW_GetNumber(value, &v);
  link->values = (pyul_t)v;
}

//
// Auto generated - end
//
//-------------------------------------------------------------------------
//</inline(py_nalt)>
%}

%pythoncode %{
#<pycode(py_nalt)>
SWI_SPARSE      = 0x1
"""sparse switch ( value table present ) otherwise lowcase present"""
SWI_V32         = 0x2
"""32-bit values in table"""
SWI_J32         = 0x4
"""32-bit jump offsets"""
SWI_VSPLIT      = 0x8
"""value table is split (only for 32-bit values)"""
SWI_DEFAULT     = 0x10
"""default case is present"""
SWI_END_IN_TBL  = 0x20
"""switchend in table (default entry)"""
SWI_JMP_INV     = 0x40
"""jumptable is inversed (last entry is for first entry in values table)"""
SWI_SHIFT_MASK  = 0x180
"""use formula (element*shift + elbase) to find jump targets"""

SWI_ELBASE      = 0x200
"""elbase is present (if not and shift!=0, endof(jumpea) is used)"""
SWI_JSIZE       = 0x400
"""jump offset expansion bit"""

SWI_VSIZE       = 0x800
"""value table element size expansion bit"""

SWI_SEPARATE    = 0x1000
"""do not create an array of individual dwords"""

SWI_SIGNED      = 0x2000
"""jump table entries are signed"""

SWI_CUSTOM      = 0x4000
"""custom jump table - ph.create_switch_xrefs will be called to create code xrefs for the table. it must return 2. custom jump table must be created by the module"""

SWI_EXTENDED    = 0x8000
"""this is switch_info_ex_t"""

SWI2_INDIRECT = 0x0001
"""value table elements are used as indexes into the jump table"""
SWI2_SUBTRACT = 0x0002
"""table values are subtracted from the elbase instead of being addded"""

# --------------------------------------------------------------------------
class switch_info_ex_t(py_clinked_object_t):
    def __init__(self, lnk = None):
        py_clinked_object_t.__init__(self, lnk)

    def _create_clink(self):
        return _idaapi.switch_info_ex_t_create()

    def _del_clink(self, lnk):
        return _idaapi.switch_info_ex_t_destroy(lnk)

    def assign(self, other):
        return _idaapi.switch_info_ex_t_assign(self, other)

    def is_indirect(self):
        return (self.flags & SWI_EXTENDED) != 0 and (self.flags2 & SWI2_INDIRECT) != 0

    def is_subtract(self):
        return (self.flags & SWI_EXTENDED) != 0 and (self.flags2 & SWI2_SUBTRACT) != 0

    def get_jtable_size(self):
        return self.jcases if self.is_indirect() else self.ncases

    def get_lowcase(self):
        return self.ind_lowcase if self.is_indirect() else self.lowcase

    def set_expr(self, r, dt):
        self.regnum = r
        self.regdtyp = dt

    def get_shift(self):
        return (self.flags & SWI_SHIFT_MASK) >> 7

    def set_shift(self, shift):
        self.flags &= ~SWI_SHIFT_MASK
        self.flags |= ((shift & 3) << 7)

    def get_jtable_element_size(self):
        code = self.flags & (SWI_J32|SWI_JSIZE)
        if   code == 0:         return 2
        elif code == SWI_J32:   return 4
        elif code == SWI_JSIZE: return 1
        else:                   return 8

    def set_jtable_element_size(self, size):
        self.flags &= ~(SWI_J32|SWI_JSIZE)
        if size == 4:   self.flags |= SWI_J32
        elif size == 1: self.flags |= SWI_JSIZE
        elif size == 8: self.flags |= SWI_J32|SWI_JSIZE
        elif size != 2: return False
        return True

    def get_vtable_element_size(self):
        code = self.flags & (SWI_V32|SWI_VSIZE)
        if   code == 0:         return 2
        elif code == SWI_V32:   return 4
        elif code == SWI_VSIZE: return 1
        return 8

    def set_vtable_element_size(self, size):
        self.flags &= ~SWI_V32|SWI_VSIZE
        if size == 4:   self.flags |= SWI_V32
        elif size == 1: self.flags |= SWI_VSIZE
        elif size == 8: self.flags |= SWI_V32|SWI_VSIZE
        elif size != 2: return False
        return True

    #
    # Autogenerated
    #
    def __get_regdtyp__(self):
        return _idaapi.switch_info_ex_t_get_regdtyp(self)
    def __set_regdtyp__(self, v):
        _idaapi.switch_info_ex_t_set_regdtyp(self, v)
    def __get_flags2__(self):
        return _idaapi.switch_info_ex_t_get_flags2(self)
    def __set_flags2__(self, v):
        _idaapi.switch_info_ex_t_set_flags2(self, v)
    def __get_jcases__(self):
        return _idaapi.switch_info_ex_t_get_jcases(self)
    def __set_jcases__(self, v):
        _idaapi.switch_info_ex_t_set_jcases(self, v)
    def __get_regnum__(self):
        return _idaapi.switch_info_ex_t_get_regnum(self)
    def __set_regnum__(self, v):
        _idaapi.switch_info_ex_t_set_regnum(self, v)
    def __get_flags__(self):
        return _idaapi.switch_info_ex_t_get_flags(self)
    def __set_flags__(self, v):
        _idaapi.switch_info_ex_t_set_flags(self, v)
    def __get_ncases__(self):
        return _idaapi.switch_info_ex_t_get_ncases(self)
    def __set_ncases__(self, v):
        _idaapi.switch_info_ex_t_set_ncases(self, v)
    def __get_defjump__(self):
        return _idaapi.switch_info_ex_t_get_defjump(self)
    def __set_defjump__(self, v):
        _idaapi.switch_info_ex_t_set_defjump(self, v)
    def __get_jumps__(self):
        return _idaapi.switch_info_ex_t_get_jumps(self)
    def __set_jumps__(self, v):
        _idaapi.switch_info_ex_t_set_jumps(self, v)
    def __get_elbase__(self):
        return _idaapi.switch_info_ex_t_get_elbase(self)
    def __set_elbase__(self, v):
        _idaapi.switch_info_ex_t_set_elbase(self, v)
    def __get_startea__(self):
        return _idaapi.switch_info_ex_t_get_startea(self)
    def __set_startea__(self, v):
        _idaapi.switch_info_ex_t_set_startea(self, v)
    def __get_custom__(self):
        return _idaapi.switch_info_ex_t_get_custom(self)
    def __set_custom__(self, v):
        _idaapi.switch_info_ex_t_set_custom(self, v)
    def __get_ind_lowcase__(self):
        return _idaapi.switch_info_ex_t_get_ind_lowcase(self)
    def __set_ind_lowcase__(self, v):
        _idaapi.switch_info_ex_t_set_ind_lowcase(self, v)
    def __get_values_lowcase__(self):
        return _idaapi.switch_info_ex_t_get_values_lowcase(self)
    def __set_values_lowcase__(self, v):
        _idaapi.switch_info_ex_t_set_values_lowcase(self, v)
    regdtyp = property(__get_regdtyp__, __set_regdtyp__)
    """size of the switch expression register as dtyp"""
    flags2 = property(__get_flags2__, __set_flags2__)
    jcases = property(__get_jcases__, __set_jcases__)
    """number of entries in the jump table (SWI2_INDIRECT)"""
    regnum = property(__get_regnum__, __set_regnum__)
    """the switch expression as a register number"""
    flags = property(__get_flags__, __set_flags__)
    """the switch expression as a register number"""
    ncases = property(__get_ncases__, __set_ncases__)
    """number of cases (excluding default)"""
    defjump = property(__get_defjump__, __set_defjump__)
    """default jump address"""
    jumps = property(__get_jumps__, __set_jumps__)
    """jump table address"""
    elbase = property(__get_elbase__, __set_elbase__)
    """element base"""
    startea = property(__get_startea__, __set_startea__)
    """start of switch idiom"""
    custom = property(__get_custom__, __set_custom__)
    """information for custom tables (filled and used by modules)"""
    ind_lowcase = property(__get_ind_lowcase__, __set_ind_lowcase__)
    values = property(__get_values_lowcase__, __set_values_lowcase__)
    lowcase = property(__get_values_lowcase__, __set_values_lowcase__)

#</pycode(py_nalt)>
%}