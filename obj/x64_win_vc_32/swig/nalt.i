%module(docstring="IDA Plugin SDK API wrapper: nalt",directors="1",threads="1") ida_nalt
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_NALT
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_NALT
  #define HAS_DEP_ON_INTERFACE_NALT
#endif
%include "header.i"
%{
#include <nalt.hpp>
#include <name.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include "../../../pywraps.hpp"
%}

%ignore get_import_module_name;
%rename (get_import_module_name) py_get_import_module_name;
%ignore enum_import_names;
%rename (enum_import_names) py_enum_import_names;

%ignore calc_nodeidx;

%ignore get_wide_value;
%ignore set_wide_value;
%ignore del_wide_value;

%ignore get_strid;
%ignore _set_strid;
%ignore _del_strid;
%ignore xrefpos_t;
%ignore get_xrefpos;
%ignore set_xrefpos;
%ignore del_xrefpos;

%ignore set_aflags0;
%ignore get_aflags0;
%ignore del_aflags0;

%ignore get_linnum0;
%ignore set_linnum0;
%ignore del_linnum0;

%ignore get_enum_id0;
%ignore set_enum_id0;
%ignore del_enum_id0;
%ignore get_enum_id1;
%ignore set_enum_id1;
%ignore del_enum_id1;

%ignore set_ind_purged;

%ignore _get_item_color;
%ignore _set_item_color;
%ignore _del_item_color;

%ignore get_nalt_cmt;
%ignore set_nalt_cmt;
%ignore del_nalt_cmt;
%ignore get_nalt_rptcmt;
%ignore set_nalt_rptcmt;
%ignore del_nalt_rptcmt;
%ignore get_manual_insn0;
%ignore set_manual_insn0;
%ignore del_manual_insn0;
%ignore get_graph_groups0;
%ignore set_graph_groups0;
%ignore del_graph_groups0;

%ignore jumptable_info_t;
%ignore del_jumptable_info;
%ignore set_jumptable_info;
%ignore get_jumptable_info;

%ignore refinfo_t::_get_target;
%ignore refinfo_t::_get_value;
%ignore refinfo_t::_get_opval;

%ignore custom_refinfo_handler_t;
%ignore custom_refinfo_handlers_t;
%ignore register_custom_refinfo;
%ignore unregister_custom_refinfo;
%ignore get_custom_refinfo_handler;
%ignore refinfo_desc_t;
%ignore get_refinfo_descs;

%ignore write_struc_path;
%ignore read_struc_path;
%ignore del_struc_path;
%ignore get_stroff0;
%ignore set_stroff0;
%ignore del_stroff0;
%ignore get_stroff1;
%ignore set_stroff1;
%ignore del_stroff1;

%ignore get__segtrans;
%ignore set__segtrans;
%ignore del__segtrans;

%ignore validate_idb_names;
%rename (validate_idb_names) validate_idb_names2;

%template (custom_data_type_ids_fids_array) wrapped_array_t<int16,UA_MAXOP>;

%extend custom_data_type_ids_t {
  wrapped_array_t<int16,UA_MAXOP> __getFids() {
    return wrapped_array_t<int16,UA_MAXOP>($self->fids);
  }

  %pythoncode {
    fids = property(__getFids)
  }
}

%template (strpath_ids_array) wrapped_array_t<tid_t,32>;

%extend strpath_t {
  wrapped_array_t<tid_t,32> __getIds() {
    return wrapped_array_t<tid_t,32>($self->ids);
  }

  %pythoncode {
    ids = property(__getIds)
  }
}

%ignore switch_info_t::version;

%apply uchar { op_dtype_t regdtype };

%extend switch_info_t
{
  void assign(const switch_info_t &other) { *($self) = other; }
  ea_t _get_values_lowcase() const { return $self->values; }
  void _set_values_lowcase(ea_t values) { $self->values = values; }

  %pythoncode {
    values = property(_get_values_lowcase, _set_values_lowcase)
    lowcase = property(_get_values_lowcase, _set_values_lowcase)
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
  qstring name_buf;
  if ( name == NULL && get_name(&name_buf, ea) > 0 )
    name = name_buf.begin();

  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_name;
  if ( name == NULL )
    py_name = borref_t(Py_None);
  else
    py_name = newref_t(IDAPyStr_FromUTF8(name));

  newref_t py_ord(Py_BuildValue(PY_BV_UVAL, bvuval_t(ord)));
  newref_t py_ea(Py_BuildValue(PY_BV_EA, bvea_t(ea)));
  newref_t py_result(
          PyObject_CallFunctionObjArgs(
                  (PyObject *)param,
                  py_ea.o,
                  py_name.o,
                  py_ord.o,
                  NULL));
  return py_result != NULL && PyObject_IsTrue(py_result.o) ? 1 : 0;
}
//</code(py_nalt)>
%}

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
  qstring qbuf;
  if ( !get_import_module_name(&qbuf, mod_index) )
    Py_RETURN_NONE;

  return IDAPyStr_FromUTF8AndSize(qbuf.begin(), qbuf.length());
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
static switch_info_t *switch_info_t__from_ptrval__(size_t ptrval)
{
  return (switch_info_t *) ptrval;
}
//</inline(py_nalt)>
%}

%pythoncode %{
#<pycode(py_nalt)>
_real_get_switch_info = get_switch_info
def get_switch_info(*args):
    if len(args) == 1:
        si, ea = switch_info_t(), args[0]
    else:
        si, ea = args
    return None if _real_get_switch_info(si, ea) <= 0 else si
def get_abi_name(*args):
    import ida_typeinf
    return ida_typeinf.get_abi_name(args)
#</pycode(py_nalt)>
%}
%pythoncode %{
if _BC695:
    ASCSTR_LAST=7
    ASCSTR_LEN2=STRTYPE_LEN2
    ASCSTR_LEN4=STRTYPE_LEN4
    ASCSTR_PASCAL=STRTYPE_PASCAL
    ASCSTR_TERMCHR=STRTYPE_TERMCHR
    ASCSTR_ULEN2=STRTYPE_LEN2_16
    ASCSTR_ULEN4=STRTYPE_LEN4_16
    ASCSTR_UNICODE=STRTYPE_C_16
    ASCSTR_UTF16=STRTYPE_C_16
    ASCSTR_UTF32=STRTYPE_C_32
    REF_VHIGH=V695_REF_VHIGH
    REF_VLOW=V695_REF_VLOW
    SWI_END_IN_TBL=SWI_DEF_IN_TBL
    SWI_BC695_EXTENDED=0x8000
    SWI2_INDIRECT=SWI_INDIRECT >> 16
    SWI2_SUBTRACT=SWI_SUBTRACT >> 16
    import ida_netnode
    RIDX_AUTO_PLUGINS=ida_netnode.BADNODE
    change_encoding_name=rename_encoding
    def del_tinfo2(ea, n=None):
        if n is not None:
            return del_op_tinfo(ea, n)
        else:
            return del_tinfo(ea)
    get_encodings_count=get_encoding_qty
    def get_op_tinfo(*args):
        import ida_typeinf
        if isinstance(args[2], ida_typeinf.tinfo_t): # 6.95: ea, n, tinfo_t
            ea, n, tif = args
        else:                                        # 7.00: tinfo_t, ea, n
            tif, ea, n = args
        return _ida_nalt.get_op_tinfo(tif, ea, n)
    get_op_tinfo2=get_op_tinfo
    def is_unicode(strtype):
        return (strtype & STRWIDTH_MASK) > 0
    set_op_tinfo2=set_op_tinfo
    set_tinfo2=set_tinfo
    def make_switch_info_t__init__(real_init):
        def wrapper(self):
            real_init(self)
            self.bc695_api = False
        return wrapper
    switch_info_t.__init__ = make_switch_info_t__init__(switch_info_t.__init__)
    switch_info_t.regdtyp = switch_info_t.regdtype
    def get_tinfo(*args):
        import ida_typeinf
        if isinstance(args[1], ida_typeinf.tinfo_t): # 6.95: ea, tinfo_t
            ea, tif = args
        else:                                        # 7.00: tinfo_t, ea
            tif, ea = args
        return _ida_nalt.get_tinfo(tif, ea)
    get_tinfo2=get_tinfo
    def get_refinfo(*args):
        if isinstance(args[2], refinfo_t): # 6.95: ea, n, refinfo_t
            ea, n, ri = args
        else:                              # 7.00: refinfo_t, ea, n
            ri, ea, n = args
        return _ida_nalt.get_refinfo(ri, ea, n)
    get_switch_info_ex=get_switch_info
    set_switch_info_ex=set_switch_info
    del_switch_info_ex=del_switch_info
    switch_info_ex_t_assign=_ida_nalt.switch_info_t_assign
    switch_info_ex_t_get_custom=_ida_nalt.switch_info_t_custom_get
    switch_info_ex_t_get_defjump=_ida_nalt.switch_info_t_defjump_get
    switch_info_ex_t_get_elbase=_ida_nalt.switch_info_t_elbase_get
    switch_info_ex_t_get_flags=_ida_nalt.switch_info_t_flags_get
    switch_info_ex_t_get_ind_lowcase=_ida_nalt.switch_info_t_ind_lowcase_get
    switch_info_ex_t_get_jcases=_ida_nalt.switch_info_t_jcases_get
    switch_info_ex_t_get_jumps=_ida_nalt.switch_info_t_jumps_get
    switch_info_ex_t_get_ncases=_ida_nalt.switch_info_t_ncases_get
    switch_info_ex_t_get_regdtyp=_ida_nalt.switch_info_t_regdtype_get
    switch_info_ex_t_get_regnum=_ida_nalt.switch_info_t_regnum_get
    switch_info_ex_t_get_startea=_ida_nalt.switch_info_t_startea_get
    switch_info_ex_t_get_values_lowcase=_ida_nalt.switch_info_t__get_values_lowcase
    switch_info_ex_t_set_custom=_ida_nalt.switch_info_t_custom_set
    switch_info_ex_t_set_defjump=_ida_nalt.switch_info_t_defjump_set
    switch_info_ex_t_set_elbase=_ida_nalt.switch_info_t_elbase_set
    switch_info_ex_t_set_flags=_ida_nalt.switch_info_t_flags_set
    switch_info_ex_t_set_ind_lowcase=_ida_nalt.switch_info_t_ind_lowcase_set
    switch_info_ex_t_set_jcases=_ida_nalt.switch_info_t_jcases_set
    switch_info_ex_t_set_jumps=_ida_nalt.switch_info_t_jumps_set
    switch_info_ex_t_set_ncases=_ida_nalt.switch_info_t_ncases_set
    switch_info_ex_t_set_regdtyp=_ida_nalt.switch_info_t_regdtype_set
    switch_info_ex_t_set_regnum=_ida_nalt.switch_info_t_regnum_set
    switch_info_ex_t_set_startea=_ida_nalt.switch_info_t_startea_set
    switch_info_ex_t_set_values_lowcase=_ida_nalt.switch_info_t__set_values_lowcase
    def __switch_info_t_get_flags__(instance):
        return _ida_nalt.switch_info_t_flags_get(instance) | SWI_BC695_EXTENDED
    def __switch_info_t_set_flags__(instance, v):
        if instance.bc695_api:
            v |= (_ida_nalt.switch_info_t_flags_get(instance) & 0xFFFF0000)
        _ida_nalt.switch_info_t_flags_set(instance, v)
    switch_info_t.flags = property(__switch_info_t_get_flags__, __switch_info_t_set_flags__)
    def __switch_info_t_get_flags2__(instance):
        instance.bc695_api = True
        return _ida_nalt.switch_info_t_flags_get(instance) >> 16
    def __switch_info_t_set_flags2__(instance, v):
        instance.bc695_api = True
        flags = _ida_nalt.switch_info_t_flags_get(instance)
        instance.flags = (flags & 0xFFFF) | (v << 16)
    switch_info_t.flags2 = property(__switch_info_t_get_flags2__, __switch_info_t_set_flags2__)
    switch_info_ex_t=switch_info_t

%}