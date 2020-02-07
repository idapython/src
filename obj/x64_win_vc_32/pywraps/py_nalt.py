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

#<pycode_BC695(py_nalt)>
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
#</pycode_BC695(py_nalt)>
