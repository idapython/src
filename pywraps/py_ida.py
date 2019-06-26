#<pycode(py_ida)>
def __make_idainfo_bound(func, attr):
    def __func(self, *args):
        return func(*args)
    setattr(idainfo, attr, __func)

_NO_SETTER = "<nosetter>"
def __make_idainfo_accessors(
        attr,
        getter_name=None,
        setter_name=None):
    if getter_name is None:
        getter_name = attr
    getter = globals()["idainfo_%s" % getter_name]
    __make_idainfo_bound(getter, getter_name)
    if setter_name != _NO_SETTER:
        if setter_name is None:
            setter_name = "set_%s" % attr
        setter = globals()["idainfo_%s" % setter_name]
        __make_idainfo_bound(setter, setter_name)

def __make_idainfo_getter(name):
    return __make_idainfo_accessors(None, getter_name=name, setter_name=_NO_SETTER)


idainfo_big_arg_align = inf_big_arg_align
__make_idainfo_getter("big_arg_align")

idainfo_gen_null = inf_gen_null
idainfo_set_gen_null = inf_set_gen_null
__make_idainfo_accessors("gen_null")

idainfo_gen_lzero = inf_gen_lzero
idainfo_set_gen_lzero = inf_set_gen_lzero
__make_idainfo_accessors("gen_lzero")

idainfo_gen_tryblks = inf_gen_tryblks
idainfo_set_gen_tryblks = inf_set_gen_tryblks
__make_idainfo_accessors("gen_tryblks")

idainfo_get_demname_form = inf_get_demname_form
__make_idainfo_getter("get_demname_form")

idainfo_get_pack_mode = inf_get_pack_mode
idainfo_set_pack_mode = inf_set_pack_mode
__make_idainfo_accessors(None, "get_pack_mode", "set_pack_mode")

idainfo_is_32bit = inf_is_32bit
__make_idainfo_getter("is_32bit")

idainfo_is_64bit = inf_is_64bit
idainfo_set_64bit = inf_set_64bit
__make_idainfo_accessors(None, "is_64bit", "set_64bit")

idainfo_is_auto_enabled = inf_is_auto_enabled
idainfo_set_auto_enabled = inf_set_auto_enabled
__make_idainfo_accessors(None, "is_auto_enabled", "set_auto_enabled")

idainfo_is_be = inf_is_be
idainfo_set_be = inf_set_be
__make_idainfo_accessors(None, "is_be", "set_be")

idainfo_is_dll = inf_is_dll
__make_idainfo_getter("is_dll")

idainfo_is_flat_off32 = inf_is_flat_off32
__make_idainfo_getter("is_flat_off32")

idainfo_is_graph_view = inf_is_graph_view
idainfo_set_graph_view = inf_set_graph_view
__make_idainfo_accessors(None, "is_graph_view", "set_graph_view")

idainfo_is_hard_float = inf_is_hard_float
__make_idainfo_getter("is_hard_float")

idainfo_is_kernel_mode = inf_is_kernel_mode
__make_idainfo_getter("is_kernel_mode")

idainfo_is_mem_aligned4 = inf_is_mem_aligned4
__make_idainfo_getter("is_mem_aligned4")

idainfo_is_snapshot = inf_is_snapshot
__make_idainfo_getter("is_snapshot")

idainfo_is_wide_high_byte_first = inf_is_wide_high_byte_first
idainfo_set_wide_high_byte_first = inf_set_wide_high_byte_first
__make_idainfo_accessors(None, "is_wide_high_byte_first", "set_wide_high_byte_first")

idainfo_like_binary = inf_like_binary
__make_idainfo_getter("like_binary")

idainfo_line_pref_with_seg = inf_line_pref_with_seg
idainfo_set_line_pref_with_seg = inf_set_line_pref_with_seg
__make_idainfo_accessors("line_pref_with_seg")

idainfo_show_auto = inf_show_auto
idainfo_set_show_auto = inf_set_show_auto
__make_idainfo_accessors("show_auto")

idainfo_show_line_pref = inf_show_line_pref
idainfo_set_show_line_pref = inf_set_show_line_pref
__make_idainfo_accessors("show_line_pref")

idainfo_show_void = inf_show_void
idainfo_set_show_void = inf_set_show_void
__make_idainfo_accessors("show_void")

idainfo_loading_idc = inf_loading_idc
__make_idainfo_getter("loading_idc")

idainfo_map_stkargs = inf_map_stkargs
__make_idainfo_getter("map_stkargs")

idainfo_pack_stkargs = inf_pack_stkargs
__make_idainfo_getter("pack_stkargs")

idainfo_readonly_idb = inf_readonly_idb
__make_idainfo_getter("readonly_idb")

idainfo_set_store_user_info = lambda *args: not inf_set_store_user_info()

idainfo_stack_ldbl = inf_stack_ldbl
__make_idainfo_getter("stack_ldbl")

idainfo_stack_varargs = inf_stack_varargs
__make_idainfo_getter("stack_varargs")

idainfo_use_allasm = inf_use_allasm
__make_idainfo_getter("use_allasm")

idainfo_use_gcc_layout = inf_use_gcc_layout
__make_idainfo_getter("use_gcc_layout")

macros_enabled = inf_macros_enabled
should_create_stkvars = inf_should_create_stkvars
should_trace_sp = inf_should_trace_sp
show_all_comments = inf_show_all_comments
show_comments = lambda *args: not inf_hide_comments()
show_repeatables = inf_show_repeatables

__make_idainfo_accessors(None, "is_graph_view", "set_graph_view")

SW_RPTCMT = SCF_RPTCMT
SW_ALLCMT = SCF_ALLCMT
SW_NOCMT = SCF_NOCMT
SW_LINNUM = SCF_LINNUM
SW_TESTMODE = SCF_TESTMODE
SW_SHHID_ITEM = SCF_SHHID_ITEM
SW_SHHID_FUNC = SCF_SHHID_FUNC
SW_SHHID_SEGM = SCF_SHHID_SEGM
#</pycode(py_ida)>


#<pycode_BC695(py_ida)>
AF2_ANORET=AF_ANORET
AF2_CHKUNI=AF_CHKUNI
AF2_DATOFF=AF_DATOFF
AF2_DOCODE=AF_DOCODE
AF2_DODATA=AF_DODATA
AF2_FTAIL=AF_FTAIL
AF2_HFLIRT=AF_HFLIRT
AF2_JUMPTBL=AF_JUMPTBL
AF2_MEMFUNC=AF_MEMFUNC
AF2_PURDAT=AF_PURDAT
AF2_REGARG=AF_REGARG
AF2_SIGCMT=AF_SIGCMT
AF2_SIGMLT=AF_SIGMLT
AF2_STKARG=AF_STKARG
AF2_TRFUNC=AF_TRFUNC
AF2_VERSP=AF_VERSP
AF_ASCII=AF_STRLIT
ASCF_AUTO=STRF_AUTO
ASCF_COMMENT=STRF_COMMENT
ASCF_GEN=STRF_GEN
ASCF_SAVECASE=STRF_SAVECASE
ASCF_SERIAL=STRF_SERIAL
ASCF_UNICODE=STRF_UNICODE
INFFL_LZERO=OFLG_LZERO
ansi2idb=ida_idaapi._BC695.identity
idb2scr=ida_idaapi._BC695.identity
scr2idb=ida_idaapi._BC695.identity
showAllComments=show_all_comments
showComments=show_comments
showRepeatables=show_repeatables
toEA=to_ea

def __wrap_hooks_callback(klass, new_name, old_name, do_call):
    bkp_name = "__real_%s" % new_name
    def __wrapper(self, *args):
        rc = getattr(self, bkp_name)(*args)
        cb = getattr(self, old_name, None)
        if cb:
            rc = do_call(cb, *args)
        return rc

    setattr(klass, bkp_name, getattr(klass, new_name))
    setattr(__wrapper, "bc695_trampoline", True)
    setattr(klass, new_name, __wrapper)

idainfo.ASCIIbreak = idainfo.strlit_break
idainfo.ASCIIpref = idainfo.strlit_pref
idainfo.ASCIIsernum = idainfo.strlit_sernum
idainfo.ASCIIzeroes = idainfo.strlit_zeroes
idainfo.asciiflags = idainfo.strlit_flags
idainfo.beginEA = idainfo.start_ea
idainfo.binSize = idainfo.bin_prefix_size
def my_get_proc_name(self):
    return [self.procname, self.procname]
idainfo.get_proc_name = my_get_proc_name
idainfo.graph_view = property(idainfo.is_graph_view, idainfo.set_graph_view)
idainfo.mf = property(idainfo.is_be, idainfo.set_be)
idainfo.namelen = idainfo.max_autoname_len
idainfo.omaxEA = idainfo.omax_ea
idainfo.ominEA = idainfo.omin_ea
def make_outflags_accessors(bit):
    def getter(self):
        return (self.outflags & bit) != 0
    def setter(self, value):
        if value:
            self.outflags |= bit
        else:
            self.outflags &= ~bit
    return getter, setter
idainfo.s_assume = property(*make_outflags_accessors(OFLG_GEN_ASSUME))
idainfo.s_auto = property(idainfo.is_auto_enabled, idainfo.set_auto_enabled)
idainfo.s_null = property(*make_outflags_accessors(OFLG_GEN_NULL))
idainfo.s_org = property(*make_outflags_accessors(OFLG_GEN_ORG))
idainfo.s_prefseg = property(*make_outflags_accessors(OFLG_PREF_SEG))
idainfo.s_showauto = property(*make_outflags_accessors(OFLG_SHOW_AUTO))
idainfo.s_showpref = property(*make_outflags_accessors(OFLG_SHOW_PREF))
idainfo.s_void = property(*make_outflags_accessors(OFLG_SHOW_VOID))
idainfo.startIP = idainfo.start_ip
idainfo.startSP = idainfo.start_sp
def make_lflags_accessors(bit):
    def getter(self):
        return (self.lflags & bit) != 0
    def setter(self, value):
        if value:
            self.lflags |= bit
        else:
            self.lflags &= ~bit
    return getter, setter
idainfo.wide_high_byte_first = property(*make_lflags_accessors(LFLG_WIDE_HBF))
def make_obsolete_accessors():
    def getter(self):
        return False
    def setter(self, value):
        pass
    return getter, setter
idainfo.allow_nonmatched_ops = property(*make_obsolete_accessors())
idainfo.check_manual_ops = property(*make_obsolete_accessors())
#</pycode_BC695(py_ida)>
