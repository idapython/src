%module(docstring="IDA Plugin SDK API wrapper: ida",directors="1",threads="1") ida_ida
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_IDA
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_IDA
  #define HAS_DEP_ON_INTERFACE_IDA
#endif
%include "header.i"
// Ignore kernel-only symbols
%ignore idainfo::align_short_demnames;
%ignore idainfo::align_strtype;
%ignore idainfo::align_long_demnames;
%ignore idainfo::store_user_info;
%ignore idainfo::zero;
%ignore idainfo::padding;
%ignore idainfo::netdelta;
%ignore idainfo::privrange;
%ignore idainfo::padding2;
%ignore idainfo::idainfo;
%ignore idainfo::~idainfo;

%ignore hook_cb_t;
%ignore hook_type_t;
%ignore hook_to_notification_point;
%ignore unhook_from_notification_point;
%ignore invoke_callbacks;
%ignore post_event_visitor_t;
%ignore register_post_event_visitor;
%ignore unregister_post_event_visitor;

%extend idainfo
{
  qstring get_abiname()
  {
    qstring buf;
    get_abi_name(&buf);
    return buf;
  }

#ifdef BC695
  // Compat 6.95; since inf is a cvar, I can't just add properties to it..
  ea_t get_minEA() const { return $self->min_ea; }
  void set_minEA(ea_t ea) { $self->min_ea = ea; }
  ea_t get_maxEA() const { return $self->max_ea; }
  void set_maxEA(ea_t ea) { $self->max_ea = ea; }
  qstring get_procName() const { return $self->procname; }
#endif

  %pythoncode {
    abiname = property(get_abiname)
#ifdef BC695
    minEA = property(get_minEA, set_minEA)
    maxEA = property(get_maxEA, set_maxEA)
    procName = property(get_procName)
#endif
  }
}

%ignore setflag(uchar &where,uchar bit,int value);
%ignore setflag(ushort &where,ushort bit,int value);
%ignore setflag(uint32 &where,uint32 bit,int value);

// Make idainfo::get_proc_name() work
%include "cstring.i"
%cstring_bounded_output(char *buf, 8);

%ignore BADADDR;
%ignore BADSEL;

%include "ida.hpp"

%clear(char *buf);
%pythoncode %{
if _BC695:
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

%}