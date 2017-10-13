
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
    setattr(klass, new_name, __wrapper)

#</pycode_BC695(py_ida)>
