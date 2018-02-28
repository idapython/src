#<pycode(py_typeinf)>

import ida_idaapi
ida_idaapi._listify_types(
    reginfovec_t)

#</pycode(py_typeinf)>

#<pycode_BC695(py_typeinf)>
BFI_NOCONST=0
BFI_NOLOCS=0
NTF_NOIDB=0
PRVLOC_STKOFF=PRALOC_VERIFY
PRVLOC_VERIFY=PRALOC_STKOFF
TERR_TOOLONGNAME=TERR_WRONGNAME
@bc695redef
def add_til(name, flags=0):
    return _ida_typeinf.add_til(name, flags)
add_til2=add_til
@bc695redef
def apply_decl(arg0, arg1, arg2=None, arg3=0):
    if type(arg0) in [int, long]: # old apply_cdecl()
        return _ida_typeinf.apply_cdecl(cvar.idati, arg0, arg1, 0)
    else:
        assert(arg2 is not None)
        return _ida_typeinf.apply_cdecl(arg0, arg1, arg2, arg3)
apply_cdecl2=apply_decl
apply_tinfo2=apply_tinfo
calc_c_cpp_name4=calc_c_cpp_name
import ida_idaapi
callregs_init_regs=ida_idaapi._BC695.dummy
choose_local_type=choose_local_tinfo
@bc695redef
def choose_named_type2(root_til, title, ntf_flags, func, out_sym):
    class func_pred_t(predicate_t):
        def __init__(self, func):
            predicate_t.__init__(self)
            self.func = func
        def should_display(self, til, name, tp, flds):
            return self.func(name, tp, flds)
    fp = func_pred_t(func)
    return choose_named_type(out_sym, root_til, title, ntf_flags, fp)
deref_ptr2=deref_ptr
extract_varloc=extract_argloc
const_vloc_visitor_t=const_aloc_visitor_t
for_all_const_varlocs=for_all_const_arglocs
for_all_varlocs=for_all_arglocs
@bc695redef
def gen_decorate_name3(name, mangle, cc):
    return gen_decorate_name(name, mangle, cc, None) # ATM gen_decorate_name doesn't use its tinfo_t
get_enum_member_expr2=get_enum_member_expr
get_idainfo_by_type3=get_idainfo_by_type
@bc695redef
def guess_func_tinfo2(pfn, tif):
    return guess_tinfo(pfn.start_ea, tif)
@bc695redef_with_pydoc(load_til.__doc__)
def load_til(name, tildir=None, *args):
    # 6.95 C++ prototypes
    # idaman til_t *ida_export load_til(const char *tildir, const char *name, char *errbuf, size_t bufsize);
    # idaman til_t *ida_export load_til2(                   const char *name, char *errbuf, size_t bufsize);
    #
    # 6.95 Python prototypes
    # load_til(tildir, name)
    # load_til(tildir, name, errbuf, bufsize)
    # load_til2(name, errbuf, bufsize=0)
    #
    # -> it's virtually impossible to tell whether it's load_til2(),
    # or load_til() that's called since they both take 2 first string
    # arguments. We'll rely the contents of those strings...
    if name is None or name == "": # load_til(), with an empty tildir
        name = tildir
        tildir = ""
        return _ida_typeinf.load_til(name, tildir)
    else:
        return _ida_typeinf.load_til(name, tildir)
load_til2=load_til
lower_type2=lower_type
optimize_varloc=optimize_argloc
@bc695redef
def parse_decl2(til, decl, tif, flags):
    return _ida_typeinf.parse_decl(tif, til, decl, flags)
@bc695redef
def print_type(ea, flags):
    if isinstance(flags, bool):
        flags = PRTYPE_1LINE if flags else 0
    return _ida_typeinf.print_type(ea, flags)
@bc695redef
def print_type2(ea, flags):
    return _ida_typeinf.print_type(ea, flags)
print_type3=_ida_typeinf.print_type
print_varloc=print_argloc
@bc695redef
def resolve_typedef2(til, p, *args):
    return _ida_typeinf.resolve_typedef(til, p)
scattered_vloc_t=scattered_aloc_t
set_compiler2=set_compiler
varloc_t=argloc_t
varpart_t=argpart_t
verify_varloc=verify_argloc
vloc_visitor_t=aloc_visitor_t
def guess_tinfo(*args):
    if isinstance(args[1], tinfo_t): # 6.95: id, tinfo_t
        tid, tif = args
    else:                            # 7.00: tinfo_t, id
        tif, tid = args
    return _ida_typeinf.guess_tinfo(tif, tid)
guess_tinfo2=guess_tinfo
def find_tinfo_udt_member(*args):
    if isinstance(args[2], udt_member_t): # 6.95: typid, strmem_flags, udm
          typid, strmem_flags, udm = args
    else:                                 # 7.00: udm, typid, strmem_flags
          udm, typid, strmem_flags = args
    return _ida_typeinf.find_tinfo_udt_member(udm, typid, strmem_flags)
def __tinfo_t_find_udt_member(self, *args):
    if isinstance(args[1], udt_member_t): # 6.95: strmem_flags, udm
          strmem_flags, udm = args
    else:                                 # 7.00: udm, strmem_flags
          udm, strmem_flags = args
    return _ida_typeinf.tinfo_t_find_udt_member(self, udm, strmem_flags)
tinfo_t.find_udt_member=__tinfo_t_find_udt_member
def save_tinfo(*args):
    if isinstance(args[4], tinfo_t): # 6.95: til_t, size_t, name, int, tinfo_t
        til, _ord, name, ntf_flags, tif = args
    else:                            # 7.00: tinfo_t, til_t, size_t, name, int
        tif, til, _ord, name, ntf_flags = args
    return _ida_typeinf.save_tinfo(tif, til, _ord, name, ntf_flags)
#</pycode_BC695(py_typeinf)>
