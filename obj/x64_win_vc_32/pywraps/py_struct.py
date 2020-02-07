#<pycode_BC695(py_struct)>
get_member_name2=get_member_name

def get_member_tinfo(*args):
    import ida_typeinf
    if isinstance(args[1], ida_typeinf.tinfo_t):  # 6.95: mptr, tinfo_t
        mptr, tif = args
    else:                                         # 7.00: tinfo_t, mptr
        tif, mptr = args
    return _ida_struct.get_member_tinfo(tif, mptr);

def get_or_guess_member_tinfo(*args):
    import ida_typeinf
    if isinstance(args[1], ida_typeinf.tinfo_t):  # 6.95: mptr, tinfo_t
        mptr, tif = args
    else:                                         # 7.00: tinfo_t, mptr
        tif, mptr = args
    return _ida_struct.get_or_guess_member_tinfo(tif, mptr);

# note: if needed we might have to re-implement get_member_tinfo()
# and look whether there is a 2nd, 'tinfo_t' parameter (since the
# original get_member_tinfo function has a different signature)
get_member_tinfo2=get_member_tinfo
# same here
get_or_guess_member_tinfo2=get_or_guess_member_tinfo
save_struc2=save_struc
set_member_tinfo2=set_member_tinfo
#</pycode_BC695(py_struct)>
