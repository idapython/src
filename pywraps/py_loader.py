
#<pycode_BC695(py_loader)>
NEF_TIGHT=0
@bc695redef
def save_database(outfile, flags=0):
    if isinstance(flags, bool):
        flags = DBFL_KILL if flags else 0
    return _ida_loader.save_database(outfile, flags)
save_database_ex=save_database
#</pycode_BC695(py_loader)>
