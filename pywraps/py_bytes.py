
#<pycode(py_bytes)>
def doExtra(ea):
    setFlags(ea, get_flags_novalue(ea) | FF_LINE)

def noExtra(ea):
    setFlags(ea, get_flags_novalue(ea) & ~(FF_LINE))
#</pycode(py_bytes)>
