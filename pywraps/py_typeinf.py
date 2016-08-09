#<pycode(py_typeinf)>

def get_type_size0(ti, tp):
    """
    DEPRECATED. Please use calc_type_size instead
    Returns the size of a type
    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param tp: type string
    @return:
        - None on failure
        - The size of the type
    """
    return calc_type_size(ti, tp)

import ida_idaapi
ida_idaapi._listify_types(
    reginfovec_t)

#</pycode(py_typeinf)>
