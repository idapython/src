"""
summary: recursively visit a type and its members

description:
    In this script, we show an example of tinfo_visitor_t to list
    a user define type members, recursively.

    This scripts skips array & pointer members (by calling
    `tinfo_visitor_t.prune_now()`)

level: intermediate
"""
import ida_typeinf
import ida_netnode
import idc

class tinfo_visitor(ida_typeinf.tinfo_visitor_t):

    def __init__(self):
        ida_typeinf.tinfo_visitor_t.__init__(self, ida_typeinf.TVST_DEF)

    def visit_type(self, out, tif, name, cmt):
        type_name = tif.get_type_name()
        if tif.is_udt():
            print(f"visited udt: {type_name} {name}")
        elif tif.is_array():
            ai = ida_typeinf.array_type_data_t()
            if tif.get_array_details(ai):
                type_name = ai.elem_type._print()
                nelems = ai.nelems
                print(f"visited array: {type_name} {name}[{nelems}]")
                self.prune_now()
        elif tif.is_scalar():
            print(f"visited scalar: {type_name} {name}")
        elif tif.is_ptr():
            print(f"visited pointer: {type_name} {name}")
            self.prune_now()
        else:
            print(f"visited unknown: {type_name} {name}")

        return 0

ida_typeinf.add_til("mssdk64_win10", ida_typeinf.ADDTIL_DEFAULT)
til = ida_typeinf.get_idati()

idh_id = idc.import_type(-1, "_IMAGE_DOS_HEADER")
if idh_id != ida_netnode.BADNODE:
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, "_IMAGE_DOS_HEADER"):
        tinfo_visitor().apply_to(tif)
    else:
        print("Unable to get _IMAGE_DOS_HEADER type info.")
else:
    print("Import of _IMAGE_DOS_HEADER failed.")
