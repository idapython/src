"""
summary: apply function prototype to call sites

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
    * Open the private type libary.
    * Load its declaration in the type library by parsing its declaration and
    keep the return tuple for future use.
    * Deserialize the type info stored in the returned tuple.
    * Get the address of the function.
    * Get the address of the code reference to the function and apply
    the type info there.

level: intermediate
"""
import ida_typeinf
import ida_name
import idautils
import ida_idaapi

def apply_type_info(callee_name, callee_prototype_decl):
    til = ida_typeinf.get_idati()
    parse_result = ida_typeinf.idc_parse_decl(til, callee_prototype_decl, ida_typeinf.PT_REPLACE)
    if parse_result is None:
        print("Failed to parse declaration.")
        return

    name, types, fields, *rest = parse_result
    tif = ida_typeinf.tinfo_t()
    if not tif.deserialize(til, types, fields):
        print("Failed to deserialize type info.")
        return

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, callee_name)
    if ea == ida_idaapi.BADADDR:
        print(f"{callee_name} function not found.")
        return

    print(f"{callee_name} function found @ {ea:x}.")
    for xref in idautils.CodeRefsTo(ea, 0):
        if ida_typeinf.apply_callee_tinfo(xref, tif):
            print(f"\tApplied type info @ {xref:x}.")
        else:
            print(f"Could not apply type info @ {xref:x}")

apply_type_info(
    "KdInitSystem",
    "NTSTATUS __fastcall KdInitSystem(ULONG BootPhase, _LOADER_PARAMETER_BLOCK *LoaderBlock);")
