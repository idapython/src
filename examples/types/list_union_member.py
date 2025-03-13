"""
summary: list union members

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
    * Ask the user for a union name. It must already be present in the
    local types.
    * Retrieve the union type info from the local type
    * Extract its type details (udt)
    * Iterates it members and prints their names.

level: beginner
"""
import ida_kernwin
import ida_typeinf

name = ida_kernwin.ask_str("Dummy union", 0, "Enter a union name:")
if name is not None:
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name, ida_typeinf.BTF_UNION, True, False):
        print(f"'{name}' is not a union")
    elif  tif.is_typedef():
        print(f"'{name}' is not a (non typedefed) union.")
    else:
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            print(f"Listing the {name} union {udt.size()} field names:")
            for idx, udm in enumerate(udt):
                print(f"Field {idx}: {udm.name}")
                idx += 1
        else:
            print(f"Unable to get udt details for union '{name}'")
