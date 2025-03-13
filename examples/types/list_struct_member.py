"""
summary: list structure members

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
    * Ask the user for a structure name. It must already be present in the
    local types.
    * Retrieve the structure type info from the local type
    * Extract its type details (udt)
    * Iterates it members and prints their names.

level: beginner
"""

import ida_kernwin
import ida_typeinf

def main():
    name = ida_kernwin.ask_str("Dummy struct", 0, "Enter a structure name:")
    if name is None:
        print("No structure name provided")
        return

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name, ida_typeinf.BTF_STRUCT, True, False):
        print(f"'{name}' is not a structure")
        return

    if tif.is_typedef():
        print(f"'{name}' is not a (non typedefed) structure.")
        return

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        print(f"Unable to get udt details for structure '{name}'")
        return

    print(f"Listing the {name} structure {udt.size()} field names:")
    for idx, udm in enumerate(udt):
        print(f"Field {idx}: {udm.name}")
        idx += 1

main()
