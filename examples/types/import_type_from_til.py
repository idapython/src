"""
summary: load a type library from a file, and then a type from it

description:
   The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
    * ask the user for a specific til to be lodaed
    * if successfully loaded ask the user for a type name to be imported.
    * append the type to the local types.

level: intermediate
"""
import ida_netnode
import ida_typeinf
import ida_kernwin

def main():
    til_name = ida_kernwin.ask_str("Dummy til name", 0, "Enter a til filename:")
    if not til_name:
        print("No til name provided.")
        return

    src_til = ida_typeinf.load_til(til_name)
    if not src_til:
        print(f"{til_name} not added.")
        return

    type_name = ida_kernwin.ask_str("Dummy type name", 0, "Enter a type name")
    if not type_name:
        print(f"Please provide a type name.")
        return

    src_tif = src_til.get_named_type(type_name)
    if not src_tif:
        print(f"{til_name} has no type named {type_name}")
        return

    imported_tif = ida_typeinf.get_idati().import_type(src_tif)
    if not imported_tif:
        print(f"Could not import {type_name}")
        return

    print(f"{type_name} type has been imported, with ordinal {imported_tif.get_ordinal()}")

main()
