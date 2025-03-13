"""
summary: list database functions prototypes

description:
    This script demonstrates how to list a function return type
    along with its parameters types and name if any.
    We do this for all the functions found in the database.

level: beginner
"""
import ida_funcs
import ida_typeinf
import ida_kernwin
import ida_nalt
import idautils

for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)
    prototype = func.prototype
    if not prototype:
        print(f"{ea:x}: {func.name} has no prototype.")
        continue

    print(f"{ea:x}: {func.name} returns a: '{prototype.get_rettype()}', and accepts the following arguments:")
    for arg in prototype.iter_func():
        print(f"\t{arg.name} (of type '{arg.type})'")
