"""
summary: print enumeration members

description:
  In this example, we will first ask the user to provide the name
  of an enumeration, and then iterate on it

level: beginner
"""
import ida_kernwin
import ida_typeinf

def iter_enum(name):
    tif = ida_typeinf.get_idati().get_named_type(name)
    if not tif:
        print(f"No type named {name} in local types")
        return

    if not tif.is_enum():
        print(f"Type named {name} is not an enum")
        return

    bf = "(bitfield) " if tif.is_bitmask_enum() else ""
    print(f"Listing {bf}enum '{name}':")

    for idx, edm in enumerate(tif.iter_enum()):
        print(f"\tField {idx}: {edm.name} = 0x{edm.value:x}")

def main():
    name = ida_kernwin.ask_str("Dummy enum", 0, "Enter an enum name:")
    if name is None:
        print("Please provide an enumeration type name")
        return
    return iter_enum(name)

main()
