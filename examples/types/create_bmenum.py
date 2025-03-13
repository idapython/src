"""
summary: create a bitmask enumeration

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we create a bitmask enumeration member by member.

level: intermediate
"""
import ida_typeinf

tif = ida_typeinf.tinfo_t()
tif.create_enum(ida_typeinf.BTE_HEX | ida_typeinf.BTE_BITMASK)
for name, value in [("field1", 1), ("field2", 2), ("field3", 0xC)]:
    tif.add_edm(name, value)

print(f"{tif._print()}")

"""
Now let's add a couple enumerators to a separate group
"""

tif.add_edm("field1_1", 0x1100, 0xFF00)
tif.add_edm("field1_2", 0x1200, 0xFF00)
print(f"{tif._print()}")
