"""
summary: create a union

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we create a union by building it member after member.

level: intermediate
"""
import ida_typeinf

field_list = [("member1", ida_typeinf.BTF_INT32),
              ("member2", ida_typeinf.BTF_CHAR),
              ("member3", ida_typeinf.BTF_FLOAT)]

# Delete the structure in case it already exist.
ida_typeinf.del_named_type(None, "my_union", ida_typeinf.NTF_TYPE)

# Create a union member by member.
udt = ida_typeinf.udt_type_data_t()
udt.is_union = True
for (name, _type) in field_list:
    udm = ida_typeinf.udm_t(name, _type)
    udt.push_back(udm)

# Add a pointer to a Elf32_Sym and actually create the type.
tif = ida_typeinf.tinfo_t()
if tif.get_named_type("Elf32_Sym") and tif.create_ptr(tif):
    udm = ida_typeinf.udm_t("header_ptr", tif)
    udt.push_back(udm)
    if tif.create_udt(udt, ida_typeinf.BTF_UNION):
        tif.set_named_type(None, "my_union")
        print(tif._print(tif.get_type_name(), ida_typeinf.PRTYPE_TYPE
                         | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_MULTI))
        print("Done")
    else:
        print("Cannot create udt")
else:
    print("Error while getting pointer to Elf32_Sym")
