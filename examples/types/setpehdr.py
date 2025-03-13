"""
summary: assign DOS/PE headers structures to a PE binary

description:
  The goal of this script is to demonstrate some usage of the type API.

  In this script, we:

  * load a PE64 file in binary mode
  * import some types from the mssdk64 til
  * apply these types at the correct ofsset in the DB
  * finally, rebase the program based on the information stored
    in the ImageBase field of the IMAGE_OPTIONAL_HEADER64.

level: intermediate
"""

import ida_typeinf
import ida_bytes
import ida_name
import ida_segment
import ida_netnode
import ida_hexrays
import idc


def create_struct_at(id, ea, var_name = None):
    """
    Create the structure identified by id at
    address ea.
    """
    tif = ida_typeinf.tinfo_t()
    ida_hexrays.get_type(id, tif, ida_typeinf.BTF_STRUCT)
    ida_bytes.create_struct(ea, tif.get_size(), id, True)
    if var_name:
        ida_name.set_name(ea, var_name)


def get_struct_size(id):
    """
    Return the size of the structure identified by id.
    """
    tif = ida_typeinf.tinfo_t()
    ida_hexrays.get_type(id, tif, ida_typeinf.BTF_STRUCT)
    return tif.get_size()


def get_pe_ea(id):
    """
    Return the address of the pe header.
    """
    tif = ida_typeinf.tinfo_t()
    ida_hexrays.get_type(id, tif, ida_typeinf.BTF_STRUCT)
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    udm = udt[tif.get_udt_nmembers() - 1]
    return ida_bytes.get_dword(udm.offset // 8)



def get_field_off(id, field):
    """
    Return the offset in bytes of the member
    'field' in the structure identified by 'id'.
    """
    tif = ida_typeinf.tinfo_t()
    ida_hexrays.get_type(id, tif, ida_typeinf.BTF_STRUCT)
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    udm = udt[udt.find_member(field)]
    return udm.offset // 8


def get_struct_field_off(struct_name, field):
    """
    Return the offset in bytes of the member
    'field' in the structure identified by 'struct_name'.
    """
    tif = ida_typeinf.tinfo_t()
    tif.get_named_type(None, struct_name, ida_typeinf.BTF_STRUCT, True, False)
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    udm = udt[udt.find_member(field)]
    return udm.offset // 8


def main():

    # Add mssdk64_win10 til to the local types.
    ida_typeinf.add_til("mssdk64_win10", ida_typeinf.ADDTIL_DEFAULT)

    # Get _IMAGE_XXX struct ids. -1 Means that the type is appended
    # to the local type list.
    idh_id = idc.import_type(-1, "_IMAGE_DOS_HEADER")
    inh_id = idc.import_type(-1, "_IMAGE_NT_HEADERS64")
    ish_id = idc.import_type(-1, "_IMAGE_SECTION_HEADER")
    if idh_id == ida_netnode.BADNODE or inh_id == ida_netnode.BADNODE \
    or ish_id == ida_netnode.BADNODE:
        print("At least one type has not been imported. Quit.")
        return

    # Create _IMAGE_DOS_HEADER at offset 0.
    create_struct_at(idh_id, 0, "DOS_HEADER")

    # Get the e_lfanew value.
    inh_ea = get_pe_ea(idh_id)

    # Create _IMAGE_NT_HEADERS at offset inh_ea.
    create_struct_at(inh_id, inh_ea, "NT_HEADERS")

    # Get the number of sections.
    ifh_off = get_field_off(inh_id, "FileHeader")
    nos_off = get_struct_field_off("_IMAGE_FILE_HEADER", "NumberOfSections")
    sections = ida_bytes.get_word(inh_ea + ifh_off + nos_off)

    # Create _IMAGE_SECTION_HEADERs.
    section_ea = inh_ea + get_struct_size(inh_id)
    ish_size = get_struct_size(ish_id)
    section_eas = []
    for section in range(sections):
        section_eas.append(section_ea)
        create_struct_at(ish_id, section_ea)
        section_ea += ish_size


    ioh_off = get_field_off(inh_id, "OptionalHeader")
    ioh_ea = inh_ea + ioh_off

    # Get Section alignment.
    sec_align_off = get_struct_field_off("_IMAGE_OPTIONAL_HEADER64", "SectionAlignment")

    # Get the image base ea.
    image_base_member_off = get_struct_field_off("_IMAGE_OPTIONAL_HEADER64", "ImageBase")
    image_base = ida_bytes.get_qword(ioh_ea + image_base_member_off)
    ida_segment.rebase_program(image_base, ida_segment.MSF_FIXONCE)

main()
