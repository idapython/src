"""
summary: list cross-references to function stack frame variables

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we demonstrate how to list each stack variables
    xref:
    * Get the function object surrounding cursor location.
    * Use this function to retrieve the corresponding frame object.
    * For each frame element:
        - Build the stack variable xref list
        - Print it.

level: intermediate
"""

import ida_typeinf
import ida_frame
import ida_funcs
import ida_xref
import ida_kernwin

XREF_TO_STR = {ida_xref.dr_R: "READ",
               ida_xref.dr_W: "WRITE"
}

def list_xrefs(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        print('No function under the cursor')
        return

    print(f'Function @ {func.start_ea:x}')

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        print('No frame found')
        return

    nmembers = frame_tif.get_udt_nmembers()
    print(f'Frame has {nmembers} members')

    if nmembers <= 0:
        print('No members found.')
        return

    frame_udt = ida_typeinf.udt_type_data_t()
    if not frame_tif.get_udt_details(frame_udt):
        print('Unable to get the frame details.')
        return

    for frame_udm in frame_udt:
        start_off = frame_udm.begin() // 8
        end_off = frame_udm.end() // 8
        xreflist = ida_frame.xreflist_t()
        ida_frame.build_stkvar_xrefs(
            xreflist, func, start_off, end_off)
        size = xreflist.size()
        print(f'{frame_udm.name} stack variable starts @ '
                f'{start_off:x}, ends @ {end_off:x}, '
                f'xref size: {size}')

        for idx in range(size):
            type_ = XREF_TO_STR.get(xreflist[idx].type, "UNK")
            print(f'\t[{idx}]: xref @ {xreflist[idx].ea:x} '
                    f'of type {type_}')

list_xrefs(ida_kernwin.get_screen_ea())
