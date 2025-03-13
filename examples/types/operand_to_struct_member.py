"""
summary: turn instruction operand into a structure offset

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
     * ask the user to choose the structure that will be used for
     the conversion.
     * build the structure path and call ida_bytes.op_stroff. In case
     an enum is found a modal chooser is displayed in order to select
     a member.

level: advanced
"""
import ida_typeinf
import ida_kernwin
import ida_pro
import ida_ua
import ida_bytes

class union_member_chooser_t(ida_kernwin.Choose):
    def __init__(self, title, udm_list):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Type Name", 30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Type ID", 30 | ida_kernwin.Choose.CHCOL_HEX]
            ]
        )
        self.items = [ [udm.type.get_type_name(), hex(udm.type.get_tid())]
                      for udm in udm_list]
        self.icon = 5

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]


def choose_union_member(tif):
    """
    Display a chooser containing the list of the union
    members. The selected entry (0-based) is returned
    or -1.
    """
    udm_list = []
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return None
    for udm in udt:
        udm_list.append(udm)
    uch = union_member_chooser_t("Choose a union member", udm_list)
    return uch.Show(modal=True)


def build_strpath(tif, offset):
    """
    Build the structure path and return it.
    """
    tid_list = []
    offset *= 8
    while True:
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                break
            if tif.is_union():
                n = choose_union_member(tif)
                if n == -1:
                    break
                tid_list.append(tif.get_udm_tid(n))
                tif = ida_typeinf.tinfo_t(udt[n].type)
            elif tif.is_struct():
                tid_list.append(tif.get_tid())
                udm = ida_typeinf.udm_t()
                udm.offset = offset
                idx = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
                if idx != -1:
                    offset -= udm.offset
                    tif = ida_typeinf.tinfo_t(udm.type)
        else:
            break
    size = len(tid_list)
    path = ida_pro.tid_array(size)
    for idx, tid in enumerate(tid_list):
        path[idx] = tid
    return (path, size)


def main(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea):
        tif = ida_typeinf.tinfo_t()
        if ida_kernwin.choose_struct(tif, "Choose the structure:"):
            n = ida_kernwin.get_opnum()
            if n == -1:
                print("No operand selected")
            else:
                path, size = build_strpath(tif, insn.ops[n].addr)
                ida_bytes.op_stroff(insn, n, path.cast(), size, 0)
    else:
        print(f"Unable to decode ins @ {ea:x}")


if __name__ == "__main__":
    main(ida_kernwin.get_screen_ea())
