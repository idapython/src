"""
summary: change the type & name of a function stack frame variable

description:
    The goal of this script is to demonstrate some usage of the type API.

    In this script, we show a way to change the type and the name
    of a stack variable. In this case we will take advantage of the
    fact that RtlImageNtHeader calls RtlImageNtHeaderEx which takes
    a pointer to PIMAGE_NT_HEADERS as its fourth parameter and, for
    this, uses a stack variable of its caller.

    * Get the function object for RtlImageNtHeader.
    * Iterate through the function item to localize the load of the
      stack variable address before the call to RtlImageNtHeaderEx. We
       keep this information.
    * Localize the call and take advantage of the previoulsy stored
      instruction to get the stack variable index in the frame.
    * Set the type and rename the stack variable.

level: advanced
"""
import ida_name
import ida_funcs
import ida_allins
import ida_typeinf
import ida_ua
import ida_frame
import ida_idaapi
import ida_ida

"""
Before running the script:

                    STACK VIEW
+0000000000000000     _UNKNOWN *__return_address;
+0000000000000008     // padding byte
+0000000000000009     // padding byte
+000000000000000A     // padding byte
+000000000000000B     // padding byte
+000000000000000C     // padding byte
+000000000000000D     // padding byte
+000000000000000E     // padding byte
+000000000000000F     // padding byte
+0000000000000010     _QWORD arg_8;

                    DISASSEMBLY
.text:000000018002E770                                         public RtlImageNtHeader
.text:000000018002E770                         RtlImageNtHeader proc near              ; CODE XREF: sub_180007FF4+1B1↑p
.text:000000018002E770                                                                 ; sub_18002E394+66↑p ...
.text:000000018002E770
.text:000000018002E770                         arg_8           = qword ptr  10h
.text:000000018002E770
.text:000000018002E770 48 83 EC 28                             sub     rsp, 28h
.text:000000018002E774 48 83 64 24 38 00                       and     [rsp+28h+arg_8], 0
.text:000000018002E77A 4C 8D 4C 24 38                          lea     r9, [rsp+28h+arg_8]
.text:000000018002E77F 45 33 C0                                xor     r8d, r8d
.text:000000018002E782 48 8B D1                                mov     rdx, rcx
.text:000000018002E785 41 8D 48 01                             lea     ecx, [r8+1]
.text:000000018002E789 E8 52 5C FF FF                          call    RtlImageNtHeaderEx
.text:000000018002E789
.text:000000018002E78E 48 8B 44 24 38                          mov     rax, [rsp+28h+arg_8]
.text:000000018002E793 48 83 C4 28                             add     rsp, 28h
.text:000000018002E797 C3                                      retn

After running the script:

                    STACK VIEW
-0000000000000001     // padding byte
+0000000000000000     _UNKNOWN *__return_address;
+0000000000000008     // padding byte
+0000000000000009     // padding byte
+000000000000000A     // padding byte
+000000000000000B     // padding byte
+000000000000000C     // padding byte
+000000000000000D     // padding byte
+000000000000000E     // padding byte
+000000000000000F     // padding byte
+0000000000000010     struct _IMAGE_NT_HEADERS64 *pNtHeaders;


                    DISASSEMBLY
.text:000000018002E770                                         public RtlImageNtHeader
.text:000000018002E770                         RtlImageNtHeader proc near              ; CODE XREF: sub_180007FF4+1B1↑p
.text:000000018002E770                                                                 ; sub_18002E394+66↑p ...
.text:000000018002E770
.text:000000018002E770                         pNtHeaders      = qword ptr  10h
.text:000000018002E770
.text:000000018002E770 48 83 EC 28                             sub     rsp, 28h
.text:000000018002E774 48 83 64 24 38 00                       and     [rsp+28h+pNtHeaders], 0
.text:000000018002E77A 4C 8D 4C 24 38                          lea     r9, [rsp+28h+pNtHeaders]
.text:000000018002E77F 45 33 C0                                xor     r8d, r8d
.text:000000018002E782 48 8B D1                                mov     rdx, rcx
.text:000000018002E785 41 8D 48 01                             lea     ecx, [r8+1]
.text:000000018002E789 E8 52 5C FF FF                          call    RtlImageNtHeaderEx
.text:000000018002E789
.text:000000018002E78E 48 8B 44 24 38                          mov     rax, [rsp+28h+pNtHeaders]
.text:000000018002E793 48 83 C4 28                             add     rsp, 28h
.text:000000018002E797 C3                                      retn
"""

new_name = "pNtHeaders"
caller_name = "RtlImageNtHeader"
callee_name = "RtlImageNtHeaderEx"

type_name = "_IMAGE_NT_HEADERS64"

lea_insn = None

def main():
    if not ida_ida.inf_is_64bit() or ida_ida.inf_get_procname() != "metapc":
        print("Not an x64 database. Quitting!")
        return

    func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, caller_name)
    if func_ea == ida_idaapi.BADADDR:
        print(f"Function {caller_name} not found. Quitting!")
        return

    # We will need the register number for `r9`
    import idautils
    R_r9 = idautils.procregs.r9.reg

    func_items = ida_funcs.func_item_iterator_t(ida_funcs.get_func(func_ea))
    for func_item in func_items.code_items():
        curr_insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(curr_insn, func_item):
            continue

        if curr_insn.itype == ida_allins.NN_lea:
            if curr_insn.Op1.type == ida_ua.o_reg and curr_insn.Op1.is_reg(R_r9):
                lea_insn = curr_insn
                continue

        if curr_insn.itype != ida_allins.NN_call:
            continue

        if ida_funcs.get_func_name(curr_insn.Op1.addr) == callee_name:
            caller_func = ida_funcs.get_func(func_ea)

            caller_frame = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(caller_frame, caller_func):
                print("Unable to get the frame of the caller function. Quitting!")
                break

            if lea_insn is None:
                print("LEA address is None. Could not happen! Stop!")
                break

            idx = caller_frame.get_stkvar(lea_insn, lea_insn.Op2, lea_insn.Op2.addr)
            if idx == -1:
                print("Returned stack variable index is -1. Should not happen. Stop!")
                break

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
                print(f"Unable to retrieve {type_name} type info object")
                continue

            if not tif.create_ptr(tif):
                print("Unable to create the pointer type.")
                continue

            if caller_frame.set_udm_type(idx, tif) == ida_typeinf.TERR_OK:
                print(f"Type applied to stack variable index {idx}.")
                if caller_frame.rename_udm(idx, new_name) == ida_typeinf.TERR_OK:
                    print(f"Name changed for stack variable index {idx}.")
                else:
                    print(f"Unable to rename stack variable index {idx}.")
            else:
                print(f"Unable to change type of stack variable index {idx}.")

main()
