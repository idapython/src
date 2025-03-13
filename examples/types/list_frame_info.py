"""
summary: print function stack frame information

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we retrieve the function frame structure, and iterate
    on the frame members.

level: beginner
"""
import ida_funcs
import ida_frame
import ida_typeinf
import ida_kernwin

def list_frame_info(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        print(f"No function found at {func_ea:x}.")
        return

    frame_tif = func.frame_object
    if not frame_tif:
        print(f"Function {func.name} has no frame")
        return

    print("List frame information:")
    print("-----------------------")
    print(f"{func.name} @ {func.start_ea:x} framesize {frame_tif.get_size():x}")
    print(f"Local variable size: {func.frsize:x}")
    print(f"Saved registers: {func.frregs:x}")
    print(f"Argument size: {func.argsize:x}")
    for idx, udm in enumerate(frame_tif.iter_struct()):
        print(f"\t#{idx} {udm.name}: soff={udm.offset//8:x} eof={udm.end()//8:x} {udm.type.dstr()}")
        idx += 1

list_frame_info(ida_kernwin.get_screen_ea())
