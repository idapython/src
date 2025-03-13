"""
summary: change the name of an existing stack variable

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we demonstrate a way to change the name of a
    stack variable:
    * Get the function object surrounding cursor location.
    * Use this function to retrieve the corresponding frame object.
    * Find the frame member matching the given name.
    * Using its offset in the frame structure object, calculate
      the actual stack delta.
    * Use the previous result to redefine the stack variable name if
      it is not a special or argument member.

level: advanced
"""
import ida_funcs
import ida_frame
import ida_typeinf
import idc

def rename_stkvar(func_ea, old_name, new_name):
    func = ida_funcs.get_func(func_ea)
    if func is None:
        print("Please position the cursor inside a function.")
        return False

    print(f"Function @ {func.start_ea:x}")
    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        print("No frame returned.")
        return
    print(f"{frame_tif._print()}")

    idx, udm = frame_tif.get_udm(old_name)
    if not udm:
        print(f"{old_name} not found.")
        return

    print(f"Index of {old_name}: {idx}")
    tid = frame_tif.get_udm_tid(idx)
    if ida_frame.is_special_frame_member(tid):
        print(f"{old_name} is a special frame member. Will not change the name.")
    else:
        udm = ida_typeinf.udm_t()
        frame_tif.get_udm_by_tid(udm, tid)
        offset = udm.offset // 8
        if ida_frame.is_funcarg_off(func, offset):
            print(f"{old_name} is an argument member. Will not change the name.")
        else:
            sval = ida_frame.soff_to_fpoff(func, offset)
            print(f"Frame offset: {sval:x}")
            ida_frame.define_stkvar(func, new_name, sval, udm.type)

rename_stkvar(idc.here(), "arg_8", "Renamed")
