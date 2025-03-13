"""
summary: add a new member to an existing function frame

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we show a way to add a new frame member (a pointer to
     an uint64) inside a wide enough gap in the frame:
    * Get the function object surrounding cursor location.
    * Use this function to retrieve the corresponding frame object.
    * Find a wide enough gap to create our new member.
    * If found, we use cal_frame_offset() to get the actual
      offset in the frame structure.
    * Use the previous result to add the new member.

level: advanced
"""
import ida_funcs
import ida_frame
import ida_typeinf
import ida_range
import idc

def add_frame_member(func_ea):
    name = "my_stkvar"

    tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)
    tif.create_ptr(tif)

    func = ida_funcs.get_func(func_ea)
    if not func:
        print('Failed to get function!')
        return
    print(f"Function @ {func.start_ea:x}")

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        print('Failed to get frame!')
        return
    print(f"{frame_tif._print()}")

    rs = ida_range.rangeset_t()
    sp_offset = 0
    if frame_tif.calc_gaps(rs):
        for range in rs:
            if range.start_ea <= 0:
                continue
            elif (range.end_ea - range.start_ea) >= tif.get_size():
                sp_offset = range.start_ea
                print(f"Range [{range.start_ea:x}, {range.end_ea:x}[ selected.")
                break
    
    if sp_offset > 0:
        sval = ida_frame.calc_frame_offset(func, sp_offset, None, None)
        if ida_frame.add_frame_member(func, name, sval, tif):
            print(f"Frame member added at frame offset {sval}!")
        else:
            print("Failed adding frame member")
    else:
        print("Could not find gaps in current frame...")

add_frame_member(idc.here())
