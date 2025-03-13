"""
summary: create a segment, and define (complex) data in it

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we show how to create, set type and name of
    a user shared data region in an ntdll IDB:
    * Load the `_KUSER_SHARED_DATA` data type from a type info
      library shipped with IDA, and import it into the IDB's "local types"
    * Create a data segment with UserSharedData as its name.
    * Apply the type to the start of the newly created segment base
      address.
    * Set the address name.

level: intermediate
"""
import ida_segment
import ida_typeinf
import ida_name
import ida_kernwin

USE64 = 2
PERM_RW  = 0x6
start_ea = 0x7FFE0000

_KUSER_SHARED_DATA = "_KUSER_SHARED_DATA"

tif = ida_typeinf.get_idati().get_named_type(_KUSER_SHARED_DATA)
if not tif:

    # Load type library containing the type we're interested in
    ntddk64 = ida_typeinf.load_til("ntddk64")

    # Import the type in the "Local types"
    tif = ida_typeinf.get_idati().import_type(ntddk64.get_named_type(_KUSER_SHARED_DATA))

    # clean up after ourselves
    ida_typeinf.free_til(ntddk64)

assert(tif is not None)

segm = ida_segment.segment_t()
segm.start_ea = start_ea
segm.end_ea = start_ea + tif.get_size()
segm.sel = ida_segment.setup_selector(0)
segm.bitness = USE64
segm.align = ida_segment.saRelPara
segm.comb = ida_segment.scPub
segm.perm = PERM_RW
if ida_segment.add_segm_ex(segm, "UserSharedData", "DATA", 0) < 0:
    print("Unable to create the shared data segment.")
else:
    if not ida_typeinf.apply_tinfo(start_ea, tif, ida_typeinf.TINFO_DEFINITE):
        print(f"Unable to apply type information @ {start_ea:x}.")
    else:
        if ida_name.set_name(start_ea, "UserSharedData"):
            print("Done!")
        else:
            print(f"Unable to set {start_ea:x} name.")
