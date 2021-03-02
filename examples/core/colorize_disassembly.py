from __future__ import print_function

#---------------------------------------------------------------------
# This illustrates the setting/retrievel of background colours,
# using the IDC wrappers

BG_BLUE  = 0xc02020
BG_GREEN = 0x208020
BG_RED   = 0x2020c0

import idc

ea = idc.here()
idc.set_color(ea, idc.CIC_SEGM, BG_BLUE)
idc.set_color(ea, idc.CIC_FUNC, BG_GREEN)
idc.set_color(ea, idc.CIC_ITEM, BG_RED)
print("Segment:  %x" % idc.get_color(ea, idc.CIC_SEGM))
print("Function: %x" % idc.get_color(ea, idc.CIC_FUNC))
print("Item:     %x" % idc.get_color(ea, idc.CIC_ITEM))
