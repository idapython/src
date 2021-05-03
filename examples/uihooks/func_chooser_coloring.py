"""
summary: using `ida_kernwin.UI_Hooks.get_chooser_item_attrs` to override some defaults

description:
  color the function in the Function window according to its size.
  The larger the function, the darker the color.
"""

import ida_kernwin
import ida_funcs
import math

class func_chooser_coloring_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        self.colors = [0x808080 + (32-i) * 0x400 for i in range(32-5)]

    def get_chooser_item_attrs(self, chobj, n, attrs):
        if attrs.color != 0xFFFFFFFF:
            return # the color is already set
        ea = chobj.get_ea(n)
        fn = ida_funcs.get_func(ea)
        size = fn.size()
        if size < 32:
            return # do not color small functions
        attrs.color = self.colors[int(math.log2(size))]

fcch = func_chooser_coloring_hooks_t()
fcch.hook()
ida_kernwin.enable_chooser_item_attrs("Functions", True)

