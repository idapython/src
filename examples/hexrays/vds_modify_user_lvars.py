"""
summary: modifying local variables

description:
  Use a `ida_hexrays.user_lvar_modifier_t` to modify names,
  comments and/or types of local variables.
"""

import ida_hexrays
import ida_typeinf

import idc

class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, name_prefix="", cmt_prefix="", new_types={}):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.name_prefix = name_prefix
        self.cmt_prefix = cmt_prefix
        self.new_types = new_types

    def modify_lvars(self, lvars):
        def log(msg):
            print("modify_lvars: %s" % msg)
        log("len(lvars.lvvec) = %d" % len(lvars.lvvec))
        log("lvars.lmaps.size() = %d" % lvars.lmaps.size())
        log("lvars.stkoff_delta = %d" % lvars.stkoff_delta)
        log("lvars.ulv_flags = %x" % lvars.ulv_flags)

        for idx, one in enumerate(lvars.lvvec):
            def varlog(msg):
                log("var #%d: %s" % (idx, msg))
            varlog("name = '%s'" % one.name)
            varlog("type = '%s'" % one.type._print())
            varlog("cmt = '%s'" % one.cmt)
            varlog("size = %d" % one.size)
            varlog("flags = %x" % one.flags)
            new_type = self.new_types.get(one.name)
            if new_type:
                tif = ida_typeinf.tinfo_t()
                ida_typeinf.parse_decl(tif, None, new_type, 0)
                one.type = tif
            one.name = self.name_prefix + one.name
            one.cmt = self.cmt_prefix + one.cmt

        return True


def modify_function_lvars(name_prefix="patched_", cmt_prefix="(patched) ", new_types={}):
    ea = idc.here()
    my_mod = my_modifier_t(
        name_prefix=name_prefix,
        cmt_prefix=cmt_prefix,
        new_types=new_types)
    ida_hexrays.modify_user_lvars(ea, my_mod)
