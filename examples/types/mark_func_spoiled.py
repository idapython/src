"""
summary: mark a register "spoiled" by a function

description:
  At least two possibilies are offered in order to indicate that a function
  spoils registers (excluding the "normal" ones):

  You can either parse & apply a declaration:

        func_tfinfo = ida_typeinf.tinfo_t("int _spoils<rsi> main();")
        ida_typeinf.apply_tinfo(func.start_ea, func_tinfo, ida_typeinf.TINFO_DEFINITE)

  or retrieve & modify the `tinfo_t` object directly.

  This script showcases the latter.

level: beginner
"""

import ida_funcs
import ida_typeinf
import ida_idp
import ida_kernwin
import ida_nalt

def mark_spoiled(address, regs):

    func = ida_funcs.get_func(address)
    if func:
        func_type = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(func_type, func.start_ea)
        func_details = ida_typeinf.func_type_data_t()
        func_type.get_func_details(func_details)

        for reg in regs:
            reg_info = ida_idp.reg_info_t()
            ida_idp.parse_reg_name(reg_info, reg)
            func_details.spoiled.append(reg_info)

        func_details.flags |= ida_typeinf.FTI_SPOILED
        func_type.create_func(func_details)
        return ida_typeinf.apply_tinfo(func.start_ea, func_type, ida_typeinf.TINFO_DEFINITE)

mark_spoiled(ida_kernwin.get_screen_ea(), ["rsi"])
