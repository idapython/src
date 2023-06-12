"""
summary: inserting information into disassembly prefixes

description:
  By default, disassembly line prefixes contain segment + address
  information (e.g., '.text:08047718'), but it is possible to
  "inject" other bits of information in there, thanks to the
  `ida_lines.user_defined_prefix_t` helper type.
"""

import ida_lines
import ida_idaapi

PREFIX = ida_lines.SCOLOR_INV + ' ' + ida_lines.SCOLOR_INV

class my_user_prefix_t(ida_lines.user_defined_prefix_t):
    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        if (ea % 2 == 0) and indent == -1:
            return PREFIX
        else:
            return ""


class prefix_plugin_t(ida_idaapi.plugin_t):
    flags = 0
    comment = "This is a user defined prefix sample plugin"
    help = "This is help"
    wanted_name = "user defined prefix"
    wanted_hotkey = ""

    def __init__(self):
        self.prefix = None

    def init(self):
        self.prefix = my_user_prefix_t(8)
        print("prefix installed")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.prefix = None
        print("prefix uninstalled!")


def PLUGIN_ENTRY():
    return prefix_plugin_t()

