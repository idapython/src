"""
summary: parse listing line, and dump some information

description:
  Using `ida_kernwin.parse_tagged_line_sections`, we will parse
  so-called "tagged" listing lines, and extract semantic information
  such as instruction mnemonic, operand text, ...

  This script registers an actions, that can be used to dump
  the line sections.

level: intermediate
"""

ACTION_NAME = "dump_line_sections:dump"
ACTION_SHORTCUT = "Ctrl+Shift+D"

import ida_kernwin
import ida_lines

class dump_line_sections_ah_t(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        tls = ida_kernwin.tagged_line_sections_t()
        raw = ida_kernwin.get_custom_viewer_curline(ctx.widget, False)
        if ida_kernwin.parse_tagged_line_sections(tls, raw):
            insn_section = tls.first(ida_lines.COLOR_INSN)
            if insn_section:
                print("Found instruction with mnemonic \"%s\"" % insn_section.substr(raw))
                for op_tag in range(ida_lines.COLOR_OPND1, ida_lines.COLOR_OPND8 + 1):
                    op_n = tls.first(op_tag)
                    if not op_n:
                        break
                    print("  Operand #%d: (raw text) %s" % (op_tag - ida_lines.COLOR_OPND1, op_n.substr(raw)))
                    as_reg = tls.nearest_at(op_n.start, ida_lines.COLOR_REG)
                    if as_reg:
                        print("    Operand is register: \"%s\"" % as_reg.substr(raw))

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_DISASM \
               else ida_kernwin.AST_DISABLE_FOR_WIDGET



adesc = ida_kernwin.action_desc_t(
    ACTION_NAME,
    "Dump line sections",
    dump_line_sections_ah_t(),
    ACTION_SHORTCUT)

if ida_kernwin.register_action(adesc):
    print("Action registered. Please press \"%s\" to use" % ACTION_SHORTCUT)
