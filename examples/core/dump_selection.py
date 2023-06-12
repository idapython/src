"""
summary: retrieve & dump current selection

description:
  Shows how to retrieve the selection from a listing
  widget ("IDA View-A", "Hex View-1", "Pseudocode-A", ...) as
  two "cursors", and from there retrieve (in fact, generate)
  the corresponding text.

  After running this script:

    * select some text in one of the listing widgets (i.e.,
      "IDA View-*", "Enums", "Structures", "Pseudocode-*")
    * press Ctrl+Shift+S to dump the selection

"""

import ida_kernwin
import ida_lines

class dump_selection_handler_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if ctx.has_flag(ida_kernwin.ACF_HAS_SELECTION):
            tp0, tp1 = ctx.cur_sel._from, ctx.cur_sel.to
            ud = ida_kernwin.get_viewer_user_data(ctx.widget)
            lnar = ida_kernwin.linearray_t(ud)
            lnar.set_place(tp0.at)
            lines = []
            while True:
                cur_place = lnar.get_place()
                first_line_ref = ida_kernwin.l_compare2(cur_place, tp0.at, ud)
                last_line_ref = ida_kernwin.l_compare2(cur_place, tp1.at, ud)
                if last_line_ref > 0: # beyond last line
                    break
                line = ida_lines.tag_remove(lnar.down())
                if last_line_ref == 0: # at last line
                    line = line[0:tp1.x]
                elif first_line_ref == 0: # at first line
                    line = ' ' * tp0.x + line[tp0.x:]
                lines.append(line)
            for line in lines:
                print(line)
        return 1

    def update(self, ctx):
        ok_widgets = [
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_STRUCTS,
            ida_kernwin.BWN_ENUMS,
            ida_kernwin.BWN_PSEUDOCODE,
        ]
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type in ok_widgets \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


# -----------------------------------------------------------------------
# create actions (and attach them to IDA View-A's context menu if possible)
ACTION_NAME = "dump_selection"
ACTION_SHORTCUT = "Ctrl+Shift+S"

if ida_kernwin.unregister_action(ACTION_NAME):
    print("Unregistered previously-registered action \"%s\"" % ACTION_NAME)

if ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Dump selection",
            dump_selection_handler_t(),
            ACTION_SHORTCUT)):
    print("Registered action \"%s\"" % ACTION_NAME)
