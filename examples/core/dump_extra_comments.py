from __future__ import print_function
# -----------------------------------------------------------------------
# This example illustrates how to use the 'get_extra_cmt' API,
# to retrieve anterior and posterior extra comments.
#
# After running this script, use Ctrl+Shift+Y when in the disassembly
# view to print previous extra comment, and Ctrl+Shift+Z to print next
# extra comments.
#
# (c) Hex-Rays

import ida_lines
import ida_kernwin


# -----------------------------------------------------------------------
class dump_at_point_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, anchor):
        ida_kernwin.action_handler_t.__init__(self)
        self.anchor = anchor

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        index = self.anchor
        while True:
            cmt = ida_lines.get_extra_cmt(ea, index)
            if cmt is None:
                break
            print("Got: '%s'" % cmt)
            index += 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_DISASM \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET

    @staticmethod
    def compose_action_name(v):
        return "dump_extra_comments:%s" % v


# -----------------------------------------------------------------------
# create actions (and attach them to IDA View-A's context menu if possible)
widget_title = "IDA View-A"
ida_view = ida_kernwin.find_widget(widget_title)

actions_variants = [
    ("previous", ida_lines.E_PREV, "Ctrl+Shift+Y"),
    ("next", ida_lines.E_NEXT, "Ctrl+Shift+Z"),
]
for label, anchor, shortcut in actions_variants:
    actname = dump_at_point_handler_t.compose_action_name(label)
    if ida_kernwin.unregister_action(actname):
        print("Unregistered previously-registered action \"%s\"" % actname)

    desc = ida_kernwin.action_desc_t(
        actname,
        "Dump %s extra comments" % label,
        dump_at_point_handler_t(anchor),
        shortcut)
    if ida_kernwin.register_action(desc):
        print("Registered action \"%s\"" % actname)

    if ida_view and ida_kernwin.attach_action_to_popup(ida_view, None, actname):
        print("Permanently attached action \"%s\" to \"%s\"" % (actname, widget_title))
