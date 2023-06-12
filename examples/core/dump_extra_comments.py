"""
summary: retrieve extra comments

description:
  Use the `ida_lines.get_extra_cmt` API to retrieve anterior
  and posterior extra comments.

  This script registers two actions, that can be used to dump
  the previous and next extra comments.
"""

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


# --------------------------------------------------------
# action variants

class action_previous_handler_t(dump_at_point_handler_t):
    ACTION_LABEL    = "previous"
    ACTION_SHORTCUT = "Ctrl+Shift+Y"

    def __init__(self):
        super(action_previous_handler_t, self).__init__(ida_lines.E_PREV)

class action_next_handler_t(dump_at_point_handler_t):
    ACTION_LABEL    = "next"
    ACTION_SHORTCUT = "Ctrl+Shift+Z"

    def __init__(self):
        super(action_next_handler_t, self).__init__(ida_lines.E_NEXT)


# -----------------------------------------------------------------------
# create actions (and attach them to IDA View-A's context menu if possible)
widget_title = "IDA View-A"
ida_view = ida_kernwin.find_widget(widget_title)

action_variants = [
    action_previous_handler_t,
    action_next_handler_t,
]
for variant in action_variants:
    actname = dump_at_point_handler_t.compose_action_name(variant.ACTION_LABEL)
    if ida_kernwin.unregister_action(actname):
        print("Unregistered previously-registered action \"%s\"" % actname)

    desc = ida_kernwin.action_desc_t(
        actname,
        "Dump %s extra comments" % variant.ACTION_LABEL,
        variant(),
        variant.ACTION_SHORTCUT)
    if ida_kernwin.register_action(desc):
        print("Registered action \"%s\"" % actname)

    if ida_view and ida_kernwin.attach_action_to_popup(ida_view, None, actname):
        print("Permanently attached action \"%s\" to \"%s\"" % (actname, widget_title))
