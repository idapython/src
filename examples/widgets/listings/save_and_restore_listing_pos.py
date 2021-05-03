"""
summary: save, and then restore, positions in a listing

description:
  Shows how it is possible re-implement IDA's bookmark capability,
  using 2 custom actions: one action saves the current location,
  and the other restores it.

  Note that, contrary to actual bookmarks, this example:

    * remembers only 1 saved position
    * doesn't save that position in the IDB (and therefore cannot
      be restored if IDA is closed & reopened.)

keywords: listing, actions

see_also: jump_next_comment
"""

import ida_kernwin
import ida_moves

class listing_action_handler_t(ida_kernwin.action_handler_t):
    def update(self, ctx):
        is_listing = ctx.widget_type in [
            ida_kernwin.BWN_ENUMS,
            ida_kernwin.BWN_STRUCTS,
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_CUSTVIEW,
            ida_kernwin.BWN_PSEUDOCODE,
        ]
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if is_listing else ida_kernwin.AST_DISABLE_FOR_WIDGET

class last_pos_t(object):
    def __init__(self, widget_title, lochist_entry):
        self.widget_title = widget_title
        self.lochist_entry = lochist_entry

last_pos = None

class save_position_ah_t(listing_action_handler_t):

    ACTION_NAME = "save_and_restore_listing_pos:save_position"
    ACTION_LABEL = "Save position"
    ACTION_SHORTCUT = "Ctrl+Shift+S"
    HELP_TEXT = "Press %s in a 'listing' widget such as 'IDA View-A', 'Enums', 'Structures', 'Pseudocode-A', ... to remember the position" % ACTION_SHORTCUT

    def activate(self, ctx):
        global last_pos
        e = ida_moves.lochist_entry_t()
        if ida_kernwin.get_custom_viewer_location(e, ctx.widget):
            last_pos = last_pos_t(ctx.widget_title, e)
        else:
            print("Failed to retrieve position")


class restore_position_ah_t(listing_action_handler_t):

    ACTION_NAME = "save_and_restore_listing_pos:restore_position"
    ACTION_LABEL = "Restore position"
    ACTION_SHORTCUT = "Ctrl+Shift+O"
    HELP_TEXT = "Press %s in a 'listing' widget such as 'IDA View-A', 'Enums', 'Structures', 'Pseudocode-A', ... to restore a previously-saved position" % ACTION_SHORTCUT

    def activate(self, ctx):
        global last_pos
        if last_pos:
            w = ida_kernwin.find_widget(last_pos.widget_title)
            if w:
                ida_kernwin.custom_viewer_jump(w, last_pos.lochist_entry)
            else:
                print("Widget \"%s\" not found" % last_pos.widget_title)
        else:
            print("No last position to restore")


klasses = [
    save_position_ah_t,
    restore_position_ah_t,
]

for klass in klasses:
    if ida_kernwin.unregister_action(klass.ACTION_NAME):
        print("Unregistered previously-registered action \"%s\"" % klass.ACTION_LABEL)

    if ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                klass.ACTION_NAME,
                klass.ACTION_LABEL,
                klass(),
                klass.ACTION_SHORTCUT)):
        print("Registered action \"%s\". %s" % (klass.ACTION_LABEL, klass.HELP_TEXT))

