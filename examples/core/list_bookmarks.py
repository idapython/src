"""
summary: list bookmarks associated to a listing

description:
  This sample shows how to programmatically access the list of
  bookmarks placed in a listing widget (e.g., "IDA View-A",
  "Pseudocode-", …) using the low-level `ida_moves.bookmarks_t`
  type.

keywords: bookmarks
"""

import ida_kernwin
import ida_moves

class list_bookmarks_ah_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        v = ida_kernwin.get_current_viewer()
        if v:
            print("### Bookmarks for %s" % ida_kernwin.get_widget_title(v))
            ud = ida_kernwin.get_viewer_user_data(v)
            for loc, desc in ida_moves.bookmarks_t(v):
                print("\t'%s': %s" % (loc.place()._print(ud), desc))

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ida_kernwin.get_current_viewer() \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET

ACTION_NAME = "example:list_bookmarks"
ACTION_LABEL = "List bookmarks"
ACTION_SHORTCUT = "Ctrl+!"
ACTION_HELP = "Press %s to list bookmarks" % ACTION_SHORTCUT

if ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_NAME,
        ACTION_LABEL,
        list_bookmarks_ah_t(),
        ACTION_SHORTCUT)):
    print("Registered action \"%s\". %s" % (ACTION_LABEL, ACTION_HELP))
