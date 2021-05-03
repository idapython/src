"""
summary: retrieve the strings that are selected in the "Strings" window.

description:
  In IDA it's possible to write actions that can be applied even to
  core (i.e., "standard") widgets. The actions in this example use the
  action "context" to know what the current selection is.

  This example shows how you can either retrieve string literals data
  directly from the chooser (`ida_kernwin.get_chooser_data`), or
  by querying the IDB (`ida_bytes.get_strlit_contents`)

keywords: actions

see_also: list_strings
"""

import ida_kernwin
import ida_strlist
import ida_bytes

class show_strings_base_ah_t(ida_kernwin.action_handler_t):

    def __init__(self, use_get_chooser_data):
        ida_kernwin.action_handler_t.__init__(self)
        self.use_get_chooser_data = use_get_chooser_data

    def activate(self, ctx):
        for idx in ctx.chooser_selection:
            if self.use_get_chooser_data:
                _, _, _, s = ida_kernwin.get_chooser_data(ctx.widget_title, idx)
            else:
                si = ida_strlist.string_info_t()
                if ida_strlist.get_strlist_item(si, idx):
                    s = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
            print("Selected string (retrieved using %s) at index %d: \"%s\"" % (
                "get_chooser_data()" if self.use_get_chooser_data else "get_strlist_item()",
                idx,
                s))
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_STRINGS \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


class show_strings_using_get_chooser_data_ah_t(show_strings_base_ah_t):
    ACTION_NAME = "test:show_string_using_get_chooser_data"
    ACTION_LABEL = "Show current string(s) using get_chooser_data()"
    ACTION_SHORTCUT = "Ctrl+Shift+S"

    def __init__(self):
        show_strings_base_ah_t.__init__(self, True)


class show_strings_using_get_strlist_item_ah_t(show_strings_base_ah_t):
    ACTION_NAME = "test:show_string_using_get_strlist_item"
    ACTION_LABEL = "Show current string(s) using get_strlist_item() + get_strlit_contents()"
    ACTION_SHORTCUT = "Ctrl+Shift+K"

    def __init__(self):
        show_strings_base_ah_t.__init__(self, False)


klasses = [
    show_strings_using_get_chooser_data_ah_t,
    show_strings_using_get_strlist_item_ah_t,
]

sw = ida_kernwin.find_widget("Strings")
if not sw:
    sw = ida_kernwin.open_strings_window(ida_idaapi.BADADDR)

for klass in klasses:
    if ida_kernwin.unregister_action(klass.ACTION_NAME):
        print("Unregistered previously-registered action \"%s\"" % klass.ACTION_LABEL)

    if ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                klass.ACTION_NAME,
                klass.ACTION_LABEL,
                klass(),
                klass.ACTION_SHORTCUT)):
        print("Registered action \"%s\"" % (klass.ACTION_LABEL,))
        if sw:
            ida_kernwin.attach_action_to_popup(sw, None, klass.ACTION_NAME)
            print("Permanently added action to \"String window\"'s popup")
