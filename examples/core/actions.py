"""
summary: custom actions, with icons & tooltips

description:
  How to create user actions, that once created can be
  inserted in menus, toolbars, context menus, ...

  Those actions, when triggered, will be passed a 'context'
  that contains some of the most frequently needed bits of
  information.

  In addition, custom actions can determine when they want
  to be available (through their
  `ida_kernwin.action_handler_t.update` callback)

keywords: actions

see_also: add_hotkey
"""

import ida_kernwin

class SayHi(ida_kernwin.action_handler_t):
    def __init__(self, message):
        ida_kernwin.action_handler_t.__init__(self)
        self.message = message

    def activate(self, ctx):
        print("Hi, %s" % (self.message))
        # print("context fields: %s" % dir(ctx))
        print(" cur_ea %08X" % ctx.cur_ea)
        print(" cur_value: %08X" % ctx.cur_value)
        print(" cur_extracted_ea %08X" % ctx.cur_extracted_ea)
        return 1

    # You can implement update(), to inform IDA when:
    #  * your action is enabled
    #  * update() should queried again
    # E.g., returning 'ida_kernwin.AST_ENABLE_FOR_WIDGET' will
    # tell IDA that this action is available while the
    # user is in the current widget, and that update()
    # must be queried again once the user gives focus
    # to another widget.
    #
    # For example, the following update() implementation
    # will let IDA know that the action is available in
    # "IDA View-*" views, and that it's not even worth
    # querying update() anymore until the user has moved
    # to another view..
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_DISASM else ida_kernwin.AST_DISABLE_FOR_WIDGET


print("Creating a custom icon from raw data!")
# Stunned panda face icon data.
icon_data = b"".join([
        b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF\x61\x00\x00\x02\xCA\x49\x44\x41\x54\x78\x5E\x65",
        b"\x53\x6D\x48\x53\x6F\x14\x3F\xBA\xB5\xB7\xA0\x8D\x20\x41\xF2\xBA\x5D\xB6\x0F\x56\xF4\x41\xA2\xC0\x9C\xE9\xB4\x29\x4A\x7D\xB0\x22\x7A\x11\x02\x23\x48\x2A\xD4\x74\x53\x33\x3F\xD4",
        b"\x3E\x4A\x50\x19\xE4\xB0\xD0\x22\xCD\x44\x45\x4A\x31\x8C\x92\xA2\x3E\x65\x0A\x4D\xCB\x96\x7E\xE8\xD5\x97\xCC\xFE\xFE\x37\xA7\x77\xDB\xBD\xA7\xE7\x3C\xBE\x05\x9E\xED\xB7\xB3\xF3",
        b"\x7B\x39\xF7\xEE\x19\x17\xA8\xAC\x56\xDB\x54\x82\x60\x41\xB3\x59\xBC\xFF\xAC\xF9\xCA\xB5\xAE\x86\xCA\xF9\x4E\xAF\x1B\x3B\xEA\x5D\x48\x9D\x66\xE2\x49\x27\x9F\xD5\x66\x9B\xA2\x1C",
        b"\x22\x02\xD0\x40\xE4\x81\x6C\x3B\x76\x37\x56\xE3\x37\x5F\x2F\x62\xE8\x0B\xD3\x66\x19\x7E\x53\xA7\x99\x78\xAE\x1F\x64\x3E\x21\x71\x69\x09\x5F\x20\x98\x2D\x58\x70\x24\x07\x07\x7B",
        b"\x6F\xB0\x79\x82\x61\x81\x21\xCC\xDE\x21\x54\x16\x02\xD4\x69\x26\x9E\x74\xEE\xCB\xCF\x4D\xC7\x44\xB3\x88\x7C\x81\xC5\x22\xFE\x6C\xB9\xE9\x46\x67\x46\x1A\x8A\x16\x2B\x0A\x5B\x05",
        b"\x74\x66\x65\xE1\x98\x6F\x00\x31\x32\x87\x9F\x59\x77\x66\x66\x61\x42\xBC\xC0\xF5\x6C\x47\x1A\x36\xD7\xB9\x51\x14\xC5\x1E\xBE\xA0\xC3\x5B\xD9\x98\x99\xE1\xC0\xCE\xBE\x57\x48\xD7",
        b"\x9A\x63\x68\xEA\x7C\x8A\xF6\x14\x3B\x9F\xF6\xA6\xA4\x60\xEB\xE3\x3E\x9C\x5F\xD6\x5A\x7A\xFA\x71\xBF\xC3\x81\x3D\x4D\x35\x0D\x7C\xC1\xF3\x87\x57\x43\xF9\x87\x8F\x21\x95\x5E\xAB",
        b"\x41\x83\x4E\x83\x54\xDB\x92\x76\x20\xCA\xBF\xD0\x99\x9D\xBB\x4E\xDB\xBD\xC7\x8E\x2F\x5A\x3D\x74\x3D\x50\x03\x80\x7E\x7A\x7A\x06\x46\x47\xFD\xA0\x33\x6C\x84\x18\x46\x0C\xBD\x1F",
        b"\x86\x2D\x71\x71\x00\x52\x10\x16\x17\xE6\xC1\xE7\x1B\x61\x9A\x81\x69\x31\x30\xFC\x61\x14\xB4\x3A\x3D\x20\x82\x1E\x58\xA9\x15\x05\x41\x14\x05\xB8\x58\xEE\x82\x7D\xE9\x99\x20\xCB",
        b"\x32\x94\x95\x95\xC3\xA5\xD2\x53\x00\x51\x09\xAA\x4B\x0B\xA1\xB8\xA4\x0C\x52\x53\x33\x40\xA5\x52\x81\xDB\x5D\x01\xA2\x45\x00\x45\x51\x80\x2A\x36\x12\x8D\x42\x49\x51\x01\x44\xE5",
        b"\x18\x90\x22\x0A\x98\x8C\x46\xF0\x54\x14\x42\x6D\x7D\x3B\xE4\x1C\x75\x41\xAD\xB7\x1D\x3C\x55\x85\x60\x32\x19\x41\x8A\x2A\xDC\x57\x5C\x74\x12\x28\x47\xA5\x8E\x44\xE4\xF0\x76\x5B",
        b"\x82\xA6\xCD\x5B\x0D\xB2\x12\xE6\xE4\x06\xB5\x1A\x66\xA7\x26\x41\x92\xC2\xA0\xD5\x6A\x60\x67\x92\x19\xAE\x7B\xCE\x70\x4D\x15\xAB\x01\xAD\xC1\x08\x3F\x46\x64\x6E\x8E\x9D\xF9\x13",
        b"\xE8\x1A\xFF\xE4\x63\x8A\x0E\xE6\x02\x41\xF8\x3F\x18\x82\x40\x28\x04\xFD\xDD\x75\xF0\xB6\xFF\x2E\x75\x9A\x89\x27\x9D\xFB\xC8\x4F\x39\xBE\xE0\xB4\xAB\xCE\x35\xFE\x71\x00\x16\x17",
        b"\x25\x76\x50\x26\x76\x6B\x61\x86\x08\xE4\x1D\xAF\x81\xBC\x13\x97\xA9\xD3\x4C\x3C\xE9\xDC\x47\x7E\xCA\xF1\x05\x0C\x5F\x7D\xFE\xEF\x35\x03\xAF\x9F\x00\xB0\x73\x30\x9A\xE2\x81\x0E",
        b"\xF6\xC1\xED\x52\xB8\x77\xAB\x98\x3A\xCD\xC4\x73\x9D\x7C\x6F\xDE\xF9\xCF\x53\x0E\xFE\xA9\xCD\xAE\xB3\x87\xCE\x75\x35\x54\xE1\xD0\xCB\x47\x38\x39\x36\x88\xFF\x4D\xF8\x57\x41\x33",
        b"\xF1\xA4\x93\x0F\x00\x36\xAD\x3E\x4C\x6B\xC5\xC9\x5D\x77\x6A\x2F\xB4\x31\xA3\xC4\x40\x4F\x21\x0F\xD1\x4C\x3C\xE9\x2B\xE1\xF5\x0B\xD6\x90\xC8\x90\x4C\xE6\x35\xD0\xCC\x79\x5E\xFF",
        b"\x2E\xF8\x0B\x2F\x3D\xE5\xC3\x97\x06\xCF\xCF\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82"])
act_icon = ida_kernwin.load_custom_icon(data=icon_data, format="png")

hooks = None
act_name = "example:add_action"

if ida_kernwin.register_action(ida_kernwin.action_desc_t(
        act_name,           # Name. Acts as an ID. Must be unique.
        "Say hi!",          # Label. That's what users see.
        SayHi("developer"), # Handler. Called when activated, and for updating
        "Ctrl+F12",         # Shortcut (optional)
        "Greets the user",  # Tooltip (optional)
        act_icon)):         # Icon ID (optional)
    print("Action registered. Attaching to menu.")

    # Insert the action in the menu
    if ida_kernwin.attach_action_to_menu("Edit/Export data", act_name, ida_kernwin.SETMENU_APP):
        print("Attached to menu.")
    else:
        print("Failed attaching to menu.")

    # Insert the action in a toolbar
    if ida_kernwin.attach_action_to_toolbar("AnalysisToolBar", act_name):
        print("Attached to toolbar.")
    else:
        print("Failed attaching to toolbar.")

    # We will also want our action to be available in the context menu
    # for the "IDA View-A" widget.
    #
    # To do that, we could in theory retrieve a reference to "IDA View-A", and
    # then request to "permanently" attach the action to it, using something
    # like this:
    #   ida_kernwin.attach_action_to_popup(ida_view_a, None, act_name, None)
    #
    # but alas, that won't do: widgets in IDA are very "volatile", and
    # can be deleted & re-created on some occasions (e.g., starting a
    # debugging session), and our efforts to permanently register our
    # action on "IDA View-A" would be annihilated as soon as "IDA View-A"
    # is deleted.
    #
    # Instead, we can opt for a different method: attach our action on-the-fly,
    # when the popup for "IDA View-A" is being populated, right before
    # it is displayed.
    class Hooks(ida_kernwin.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            # We'll add our action to all "IDA View-*"s.
            # If we wanted to add it only to "IDA View-A", we could
            # also discriminate on the widget's title:
            #
            #  if ida_kernwin.get_widget_title(widget) == "IDA View-A":
            #      ...
            #
            if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
                ida_kernwin.attach_action_to_popup(widget, popup, act_name, None)

    hooks = Hooks()
    hooks.hook()
else:
    print("Action found; unregistering.")
    # No need to call detach_action_from_menu(); it'll be
    # done automatically on destruction of the action.
    if ida_kernwin.unregister_action(act_name):
        print("Unregistered.")
    else:
        print("Failed to unregister action.")

    if hooks is not None:
        hooks.unhook()
        hooks = None
