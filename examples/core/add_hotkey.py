"""
summary: triggering bits of code by pressing a shortcut

description:
  `ida_kernwin.add_hotkey` is a simpler, but much less flexible
  alternative to `ida_kernwin.register_action` (though it does
  use the same mechanism under the hood.)

  It's particularly useful during prototyping, but note that the
  actions that are created cannot be inserted in menus, toolbars
  or cannot provide a custom `ida_kernwin.action_handler_t.update`
  callback.

keywords: actions

see_also: actions
"""

import ida_kernwin

def hotkey_pressed():
    print("hotkey pressed!")

try:
    hotkey_ctx
    if ida_kernwin.del_hotkey(hotkey_ctx):
        print("Hotkey unregistered!")
        del hotkey_ctx
    else:
        print("Failed to delete hotkey!")
except:
    hotkey_ctx = ida_kernwin.add_hotkey("Shift-A", hotkey_pressed)
    if hotkey_ctx is None:
        print("Failed to register hotkey!")
        del hotkey_ctx
    else:
        print("Hotkey registered!")
