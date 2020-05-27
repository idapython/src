from __future__ import print_function
#---------------------------------------------------------------------
# This script demonstrates the usage of hotkeys.
#
# 'ida_kernwin.add_hotkey' offers a simpler alternative to
# 'ida_kernwin.register_action', but is much less flexible.
#
# Author: IDAPython team
#---------------------------------------------------------------------
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
