#---------------------------------------------------------------------
# This script demonstrates the usage of hotkeys.
#
#
# Author: IDAPython team
#---------------------------------------------------------------------
import idaapi

def hotkey_pressed():
    print("hotkey pressed!")

try:
    hotkey_ctx
    if idaapi.del_hotkey(hotkey_ctx):
        print("Hotkey unregistered!")
        del hotkey_ctx
    else:
        print("Failed to delete hotkey!")
except:
    hotkey_ctx = idaapi.add_hotkey("Shift-A", hotkey_pressed)
    if hotkey_ctx is None:
        print("Failed to register hotkey!")
        del hotkey_ctx
    else:
        print("Hotkey registered!")
