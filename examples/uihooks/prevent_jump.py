"""
summary: taking precedence over actions

description:
  Using `ida_kernwin.UI_Hooks.preprocess_action`, it is possible
  to respond to a command instead of the action that would
  otherwise do it.
"""

import ida_kernwin

class prevent_jump_t(ida_kernwin.UI_Hooks):
    def preprocess_action(self, action_name):
        if action_name == "JumpEnter":
            print("Inhibiting 'jump'!")
            return 1
        return 0

phh = prevent_jump_t()
if phh.hook():
    print("From now on, pressing <Enter> will prevent IDA from jumping. "\
          +"Please type 'phh.unhook()' to revert to the normal behavior.")
