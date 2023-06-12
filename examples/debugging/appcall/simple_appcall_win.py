"""
summary: executing code into the application being debugged (on Windows)

description:
  Using the `ida_idd.Appcall` utility to execute code in
  the process being debugged.

  This example will run the test program and stop wherever
  the cursor currently is, and then perform an appcall to
  execute the `ref4` and `ref8` functions.

  To use this example:

    * run `ida64` on test program `simple_appcall_win64.exe`, or
      `ida` on test program `simple_appcall_win32.exe`, and wait for
      auto-analysis to finish
    * select the 'windows debugger' (either local, or remote)
    * run this script

  Note: the real body of code is in `simple_appcall_common.py`.
"""

import os
import sys
sys.path.append(os.path.dirname(__file__))

# Windows binaries don't have any symbols, thus we'll have
# to assign names to addresses of interest before we can
# appcall them by name.
import ida_ida
if ida_ida.inf_is_64bit():
    ref4_ea = 0x140001000
    ref8_ea = 0x140001060
else:
    ref4_ea = 0x401000
    ref8_ea = 0x401050

import simple_appcall_common
appcall_hooks = simple_appcall_common.appcall_hooks_t(
    name_funcs=[
        (ref4_ea, "ref4"),
        (ref8_ea, "ref8"),
    ])

appcall_hooks.hook()
appcall_hooks.run()
