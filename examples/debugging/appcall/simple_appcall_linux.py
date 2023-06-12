"""
summary: executing code into the application being debugged (on Linux)

description:
  Using the `ida_idd.Appcall` utility to execute code in
  the process being debugged.

  This example will run the test program and stop wherever
  the cursor currently is, and then perform an appcall to
  execute the `ref4` and `ref8` functions.

  To use this example:

    * run `ida64` on test program `simple_appcall_linux64`, or
      `ida` on test program `simple_appcall_linux32`, and wait for
      auto-analysis to finish
    * select the 'linux debugger' (either local, or remote)
    * run this script

  Note: the real body of code is in `simple_appcall_common.py`.
"""

import os
import sys
sys.path.append(os.path.dirname(__file__))

import simple_appcall_common
appcall_hooks = simple_appcall_common.appcall_hooks_t()
appcall_hooks.hook()
appcall_hooks.run()
