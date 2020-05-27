from __future__ import print_function
#
# This sample illustrates how to use appcall, with the
# 'simple_appcall_linux32' or 'simple_appcall_linux64' test
# programs (see subdirectories.)
#
# This example will run the test program and stop wherever
# the cursor currently is, and then perform an appcall to
# `ref4` and `ref8`
#
# To use this example:
#  * run `ida64` on test program `simple_appcall_linux64`, or
#   `ida` on test program `simple_appcall_linux32`, and wait for
#    auto-analysis to finish
#  * select the 'linux debugger' (either local, or remote)
#  * run this script
#

import os
import sys
sys.path.append(os.path.dirname(__file__))

import simple_appcall_common
appcall_hooks = simple_appcall_common.appcall_hooks_t()
appcall_hooks.hook()
appcall_hooks.run()
