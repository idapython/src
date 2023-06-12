"""
summary: add functions to the IDC runtime from IDAPython

description:
  You can add IDC functions to IDA, whose "body" consists of
  IDAPython statements!

  We'll register a 'pow' function, available to all IDC code,
  that when invoked will call back into IDAPython, and execute
  the provided function body.

  After running this script, try switching to the IDC interpreter
  (using the button on the lower-left corner of IDA) and executing
  `pow(3, 7)`
"""

import ida_expr

if ida_expr.add_idc_func(
        "pow",
        lambda n, e: n ** e,
        (ida_expr.VT_LONG, ida_expr.VT_LONG)):
    print("The pow() function is now available in IDC")
else:
    print("Failed to register pow() IDC function")
