"""
summary: decompile entire file

description:
  automate IDA to perform auto-analysis on a file and,
  once that is done, produce a .c file containing the
  decompilation of all the functions in that file.

  Run like so:

        ida -A "-S...path/to/produce_c_file.py" <binary-file>

  where:

    * -A instructs IDA to run in non-interactive mode
    * -S holds a path to the script to run (note this is a single token;
         there is no space between '-S' and its path.)
"""

import ida_pro
import ida_auto
import ida_loader
import ida_hexrays

# derive output file name
idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
c_path = "%s.c" % idb_path

ida_auto.auto_wait() # wait for end of auto-analysis
ida_hexrays.decompile_many( # generate .c file
    c_path,
    None,
    ida_hexrays.VDRUN_NEWFILE
   |ida_hexrays.VDRUN_SILENT
   |ida_hexrays.VDRUN_MAYSTOP)

ida_pro.qexit(0)
