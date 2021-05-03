"""
summary: produce listing

description:
  automate IDA to perform auto-analysis on a file and,
  once that is done, produce a .lst file with the disassembly.

  Run like so:

        ida -A "-S...path/to/produce_lst_file.py" <binary-file>

  where:

    * -A instructs IDA to run in non-interactive mode
    * -S holds a path to the script to run (note this is a single token;
         there is no space between '-S' and its path.)
"""

import ida_auto
import ida_fpro
import ida_ida
import ida_loader
import ida_pro

# derive output file name
idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
lst_path = "%s.lst" % idb_path

ida_auto.auto_wait() # wait for end of auto-analysis
fptr = ida_fpro.qfile_t() # FILE * wrapper
if fptr.open(lst_path, "wt"):
    try:
        ida_loader.gen_file( # generate .lst file
            ida_loader.OFILE_LST,
            fptr.get_fp(),
            ida_ida.inf_get_min_ea(),
            ida_ida.inf_get_max_ea(),
            0)
    finally:
        fptr.close()

ida_pro.qexit(0)
