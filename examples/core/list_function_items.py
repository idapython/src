"""
summary: showcases (a few of) the iterators available on a function

description:
  This demonstrates how to use some of the iterators available on the func_t type.

  This example will focus on:

    * `func_t[.__iter__]`: the default iterator; iterates on instructions
    * `func_t.data_items`: iterate on data items contained within a function
    * `func_t.head_items`: iterate on 'heads' (i.e., addresses containing
                           the start of an instruction, or a data item.
    * `func_t.addresses`: iterate on all addresses within function (code
                          and data, beginning of an item or not)

  Type `help(ida_funcs.func_t)` for a full list of iterators.

  In addition, one can use:

    * `func_tail_iterator_t`: iterate on all the chunks (including
                              the main one) of the function
    * `func_parent_iterator_t`: iterate on all the parent functions,
                                that include this chunk

keywords: funcs iterator
"""

import ida_bytes
import ida_kernwin
import ida_funcs
import ida_ua

class logger_t(object):

    class section_t(object):
        def __init__(self, logger, header):
            self.logger = logger
            self.logger.log(header)
        def __enter__(self):
            self.logger.indent += 2
            return self
        def __exit__(self, tp, value, traceback):
            self.logger.indent -= 2
            if value:
                return False # Re-raise

    def __init__(self):
        self.indent = 0

    def log(self, *args):
        print("  " * self.indent + "".join(args))

    def log_ea(self, ea):
        F = ida_bytes.get_flags(ea)
        parts = ["0x%08x" % ea, ": "]
        if ida_bytes.is_code(F):
            parts.append("instruction (%s)" % ida_ua.print_insn_mnem(ea))
        if ida_bytes.is_data(F):
            parts.append("data")
        if ida_bytes.is_tail(F):
            parts.append("tail")
        if ida_bytes.is_unknown(F):
            parts.append("unknown")
        if ida_funcs.get_func(ea) != ida_funcs.get_fchunk(ea):
            parts.append(" (in function chunk)")
        self.log(*parts)

def main():
    # Get current ea
    ea = ida_kernwin.get_screen_ea()

    pfn = ida_funcs.get_func(ea)

    if pfn is None:
        print("No function defined at 0x%x" % ea)
        return

    func_name = ida_funcs.get_func_name(pfn.start_ea)
    logger = logger_t()
    logger.log("Function %s at 0x%x" % (func_name, ea))

    with logger_t.section_t(logger, "Code items:"):
        for item in pfn:
            logger.log_ea(item)

    with logger_t.section_t(logger, "'head' items:"):
        for item in pfn.head_items():
            logger.log_ea(item)

    with logger_t.section_t(logger, "Addresses:"):
        for item in pfn.addresses():
            logger.log_ea(item)

    with logger_t.section_t(logger, "Function chunks:"):
        for chunk in ida_funcs.func_tail_iterator_t(pfn):
            logger.log("%s chunk: 0x%08x..0x%08x" % (
                "Main" if chunk.start_ea == pfn.start_ea else "Tail",
                chunk.start_ea,
                chunk.end_ea))

if __name__ == '__main__':
    main()
