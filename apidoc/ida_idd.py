
def dbg_get_registers():
    """
    This function returns the register definition from the currently loaded debugger.
    Basically, it returns an array of structure similar to to idd.hpp / register_info_t

    @return:
        None if no debugger is loaded
        tuple(name, flags, class, dtype, bit_strings, default_bit_strings_mask)
        The bit_strings can be a tuple of strings or None (if the register does not have bit_strings)
    """
    pass


def dbg_get_thread_sreg_base(tid, sreg_value):
    """
    Returns the segment register base value

    @param tid: thread id
    @param sreg_value: segment register (selector) value
    @return:
        - The base as an 'ea'
        - Or None on failure
    """
    pass


def dbg_read_memory(ea, sz):
    """
    Reads from the debugee's memory at the specified ea

    @param ea: the debuggee's memory address
    @param sz: the amount of data to read
    @return:
        - The read buffer (as bytes)
        - Or None on failure
    """
    pass


def dbg_write_memory(ea, buffer):
    """
    Writes a buffer to the debugee's memory

    @param ea: the debuggee's memory address
    @param buf: a bytes object to write
    @return: Boolean
    """
    pass


def dbg_get_name():
    """
    This function returns the current debugger's name.

    @return: Debugger name or None if no debugger is active
    """
    pass


def dbg_get_memory_info():
    """
    This function returns the memory configuration of a debugged process.

    @return:
        None if no debugger is active
        tuple(start_ea, end_ea, name, sclass, sbase, bitness, perm)
    """
    pass


