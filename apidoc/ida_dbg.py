
def get_manual_regions(*args):
    """
    Returns the manual memory regions

    This function has the following signatures:

        1. get_manual_regions() -> List[Tuple(ida_idaapi.ea_t, ida_idaapi.ea_t, str, str, ida_idaapi.ea_t, int, int)]
           Where each tuple holds (start_ea, end_ea, name, sclass, sbase, bitness, perm)
        2. get_manual_regions(storage: meminfo_vec_t) -> None
    """
    pass


def dbg_is_loaded():
    """
    Checks if a debugger is loaded

    @return: Boolean
    """
    pass


def refresh_debugger_memory():
    """
    Refreshes the debugger memory

    @return: Nothing
    """
    pass


def py_list_bptgrps():
    """
    Returns list of breakpoint group names

    @return: A list of strings or None on failure
    """
    pass


def internal_get_sreg_base(tid: int, sreg_value: int):
    """
    Get the sreg base, for the given thread.

    @param tid: the thread ID
    @param sreg_value: the sreg value
    @return: The sreg base, or BADADDR on failure.
    """
    pass


def dbg_can_query():
    """
    This function can be used to check if the debugger can be queried:
      - debugger is loaded
      - process is suspended
      - process is not suspended but can take requests. In this case some requests like
        memory read/write, bpt management succeed and register querying will fail.
        Check if idaapi.get_process_state() < 0 to tell if the process is suspended

    @return: Boolean
    """
    pass


def get_reg_vals(tid: int, clsmask: int=-1) -> 'ida_idd.regvals_t':
    """
    Fetch live registers values for the thread

    @param tid The ID of the thread to read registers for
    @param clsmask An OR'ed mask of register classes to
           read values for (can be used to speed up the
           retrieval process)

    @return: a list of register values (empty if an error occurs)
    """
    pass


def get_reg_val(*args):
    """
    Get a register value.

    This function has the following signatures:

        1. get_reg_val(name: str) -> Union[int, float, bytes]
        2. get_reg_val(name: str, regval: regval_t) -> bool

    The first (and most user-friendly) form will return
    a value whose type is related to the register type.
    I.e., either an integer, a float or, in the case of large
    vector registers, a bytes sequence.

    @param name the register name
    @return the register value (1st form)
    """
    pass

def set_reg_val(*args) -> bool:
    """
    Set a register value by name

    This function has the following signatures:
        1. set_reg_val(name: str, value: Union[int, float, bytes]) -> bool
        1. set_reg_val(tid: int, regidx: int, value: Union[int, float, bytes]) -> bool

    Depending on the register type, this will expect
    either an integer, a float or, in the case of large
    vector registers, a bytes sequence.

    @param name (1st form) the register name
    @param tid (2nd form) the thread ID
    @param regidx (2nd form) the register index
    @param value the register value
    @return success
    """
    pass

def list_bptgrps() -> List[str]:
    """
    Retrieve the list of absolute path of all folders of bpt dirtree.
    Synchronous function, Notification, none (synchronous function)
    """
    pass
