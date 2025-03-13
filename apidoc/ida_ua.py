
def decode_preceding_insn(out: insn_t, ea: ida_idaapi.ea_t) -> Tuple[ida_idaapi.ea_t, bool]:
    """
    Decodes the preceding instruction.

    @param out: instruction storage
    @param ea: current ea
    @return: tuple(preceeding_ea or BADADDR, farref = Boolean)
    """
    pass

def construct_macro(*args):
    """
    See ua.hpp's construct_macro().

    This function has the following signatures

        1. construct_macro(insn: insn_t, enable: bool, build_macro: callable) -> bool
        2. construct_macro(constuctor: macro_constructor_t, insn: insn_t, enable: bool) -> bool

    @param insn: the instruction to build the macro for
    @param enable: enable macro generation
    @param build_macro: a callable with 2 arguments: an insn_t, and
                        whether it is ok to consider the next instruction
                        for the macro
    @param constructor: a macro_constructor_t implementation
    @return: success
    """
    pass
