
def create_switch_xrefs(ea, si):
    """
    This function creates xrefs from the indirect jump.

    Usually there is no need to call this function directly because the kernel
    will call it for switch tables

    Note: Custom switch information are not supported yet.

    @param ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass


def calc_switch_cases(ea, si):
    """
    Get information about a switch's cases.

    The returned information can be used as follows:

        for idx in range(len(results.cases)):
            cur_case = results.cases[idx]
            for cidx in range(len(cur_case)):
                print("case: %d" % cur_case[cidx])
            print("  goto 0x%x" % results.targets[idx])

    @param ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: a structure with 2 members: 'cases', and 'targets'.
    """
    pass

def create_switch_table(ea, si):
    """
    Create switch table from the switch information

    @param ea: address of the 'indirect jump' instruction
    @param si: switch information

    @return: Boolean
    """
    pass
