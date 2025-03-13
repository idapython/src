
def AssembleLine(ea, cs, ip, use32, line):
    """
    Assemble an instruction to a string (display a warning if an error is found)

    @param ea: linear address of instruction
    @param cs:  cs of instruction
    @param ip:  ip of instruction
    @param use32: is 32bit segment
    @param line: line to assemble
    @return:
        - None on failure
        - or a string containing the assembled instruction
    """
    pass


def assemble(ea, cs, ip, use32, line):
    """
    Assemble an instruction into the database (display a warning if an error is found)

    @param ea: linear address of instruction
    @param cs: cs of instruction
    @param ip: ip of instruction
    @param use32: is 32bit segment?
    @param line: line to assemble

    @return: Boolean. True on success.
    """

def ph_get_id():
    """
    Returns the 'ph.id' field
    """
    pass

def ph_get_version():
    """
    Returns the 'ph.version'
    """
    pass

def ph_get_flag():
    """
    Returns the 'ph.flag'
    """
    pass

def ph_get_cnbits():
    """
    Returns the 'ph.cnbits'
    """
    pass

def ph_get_dnbits():
    """
    Returns the 'ph.dnbits'
    """
    pass

def ph_get_reg_first_sreg():
    """
    Returns the 'ph.reg_first_sreg'
    """
    pass

def ph_get_reg_last_sreg():
    """
    Returns the 'ph.reg_last_sreg'
    """
    pass

def ph_get_segreg_size():
    """
    Returns the 'ph.segreg_size'
    """
    pass

def ph_get_reg_code_sreg():
    """
    Returns the 'ph.reg_code_sreg'
    """
    pass

def ph_get_reg_data_sreg():
    """
    Returns the 'ph.reg_data_sreg'
    """
    pass

def ph_get_icode_return():
    """
    Returns the 'ph.icode_return'
    """
    pass

def ph_get_instruc_start():
    """
    Returns the 'ph.instruc_start'
    """
    pass

def ph_get_instruc_end():
    """
    Returns the 'ph.instruc_end'
    """
    pass

def ph_get_tbyte_size():
    """
    Returns the 'ph.tbyte_size' field as defined in he processor module
    """
    pass

def ph_get_instruc():
    """
    Returns a list of tuples (instruction_name, instruction_feature) containing the
    instructions list as defined in he processor module
    """
    pass

def ph_get_regnames():
    """
    Returns the list of register names as defined in the processor module
    """
    pass

def ph_get_operand_info(ea: ida_idaapi.ea_t, n: int) -> Union[Tuple[int, ida_idaapi.ea_t, int, int, int], None]:
    """
    Returns the operand information given an ea and operand number.

    @param ea: address
    @param n: operand number

    @return: Returns an idd_opinfo_t as a tuple: (modified, ea, reg_ival, regidx, value_size).
             Please refer to idd_opinfo_t structure in the SDK.
    """
    pass
