
def generate_disassembly(ea, max_lines, as_stack, notags):
    """
    Generate disassembly lines (many lines) and put them into a buffer

    @param ea: address to generate disassembly for
    @param max_lines: how many lines max to generate
    @param as_stack: Display undefined items as 2/4/8 bytes
    @return:
        - None on failure
        - tuple(most_important_line_number, list(lines)) : Returns a tuple containing
          the most important line number and a list of generated lines
    """
    pass

