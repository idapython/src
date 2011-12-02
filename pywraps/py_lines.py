#<pycode(py_lines)>

# ---------------- Color escape sequence defitions -------------------------
COLOR_ADDR_SIZE = 16 if _idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL else 8
SCOLOR_FG_MAX   = '\x28'             #  Max color number
SCOLOR_OPND1    = chr(cvar.COLOR_ADDR+1)  #  Instruction operand 1
SCOLOR_OPND2    = chr(cvar.COLOR_ADDR+2)  #  Instruction operand 2
SCOLOR_OPND3    = chr(cvar.COLOR_ADDR+3)  #  Instruction operand 3
SCOLOR_OPND4    = chr(cvar.COLOR_ADDR+4)  #  Instruction operand 4
SCOLOR_OPND5    = chr(cvar.COLOR_ADDR+5)  #  Instruction operand 5
SCOLOR_OPND6    = chr(cvar.COLOR_ADDR+6)  #  Instruction operand 6
SCOLOR_UTF8     = chr(cvar.COLOR_ADDR+10) #  Following text is UTF-8 encoded

# ---------------- Line prefix colors --------------------------------------
PALETTE_SIZE   =  (cvar.COLOR_FG_MAX+_idaapi.COLOR_BG_MAX)

def requires_color_esc(c):
    """
    Checks if the given character requires escaping
    @param c: character (string of one char)
    @return: Boolean
    """
    t = ord(c[0])
    return c >= COLOR_ON and c <= COLOR_INV

def COLSTR(str, tag):
    """
    Utility function to create a colored line
    @param str: The string
    @param tag: Color tag constant. One of SCOLOR_XXXX
    """
    return SCOLOR_ON + tag + str + SCOLOR_OFF + tag

#</pycode(py_lines)>
