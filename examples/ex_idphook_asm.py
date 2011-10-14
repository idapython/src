import idaapi
import idautils

"""
    This is a sample plugin for extending the assemble().

    We add support for assembling the following pseudo instructions:
      - "zero eax" -> xor eax, eax
      - "nothing" -> nop


(c) Hex-Rays
"""

#--------------------------------------------------------------------------
class assemble_idp_hook_t(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def assemble(self, ea, cs, ip, use32, line):
        line = line.strip()
        if line == "xor eax, eax":
            return "\x33\xC0"
        elif line == "nop":
            # Decode current instruction to figure out its size
            cmd = idautils.DecodeInstruction(ea)
            if cmd:
                # NOP all the instruction bytes
                return "\x90" * cmd.size
        return None


#---------------------------------------------------------------------
# Remove an existing hook on second run
try:
    idp_hook_stat = "un"
    print("IDP hook: checking for hook...")
    idphook
    print("IDP hook: unhooking....")
    idphook.unhook()
    del idphook
except:
    print("IDP hook: not installed, installing now....")
    idp_hook_stat = ""
    idphook = assemble_idp_hook_t()
    idphook.hook()

print("IDP hook %sinstalled. Run the script again to %sinstall" % (idp_hook_stat, idp_hook_stat))
