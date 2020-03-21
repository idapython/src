from __future__ import print_function
import idaapi
import idautils

"""
    This is a sample script for extending the assemble() hook.

    We add support for assembling the following pseudo instructions:
      - "zero eax" -> xor eax, eax
      - "nothing" -> nop


(c) Hex-Rays
"""

#--------------------------------------------------------------------------
class assemble_idp_hook_t(idaapi.IDP_Hooks):
    def ev_assemble(self, ea, cs, ip, use32, line):
        line = line.strip()
        if line == "zero eax":
            return b"\x33\xC0"
        elif line == "nothing":
            # Decode current instruction to figure out its size
            cmd = idautils.DecodeInstruction(ea)
            if cmd:
                # NOP all the instruction bytes
                return b"\x90" * cmd.size
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
