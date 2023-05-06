"""
summary: dynamically provide a custom call type

description:
  This plugin can greatly improve decompilation of indirect calls:

      call    [eax+4]

  For them, the decompiler has to guess the prototype of the called function.
  This has to be done at a very early phase of decompilation because
  the function prototype influences the data flow analysis. On the other
  hand, we do not have global data flow analysis results yet because
  we haven't analyzed all calls in the function. It is a chicked-and-egg
  problem.

  The decompiler uses various techniques to guess the called function
  prototype. While it works very well, it may fail in some cases.

  To fix, the user can specify the call prototype manually, using
  "Edit, Operand types, Set operand type" at the call instruction.

  This plugin illustrates another approach to the problem:
  if you happen to be able to calculate the call prototypes dynamically,
  this is how to inform the decompiler about them.
"""

import ida_idaapi
import ida_nalt
import ida_kernwin
import ida_typeinf
import ida_hexrays

testing = False # only for testing purposes

class callinfo_provider_t(ida_hexrays.Hexrays_Hooks):

    # this callback will be called for all call instructions
    # our plugin may provide the function prototype or even a complete new callinfo
    # object. The callinfo object may be useful if the prototype is not enough
    # to express all details of the call.
    def build_callinfo(self, blk, type):
        # it is a good idea to skip direct calls.
        # note that some indirect calls may be resolved and become direct calls,
        # and will be filtered out here:
        ida_kernwin.msg("%x: got called for: %s\n" % (blk.tail.ea, blk.tail.dstr()))
        tail = blk.tail
        if tail.opcode == ida_hexrays.m_call:
            return

        # also, if the type was specified by the user, do not interfere
        call_ea = tail.ea
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_op_tinfo(tif, call_ea, 0):
            return

        global testing
        if not testing:
            # ok, the decompiler really has to guess the type.
            # just for the sake of an example, return a predefined prototype.
            # in real life you will provide the prototype you discovered yourself,
            # using your magic of yours :)
            my_proto = "int f();"
            ida_kernwin.msg("%x: providing prototype %s\n" % (call_ea, my_proto))
            ida_typeinf.parse_decl(type, None, my_proto, 0)
        else:
            # as an alternative to filling 'type', you can
            # choose to return a mcallinfo_t instance.
            mi = ida_hexrays.mcallinfo_t()
            mi.cc = ida_typeinf.CM_CC_STDCALL | ida_typeinf.CM_N32_F48 # let's use stdcall to differentiate from the tinfo_t-filling version
            mi.return_type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT)
            mi.return_argloc.set_reg1(0) # eax
            return mi

# a plugin interface, boilerplate code
class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Hex-Rays custom prototype provider (IDAPython)"
    wanted_hotkey = ""
    comment = "Sample plugin21 for Hex-Rays decompiler"
    help = ""
    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            self.hooks = callinfo_provider_t()
            self.hooks.hook()
            ida_kernwin.warning(
                "Installed callinfo provider sample (vds21.py)\n" +\
                "Please note that it is just an example\n" +\
                "and will spoil your decompilations!")
            return ida_idaapi.PLUGIN_KEEP # keep us in the memory
    def term(self):
        self.hooks.unhook()
    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return my_plugin_t()

