#<pycode(py_idp)>

#----------------------------------------------------------------------------
#               P R O C E S S O R  M O D U L E S  C O N S T A N T S
#----------------------------------------------------------------------------

# ----------------------------------------------------------------------
# processor_t related constants

CUSTOM_CMD_ITYPE    = 0x8000
REG_SPOIL           = 0x80000000

REAL_ERROR_FORMAT   = -1   #  not supported format for current .idp
REAL_ERROR_RANGE    = -2   #  number too big (small) for store (mem NOT modifyed)
REAL_ERROR_BADDATA  = -3   #  illegal real data for load (IEEE data not filled)

#
#  Check whether the operand is relative to stack pointer or frame pointer.
#  This function is used to determine how to output a stack variable
#  This function may be absent. If it is absent, then all operands
#  are sp based by default.
#  Define this function only if some stack references use frame pointer
#  instead of stack pointer.
#  returns flags:
OP_FP_BASED   = 0x00000000   #  operand is FP based
OP_SP_BASED   = 0x00000001   #  operand is SP based
OP_SP_ADD     = 0x00000000   #  operand value is added to the pointer
OP_SP_SUB     = 0x00000002   #  operand value is substracted from the pointer

# processor_t.id
PLFM_386        = 0       # Intel 80x86
PLFM_Z80        = 1       # 8085, Z80
PLFM_I860       = 2       # Intel 860
PLFM_8051       = 3       # 8051
PLFM_TMS        = 4       # Texas Instruments TMS320C5x
PLFM_6502       = 5       # 6502
PLFM_PDP        = 6       # PDP11
PLFM_68K        = 7       # Motoroal 680x0
PLFM_JAVA       = 8       # Java
PLFM_6800       = 9       # Motorola 68xx
PLFM_ST7        = 10      # SGS-Thomson ST7
PLFM_MC6812     = 11      # Motorola 68HC12
PLFM_MIPS       = 12      # MIPS
PLFM_ARM        = 13      # Advanced RISC Machines
PLFM_TMSC6      = 14      # Texas Instruments TMS320C6x
PLFM_PPC        = 15      # PowerPC
PLFM_80196      = 16      # Intel 80196
PLFM_Z8         = 17      # Z8
PLFM_SH         = 18      # Renesas (formerly Hitachi) SuperH
PLFM_NET        = 19      # Microsoft Visual Studio.Net
PLFM_AVR        = 20      # Atmel 8-bit RISC processor(s)
PLFM_H8         = 21      # Hitachi H8/300, H8/2000
PLFM_PIC        = 22      # Microchip's PIC
PLFM_SPARC      = 23      # SPARC
PLFM_ALPHA      = 24      # DEC Alpha
PLFM_HPPA       = 25      # Hewlett-Packard PA-RISC
PLFM_H8500      = 26      # Hitachi H8/500
PLFM_TRICORE    = 27      # Tasking Tricore
PLFM_DSP56K     = 28      # Motorola DSP5600x
PLFM_C166       = 29      # Siemens C166 family
PLFM_ST20       = 30      # SGS-Thomson ST20
PLFM_IA64       = 31      # Intel Itanium IA64
PLFM_I960       = 32      # Intel 960
PLFM_F2MC       = 33      # Fujistu F2MC-16
PLFM_TMS320C54  = 34      # Texas Instruments TMS320C54xx
PLFM_TMS320C55  = 35      # Texas Instruments TMS320C55xx
PLFM_TRIMEDIA   = 36      # Trimedia
PLFM_M32R       = 37      # Mitsubishi 32bit RISC
PLFM_NEC_78K0   = 38      # NEC 78K0
PLFM_NEC_78K0S  = 39      # NEC 78K0S
PLFM_M740       = 40      # Mitsubishi 8bit
PLFM_M7700      = 41      # Mitsubishi 16bit
PLFM_ST9        = 42      # ST9+
PLFM_FR         = 43      # Fujitsu FR Family
PLFM_MC6816     = 44      # Motorola 68HC16
PLFM_M7900      = 45      # Mitsubishi 7900
PLFM_TMS320C3   = 46      # Texas Instruments TMS320C3
PLFM_KR1878     = 47      # Angstrem KR1878
PLFM_AD218X     = 48      # Analog Devices ADSP 218X
PLFM_OAKDSP     = 49      # Atmel OAK DSP
PLFM_TLCS900    = 50      # Toshiba TLCS-900
PLFM_C39        = 51      # Rockwell C39
PLFM_CR16       = 52      # NSC CR16
PLFM_MN102L00   = 53      # Panasonic MN10200
PLFM_TMS320C1X  = 54      # Texas Instruments TMS320C1x
PLFM_NEC_V850X  = 55      # NEC V850 and V850ES/E1/E2
PLFM_SCR_ADPT   = 56      # Processor module adapter for processor modules written in scripting languages
PLFM_EBC        = 57      # EFI Bytecode
PLFM_MSP430     = 58      # Texas Instruments MSP430
PLFM_SPU        = 59      # Cell Broadband Engine Synergistic Processor Unit

#
# processor_t.flag
#
PR_SEGS        = 0x000001    #  has segment registers?
PR_USE32       = 0x000002    #  supports 32-bit addressing?
PR_DEFSEG32    = 0x000004    #  segments are 32-bit by default
PR_RNAMESOK    = 0x000008    #  allow to user register names for location names
PR_ADJSEGS     = 0x000020    #  IDA may adjust segments moving their starting/ending addresses.
PR_DEFNUM      = 0x0000C0    #  default number representation:
PRN_HEX        = 0x000000    #       hex
PRN_OCT        = 0x000040    #       octal
PRN_DEC        = 0x000080    #       decimal
PRN_BIN        = 0x0000C0    #       binary
PR_WORD_INS    = 0x000100    #  instruction codes are grouped 2bytes in binrary line prefix
PR_NOCHANGE    = 0x000200    #  The user can't change segments and code/data attributes (display only)
PR_ASSEMBLE    = 0x000400    #  Module has a built-in assembler and understands IDP_ASSEMBLE
PR_ALIGN       = 0x000800    #  All data items should be aligned properly
PR_TYPEINFO    = 0x001000    #  the processor module supports
                             #     type information callbacks
                             #     ALL OF THEM SHOULD BE IMPLEMENTED!
                             #     (the ones >= decorate_name)
PR_USE64       = 0x002000    #  supports 64-bit addressing?
PR_SGROTHER    = 0x004000    #  the segment registers don't contain
                             #     the segment selectors, something else
PR_STACK_UP    = 0x008000    #  the stack grows up
PR_BINMEM      = 0x010000    #  the processor module provides correct
                             #     segmentation for binary files
                             #     (i.e. it creates additional segments)
                             #     The kernel will not ask the user
                             #     to specify the RAM/ROM sizes
PR_SEGTRANS    = 0x020000    #  the processor module supports
                             #     the segment translation feature
                             #     (it means it calculates the code
                             #     addresses using the codeSeg() function)
PR_CHK_XREF    = 0x040000    #  don't allow near xrefs between segments
                             #     with different bases
PR_NO_SEGMOVE  = 0x080000    #  the processor module doesn't support move_segm()
                             #     (i.e. the user can't move segments)
PR_FULL_HIFXP  = 0x100000    #  REF_VHIGH operand value contains full operand
                             #     not only the high bits. Meaningful if ph.high_fixup_bits
PR_USE_ARG_TYPES = 0x200000  #  use ph.use_arg_types callback
PR_SCALE_STKVARS = 0x400000  #  use ph.get_stkvar_scale callback
PR_DELAYED     = 0x800000    #  has delayed jumps and calls
PR_ALIGN_INSN  = 0x1000000   #  allow ida to create alignment instructions
                             #     arbirtrarily. Since these instructions
                             #     might lead to other wrong instructions
                             #     and spoil the listing, IDA does not create
                             #     them by default anymore
PR_PURGING     = 0x2000000   #  there are calling conventions which may
                             #     purge bytes from the stack
PR_CNDINSNS    = 0x4000000   #  has conditional instructions
PR_USE_TBYTE   = 0x8000000   #  BTMT_SPECFLT means _TBYTE type
PR_DEFSEG64    = 0x10000000  #  segments are 64-bit by default


# ----------------------------------------------------------------------
# instruc_t related constants

#
# instruc_t.feature
#
CF_STOP = 0x00001 #  Instruction doesn't pass execution to the next instruction
CF_CALL = 0x00002 #  CALL instruction (should make a procedure here)
CF_CHG1 = 0x00004 #  The instruction modifies the first operand
CF_CHG2 = 0x00008 #  The instruction modifies the second operand
CF_CHG3 = 0x00010 #  The instruction modifies the third operand
CF_CHG4 = 0x00020 #  The instruction modifies 4 operand
CF_CHG5 = 0x00040 #  The instruction modifies 5 operand
CF_CHG6 = 0x00080 #  The instruction modifies 6 operand
CF_USE1 = 0x00100 #  The instruction uses value of the first operand
CF_USE2 = 0x00200 #  The instruction uses value of the second operand
CF_USE3 = 0x00400 #  The instruction uses value of the third operand
CF_USE4 = 0x00800 #  The instruction uses value of the 4 operand
CF_USE5 = 0x01000 #  The instruction uses value of the 5 operand
CF_USE6 = 0x02000 #  The instruction uses value of the 6 operand
CF_JUMP = 0x04000 #  The instruction passes execution using indirect jump or call (thus needs additional analysis)
CF_SHFT = 0x08000 #  Bit-shift instruction (shl,shr...)
CF_HLL  = 0x10000 #  Instruction may be present in a high level language function.

#
# Set IDP options constants
#
IDPOPT_STR        =  1    # string constant
IDPOPT_NUM        =  2    # number
IDPOPT_BIT        =  3    # bit, yes/no
IDPOPT_FLT        =  4    # float
IDPOPT_I64        =  5    # 64bit number

IDPOPT_OK         =  0    # ok
IDPOPT_BADKEY     =  1    # illegal keyword
IDPOPT_BADTYPE    =  2    # illegal type of value
IDPOPT_BADVALUE   =  3    # illegal value (bad range, for example)

# ----------------------------------------------------------------------
import ida_ua
class processor_t(ida_idaapi.pyidc_opaque_object_t):
    """Base class for all processor module scripts"""
    def __init__(self):
        # Take a reference to 'cmd'
        self.cmd = ida_ua.cmd

    def get_idpdesc(self):
        """
        This function must be present and should return the list of
        short processor names similar to the one in ph.psnames.
        This method can be overridden to return to the kernel a different IDP description.
        """
        return '\x01'.join(map(lambda t: '\x01'.join(t), zip(self.plnames, self.psnames)))

    def get_uFlag(self):
        """Use this utility function to retrieve the 'uFlag' global variable"""
        return ida_ua.cvar.uFlag

    def get_auxpref(self):
        """This function returns cmd.auxpref value"""
        return self.cmd.auxpref


# ----------------------------------------------------------------------
class __ph(object):
    id = property(lambda self: ph_get_id())
    cnbits = property(lambda self: ph_get_cnbits())
    dnbits = property(lambda self: ph_get_dnbits())
    flag = property(lambda self: ph_get_flag())
    high_fixup_bits = property(lambda self: ph_get_high_fixup_bits())
    icode_return = property(lambda self: ph_get_icode_return())
    instruc = property(lambda self: ph_get_instruc())
    instruc_end = property(lambda self: ph_get_instruc_end())
    instruc_start = property(lambda self: ph_get_instruc_start())
    regCodeSreg = property(lambda self: ph_get_regCodeSreg())
    regDataSreg = property(lambda self: ph_get_regDataSreg())
    regFirstSreg = property(lambda self: ph_get_regFirstSreg())
    regLastSreg = property(lambda self: ph_get_regLastSreg())
    regnames = property(lambda self: ph_get_regnames())
    segreg_size = property(lambda self: ph_get_segreg_size())
    tbyte_size = property(lambda self: ph_get_tbyte_size())
    version = property(lambda self: ph_get_version())

ph = __ph()

#</pycode(py_idp)>
