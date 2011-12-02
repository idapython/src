# ----------------------------------------------------------------------
#
# Misc constants
#
UA_MAXOP   = 6

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

# ----------------------------------------------------------------------
# op_t related constants

#
# op_t.type
#                  Description                          Data field
o_void     =  0 #  No Operand                           ----------
o_reg      =  1 #  General Register (al,ax,es,ds...)    reg
o_mem      =  2 #  Direct Memory Reference  (DATA)      addr
o_phrase   =  3 #  Memory Ref [Base Reg + Index Reg]    phrase
o_displ    =  4 #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
o_imm      =  5 #  Immediate Value                      value
o_far      =  6 #  Immediate Far Address  (CODE)        addr
o_near     =  7 #  Immediate Near Address (CODE)        addr
o_idpspec0 =  8 #  IDP specific type
o_idpspec1 =  9 #  IDP specific type
o_idpspec2 = 10 #  IDP specific type
o_idpspec3 = 11 #  IDP specific type
o_idpspec4 = 12 #  IDP specific type
o_idpspec5 = 13 #  IDP specific type
o_last     = 14 #  first unused type

#
# op_t.dtyp
#
dt_byte = 0 #  8 bit
dt_word = 1 #  16 bit
dt_dword = 2 #  32 bit
dt_float = 3 #  4 byte
dt_double = 4 #  8 byte
dt_tbyte = 5 #  variable size (ph.tbyte_size)
dt_packreal = 6 #  packed real format for mc68040
dt_qword = 7 #  64 bit
dt_byte16 = 8 #  128 bit
dt_code = 9 #  ptr to code (not used?)
dt_void = 10 #  none
dt_fword = 11 #  48 bit
dt_bitfild = 12 #  bit field (mc680x0)
dt_string = 13 #  pointer to asciiz string
dt_unicode = 14 #  pointer to unicode string
dt_3byte = 15 #  3-byte data
dt_ldbl = 16 #  long double (which may be different from tbyte)

#
# op_t.flags
#
OF_NO_BASE_DISP = 0x80 #  o_displ: base displacement doesn't exist meaningful only for o_displ type if set, base displacement (x.addr) doesn't exist.
OF_OUTER_DISP = 0x40 #  o_displ: outer displacement exists meaningful only for o_displ type if set, outer displacement (x.value) exists.
PACK_FORM_DEF = 0x20 #  !o_reg + dt_packreal: packed factor defined
OF_NUMBER = 0x10 # can be output as number only if set, the operand can be converted to a number only
OF_SHOW = 0x08 #  should the operand be displayed? if clear, the operand is hidden and should not be displayed

#
# insn_t.flags
#
INSN_MACRO  = 0x01   # macro instruction
INSN_MODMAC = 0x02   # macros: may modify the database to make room for the macro insn

# ----------------------------------------------------------------------
# asm_t related constants

#
# asm_t.flag
#
AS_OFFST       = 0x00000001         #  offsets are 'offset xxx' ?
AS_COLON       = 0x00000002         #  create colons after data names ?
AS_UDATA       = 0x00000004         #  can use '?' in data directives

AS_2CHRE       = 0x00000008         #  double char constants are: "xy
AS_NCHRE       = 0x00000010         #  char constants are: 'x
AS_N2CHR       = 0x00000020         #  can't have 2 byte char consts

                                    #      ASCII directives:
AS_1TEXT       = 0x00000040         #    1 text per line, no bytes
AS_NHIAS       = 0x00000080         #    no characters with high bit
AS_NCMAS       = 0x00000100         #    no commas in ascii directives

AS_HEXFM       = 0x00000E00         #  format of hex numbers:
ASH_HEXF0      = 0x00000000         #    34h
ASH_HEXF1      = 0x00000200         #    h'34
ASH_HEXF2      = 0x00000400         #    34
ASH_HEXF3      = 0x00000600         #    0x34
ASH_HEXF4      = 0x00000800         #    $34
ASH_HEXF5      = 0x00000A00         #    <^R   > (radix)
AS_DECFM       = 0x00003000         #  format of dec numbers:
ASD_DECF0      = 0x00000000         #    34
ASD_DECF1      = 0x00001000         #    #34
ASD_DECF2      = 0x00002000         #    34.
ASD_DECF3      = 0x00003000         #    .34
AS_OCTFM       = 0x0001C000         #  format of octal numbers:
ASO_OCTF0      = 0x00000000         #    123o
ASO_OCTF1      = 0x00004000         #    0123
ASO_OCTF2      = 0x00008000         #    123
ASO_OCTF3      = 0x0000C000         #    @123
ASO_OCTF4      = 0x00010000         #    o'123
ASO_OCTF5      = 0x00014000         #    123q
ASO_OCTF6      = 0x00018000         #    ~123
AS_BINFM       = 0x000E0000         #  format of binary numbers:
ASB_BINF0      = 0x00000000         #    010101b
ASB_BINF1      = 0x00020000         #    ^B010101
ASB_BINF2      = 0x00040000         #    %010101
ASB_BINF3      = 0x00060000         #    0b1010101
ASB_BINF4      = 0x00080000         #    b'1010101
ASB_BINF5      = 0x000A0000         #    b'1010101'

AS_UNEQU       = 0x00100000         #  replace undefined data items
                                    #     with EQU (for ANTA's A80)
AS_ONEDUP      = 0x00200000         #  One array definition per line
AS_NOXRF       = 0x00400000         #  Disable xrefs during the output file generation
AS_XTRNTYPE    = 0x00800000         #  Assembler understands type of extrn
                                    #     symbols as ":type" suffix
AS_RELSUP      = 0x01000000         #  Checkarg: 'and','or','xor' operations
                                    #     with addresses are possible
AS_LALIGN      = 0x02000000         #  Labels at "align" keyword
                                    #     are supported.
AS_NOCODECLN   = 0x04000000         #  don't create colons after code names
AS_NOTAB       = 0x08000000         #  Disable tabulation symbols during the output file generation
AS_NOSPACE     = 0x10000000         #  No spaces in expressions
AS_ALIGN2      = 0x20000000         #  .align directive expects an exponent rather than a power of 2
                                    #     (.align 5 means to align at 32byte boundary)
AS_ASCIIC      = 0x40000000         #  ascii directive accepts C-like
                                    #     escape sequences (\n,\x01 and similar)
AS_ASCIIZ      = 0x80000000         #  ascii directive inserts implicit
                                    #     zero byte at the end

# ----------------------------------------------------------------------
# processor_t related constants

IDP_INTERFACE_VERSION  = 76
CUSTOM_CMD_ITYPE       = 0x8000
REG_SPOIL              = 0x80000000

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
PR_USE_ARG_TYPES  = 0x200000 #  use ph.use_arg_types callback
PR_SCALE_STKVARS  = 0x400000 #  use ph.get_stkvar_scale callback
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
PR_DEFSEG64   = 0x10000000   #  segments are 64-bit by default

# ----------------------------------------------------------------------
OOF_SIGNMASK     = 0x0003      #  sign symbol (+/-) output:
OOFS_IFSIGN    = 0x0000        #    output sign if needed
OOFS_NOSIGN    = 0x0001        #    don't output sign, forbid the user to change the sign
OOFS_NEEDSIGN  = 0x0002        #    always out sign         (+-)
OOF_SIGNED       = 0x0004      #  output as signed if < 0
OOF_NUMBER       = 0x0008      #  always as a number
OOF_WIDTHMASK    = 0x0070      #  width of value in bits:
OOFW_IMM       = 0x0000        #    take from x.dtyp
OOFW_8         = 0x0010        #    8 bit width
OOFW_16        = 0x0020        #    16 bit width
OOFW_24        = 0x0030        #    24 bit width
OOFW_32        = 0x0040        #    32 bit width
OOFW_64        = 0x0050        #    32 bit width
OOF_ADDR         = 0x0080      #  output x.addr, otherwise x.value
OOF_OUTER        = 0x0100      #  output outer operand
OOF_ZSTROFF      = 0x0200      #  meaningful only if isStroff(uFlag)
                               #     append a struct field name if
                               #     the field offset is zero?
                               #     if AFL_ZSTROFF is set, then this flag
                               #     is ignored.
OOF_NOBNOT       = 0x0400      #  prohibit use of binary not
OOF_SPACES       = 0x0800      #  do not suppress leading spaces
                               #     currently works only for floating point numbers


# ----------------------------------------------------------------------
class insn_t(object):
    def __init__(self, noperands = UA_MAXOP):
        self.auxpref = 0
        self.cs = 0
        self.ea = 0
        self.flags = 0
        self.insnpref = 0
        self.ip = 0
        self.itype = 0
        self.n = 0
        self.segpref = 0
        self.size = 0
        self.Operands = []

        # store the number of operands
        self.n = noperands

        # create operands
        for i in xrange(0, noperands):
            op = op_t()
            op.n = i
            self.Operands.append(op)
            setattr(self, 'Op%d' % (i+1), op)
    def __getitem__(self, i):
        return self.Operands[i]

# ----------------------------------------------------------------------
class op_t(object):
    def __init__(self):
        self.addr = 0
        self.dtyp = 0
        self.flags = 0
        self.n = 0
        self.offb = 0
        self.offo = 0
        self.reg = 0
        self.specval = 0
        self.specflag1 = 0
        self.specflag2 = 0
        self.specflag3 = 0
        self.specflag4 = 0
        self.type = 0
        self.value = 0

    # make sure reg and phrase have the same value
    def __setattr__(self, name, value):
        if name == 'reg' or name == 'phrase':
           object.__setattr__(self, 'reg', value)
           object.__setattr__(self, 'phrase', value)
        else:
           object.__setattr__(self, name, value)
