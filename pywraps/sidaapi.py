import sys
import sidc

BUF = None

# ----------------------------------------------------------------------
def ua_next_byte():
    p = cmd.ea
    if p >= len(BUF):
        return None
    ch = ord(BUF[p])
    ua_seek(p+1)
    cmd.size += 1
    return ch

def ua_next_word():
    b1 = ua_next_byte()
    b2 = ua_next_byte()
    return (b2 << 8) | b1

def ua_next_long():
    w1 = ua_next_word()
    w2 = ua_next_word()
    return (w2 << 16) | w1

def ua_next_qword():
    d1 = ua_next_long()
    d2 = ua_next_long()
    return (d2 << 32) | d1

# ----------------------------------------------------------------------
def ua_set_data(data):
    global BUF
    BUF = data
    ua_seek(0)

# ----------------------------------------------------------------------
def ua_seek(v):
    cmd.ea = v

# ----------------------------------------------------------------------
def ua_get_seek():
    return cmd.ea

# ----------------------------------------------------------------------
def init_file(fn):
    global BUF, PTR
    try:
        f = open(fn, "rb")
        BUF = f.read()
        ua_seek(0)
        f.close()
    except Exception, e:
        print "init_file()", e
        return False
    return True

# ----------------------------------------------------------------------
class cvar_t:
    def __init__(self):
        self.uFlag = 0
        self.gl_comm = 1
# ----------------------------------------------------------------------
cvar = cvar_t()
cmd  = sidc.insn_t()

# ----------------------------------------------------------------------
class processor_t(object):
    def __init__(self):
        # This is an opaque object
        self.__idc_cvt_id__ = 2

        # Take a reference to 'cmd'
        self.cmd = cmd

    def get_idpdesc(self):
        """
        This function must be present and should return the list of
        short processor names similar to the one in ph.psnames
        """
        return idpdef['plnames'][0] + ':' + ':'.join(idpdef['psnames'])

    def get_uFlag(self):
        """Use this utility function to retrieve the 'uFlag' global variable"""
        return _idaapi.cvar.uFlag

    def get_auxpref(self):
        return self.cmd.auxpref

# ----------------------------------------------------------------------
BADADDR = 0xFFFFFFFFFFFFFFFFL

# ----------------------------------------------------------------------
UA_MAXOP = 6
o_last   = 14
o_void   =  0
# ----------------------------------------------------------------------

"""
# Colors dump

attrs = [x for x in dir(idaapi) if x.startswith('SCOLOR')]
for x in attrs:
  print "%s =%r;" % (x, getattr(idaapi, x))

attrs = [x for x in dir(idaapi) if x.startswith('COLOR')]
for x in attrs:
  v = getattr(idaapi, x);
  if isinstance(v, str):
    v = ord(x[0])
  print "%s =%r;" % (x, v)
"""

SCOLOR_ADDR ='(';
SCOLOR_ALTOP ='\x16';
SCOLOR_ASMDIR ='\x1b';
SCOLOR_AUTOCMT ='\x04';
SCOLOR_BINPREF ='\x14';
SCOLOR_CHAR ='\n';
SCOLOR_CNAME ='%';
SCOLOR_CODNAME ='\x1a';
SCOLOR_COLLAPSED ="'";
SCOLOR_CREF ='\x0e';
SCOLOR_CREFTAIL ='\x10';
SCOLOR_DATNAME ='\x06';
SCOLOR_DCHAR ='\x1e';
SCOLOR_DEFAULT ='\x01';
SCOLOR_DEMNAME ='\x08';
SCOLOR_DNAME ='\x07';
SCOLOR_DNUM ='\x1f';
SCOLOR_DREF ='\x0f';
SCOLOR_DREFTAIL ='\x11';
SCOLOR_DSTR ='\x1d';
SCOLOR_ERROR ='\x12';
SCOLOR_ESC ='\x03';
SCOLOR_EXTRA ='\x15';
SCOLOR_FG_MAX ='(';
SCOLOR_HIDNAME ='\x17';
SCOLOR_IMPNAME ='"';
SCOLOR_INSN ='\x05';
SCOLOR_INV ='\x04';
SCOLOR_KEYWORD =' ';
SCOLOR_LIBNAME ='\x18';
SCOLOR_LOCNAME ='\x19';
SCOLOR_MACRO ='\x1c';
SCOLOR_NUMBER ='\x0c';
SCOLOR_OFF ='\x02';
SCOLOR_ON ='\x01';
SCOLOR_OPND1 =')';
SCOLOR_OPND2 ='*';
SCOLOR_OPND3 ='+';
SCOLOR_OPND4 =',';
SCOLOR_OPND5 ='-';
SCOLOR_OPND6 ='.';
SCOLOR_PREFIX ='\x13';
SCOLOR_REG ='!';
SCOLOR_REGCMT ='\x02';
SCOLOR_RPTCMT ='\x03';
SCOLOR_SEGNAME ='#';
SCOLOR_STRING ='\x0b';
SCOLOR_SYMBOL ='\t';
SCOLOR_UNAME ='&';
SCOLOR_UNKNAME ='$';
SCOLOR_UTF8 ='2';
SCOLOR_VOIDOP ='\r';
COLOR_ADDR =40;
COLOR_ADDR_SIZE =8;
COLOR_ALTOP =22;
COLOR_ASMDIR =27;
COLOR_AUTOCMT =4;
COLOR_BG_MAX =12;
COLOR_BINPREF =20;
COLOR_CHAR =10;
COLOR_CNAME =37;
COLOR_CODE =5;
COLOR_CODNAME =26;
COLOR_COLLAPSED =39;
COLOR_CREF =14;
COLOR_CREFTAIL =16;
COLOR_CURITEM =9;
COLOR_CURLINE =10;
COLOR_DATA =6;
COLOR_DATNAME =6;
COLOR_DCHAR =30;
COLOR_DEFAULT =1;
COLOR_DEMNAME =8;
COLOR_DNAME =7;
COLOR_DNUM =31;
COLOR_DREF =15;
COLOR_DREFTAIL =17;
COLOR_DSTR =29;
COLOR_ERROR =18;
COLOR_ESC =3;
COLOR_EXTERN =8;
COLOR_EXTRA =21;
COLOR_FG_MAX =40;
COLOR_HIDLINE =11;
COLOR_HIDNAME =23;
COLOR_IMPNAME =34;
COLOR_INSN =5;
COLOR_INV =4;
COLOR_KEYWORD =32;
COLOR_LIBFUNC =3;
COLOR_LIBNAME =24;
COLOR_LOCNAME =25;
COLOR_MACRO =28;
COLOR_NUMBER =12;
COLOR_OFF = 2;
COLOR_ON = 1;
COLOR_OPND1 =41;
COLOR_OPND2 =42;
COLOR_OPND3 =43;
COLOR_OPND4 =44;
COLOR_OPND5 =45;
COLOR_OPND6 =46;
COLOR_PREFIX =19;
COLOR_REG =33;
COLOR_REGCMT =2;
COLOR_REGFUNC =4;
COLOR_RPTCMT =3;
COLOR_SEGNAME =35;
COLOR_SELECTED =2;
COLOR_STRING =11;
COLOR_SYMBOL =9;
COLOR_UNAME =38;
COLOR_UNKNAME =36;
COLOR_UNKNOWN =7;
COLOR_UTF8 =50;
COLOR_VOIDOP =13;