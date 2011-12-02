try:
    import pywraps
    pywraps_there = True
except:
    pywraps_there = False
import _idaapi
import random
import operator
import datetime

if pywraps_there:
    _idaapi.appcall = pywraps.appcall
    from py_idaapi import *
else:
    import idaapi
    from idaapi import *

# ----------------------------------------------------------------------------------------------------------------------------------------------
#<pycode(py_idd)>
import types

# -----------------------------------------------------------------------
class Appcall_array__(object):
    """This class is used with Appcall.array() method"""
    def __init__(self, tp):
        self.__type = tp

    def pack(self, L):
        """Packs a list or tuple into a byref buffer"""
        t = type(L)
        if not (t == types.ListType or t == types.TupleType):
            raise ValueError, "Either a list or a tuple must be passed"
        self.__size = len(L)
        if self.__size == 1:
            self.__typedobj = Appcall__.typedobj(self.__type + ";")
        else:
            self.__typedobj = Appcall__.typedobj("%s x[%d];" % (self.__type, self.__size))
        # Now store the object in a string buffer
        ok, buf = self.__typedobj.store(L)
        if ok:
            return Appcall__.byref(buf)
        else:
            return None

    def try_to_convert_to_list(self, obj):
        """Is this object a list? We check for the existance of attribute zero and attribute self.size-1"""
        if not (hasattr(obj, "0") and hasattr(obj, str(self.__size-1))):
            return obj
        # at this point, we are sure we have an "idc list"
        # let us convert to a Python list
        return [getattr(obj, str(x)) for x in xrange(0, self.__size)]

    def unpack(self, buf, as_list=True):
        """Unpacks an array back into a list or an object"""
        # take the value from the special ref object
        if isinstance(buf, PyIdc_cvt_refclass__):
            buf = buf.value

        # we can only unpack from strings
        if type(buf) != types.StringType:
            raise ValueError, "Cannot unpack this type!"
        # now unpack
        ok, obj = self.__typedobj.retrieve(buf)
        if not ok:
            raise ValueError, "Failed while unpacking!"
        if not as_list:
            return obj
        return self.try_to_convert_to_list(obj)


# -----------------------------------------------------------------------
# Wrapper class for the appcall()
class Appcall_callable__(object):
    """
    Helper class to issue appcalls using a natural syntax:
      appcall.FunctionNameInTheDatabase(arguments, ....)
    or
      appcall["Function@8"](arguments, ...)
    or
      f8 = appcall["Function@8"]
      f8(arg1, arg2, ...)
    or
      o = appcall.obj()
      i = byref(5)
      appcall.funcname(arg1, i, "hello", o)
    """
    def __init__(self, ea, tp = None, fld = None):
        """Initializes an appcall with a given function ea"""
        self.__ea     = ea
        self.__type   = tp
        self.__fields = fld
        self.__options = None # Appcall options
        self.__timeout = None # Appcall timeout

    def __get_timeout(self):
        return self.__timeout

    def __set_timeout(self, v):
        self.__timeout = v

    timeout = property(__get_timeout, __set_timeout)
    """An Appcall instance can change its timeout value with this attribute"""

    def __get_options(self):
        return self.__options if self.__options != None else Appcall__.get_appcall_options()

    def __set_options(self, v):
        if self.timeout:
            # If timeout value is set, then put the timeout flag and encode the timeout value
            v |= Appcall__.APPCALL_TIMEOUT | (self.timeout << 16)
        else:
            # Timeout is not set, then clear the timeout flag
            v &= ~Appcall__.APPCALL_TIMEOUT

        self.__options = v

    options = property(__get_options, __set_options)
    """Sets the Appcall options locally to this Appcall instance"""

    def __call__(self, *args):
        """Make object callable. We redirect execution to idaapi.appcall()"""
        if self.ea is None:
            raise ValueError, "Object not callable!"

        # convert arguments to a list
        arg_list = list(args)

        # Save appcall options and set new global options
        old_opt = Appcall__.get_appcall_options()
        Appcall__.set_appcall_options(self.options)

        # Do the Appcall (use the wrapped version)
        e_obj = None
        try:
            r = _idaapi.appcall(
               self.ea,
               _idaapi.get_current_thread(),
               self.type,
               self.fields,
               arg_list)
        except Exception as e:
            e_obj = e

        # Restore appcall options
        Appcall__.set_appcall_options(old_opt)

        # Return or re-raise exception
        if e_obj:
            raise Exception, e_obj

        return r

    def __get_ea(self):
        return self.__ea

    def __set_ea(self, val):
        self.__ea = val

    ea = property(__get_ea, __set_ea)
    """Returns or sets the EA associated with this object"""

    def __get_size(self):
        if self.__type == None:
            return -1
        r = _idaapi.get_type_size0(_idaapi.cvar.idati, self.__type)
        if not r:
            return -1
        return r

    size = property(__get_size)
    """Returns the size of the type"""

    def __get_type(self):
        return self.__type

    type = property(__get_type)
    """Returns the typestring"""

    def __get_fields(self):
        return self.__fields

    fields = property(__get_fields)
    """Returns the field names"""


    def retrieve(self, src=None, flags=0):
        """
        Unpacks a typed object from the database if an ea is given or from a string if a string was passed
        @param src: the address of the object or a string
        @return: Returns a tuple of boolean and object or error number (Bool, Error | Object).
        """

        # Nothing passed? Take the address and unpack from the database
        if src is None:
            src = self.ea

        if type(src) == types.StringType:
            return _idaapi.unpack_object_from_bv(_idaapi.cvar.idati, self.type, self.fields, src, flags)
        else:
            return _idaapi.unpack_object_from_idb(_idaapi.cvar.idati, self.type, self.fields, src, flags)

    def store(self, obj, dest_ea=None, base_ea=0, flags=0):
        """
        Packs an object into a given ea if provided or into a string if no address was passed.
        @param obj: The object to pack
        @param dest_ea: If packing to idb this will be the store location
        @param base_ea: If packing to a buffer, this will be the base that will be used to relocate the pointers

        @return:
            - If packing to a string then a Tuple(Boolean, packed_string or error code)
            - If packing to the database then a return code is returned (0 is success)
        """

        # no ea passed? thus pack to a string
        if dest_ea is None:
            return _idaapi.pack_object_to_bv(obj,
                                             _idaapi.cvar.idati,
                                             self.type,
                                             self.fields,
                                             base_ea,
                                             flags)
        else:
            return _idaapi.pack_object_to_idb(obj,
                                              _idaapi.cvar.idati,
                                              self.type,
                                              self.fields,
                                              dest_ea,
                                              flags)

# -----------------------------------------------------------------------
class Appcall_consts__(object):
    """Helper class used by Appcall.Consts attribute
    It is used to retrieve constants via attribute access"""
    def __init__(self, default=0):
        self.__default = default

    def __getattr__(self, attr):
        return Appcall__.valueof(attr, self.__default)

# -----------------------------------------------------------------------
class Appcall__(object):
    APPCALL_MANUAL = 0x1
    """
    Only set up the appcall, do not run it.
    you should call CleanupAppcall() when finished
    """

    APPCALL_DEBEV  = 0x2
    """
    Return debug event information
    If this bit is set, exceptions during appcall
    will generate idc exceptions with full
    information about the exception
    """

    APPCALL_TIMEOUT = 0x4
    """
    Appcall with timeout
    The timeout value in milliseconds is specified
    in the high 2 bytes of the 'options' argument:
    If timed out, errbuf will contain "timeout".
    """

    def __init__(self):
        self.__consts = Appcall_consts__()
    def __get_consts(self):
        return self.__consts
    Consts = property(__get_consts)
    """Use Appcall.Consts.CONST_NAME to access constants"""

    @staticmethod
    def __name_or_ea(name_or_ea):
        """
        Function that accepts a name or an ea and checks if the address is enabled.
        If a name is passed then idaapi.get_name_ea() is applied to retrieve the name
        @return:
            - Returns the resolved EA or
            - Raises an exception if the address is not enabled
        """

        # a string? try to resolve it
        if type(name_or_ea) == types.StringType:
            ea = _idaapi.get_name_ea(_idaapi.BADADDR, name_or_ea)
        else:
            ea = name_or_ea
        # could not resolve name or invalid address?
        if ea == _idaapi.BADADDR or not _idaapi.isEnabled(ea):
            raise ValueError, "Undefined function " + name_or_ea
        return ea

    @staticmethod
    def proto(name_or_ea, prototype, flags = None):
        """
        Allows you to instantiate an appcall (callable object) with the desired prototype
        @param name_or_ea: The name of the function (will be resolved with LocByName())
        @param prototype:
        @return:
            - On failure it raises an exception if the prototype could not be parsed
              or the address is not resolvable
            - Returns a callbable Appcall instance with the given prototypes and flags
        """

        # resolve and raise exception on error
        ea = Appcall__.__name_or_ea(name_or_ea)
        # parse the type
        if flags is None:
            flags = 1 | 2 | 4 # PT_SIL | PT_NDC | PT_TYP

        result = _idaapi.idc_parse_decl(_idaapi.cvar.idati, prototype, flags)
        if result is None:
            raise ValueError, "Could not parse type: " + prototype

        # Return the callable method with type info
        return Appcall_callable__(ea, result[1], result[2])

    def __getattr__(self, name_or_ea):
        """Allows you to call functions as if they were member functions (by returning a callable object)"""
        # resolve and raise exception on error
        ea = self.__name_or_ea(name_or_ea)
        if ea == _idaapi.BADADDR:
            raise ValueError, "Undefined function " + name
        # Return the callable method
        return Appcall_callable__(ea)

    def __getitem__(self, idx):
        """
        Use self[func_name] syntax if the function name contains invalid characters for an attribute name
        See __getattr___
        """
        return self.__getattr__(idx)

    @staticmethod
    def valueof(name, default=0):
        """
        Returns the numeric value of a given name string.
        If the name could not be resolved then the default value will be returned
        """
        t, v = _idaapi.get_name_value(_idaapi.BADADDR, name)
        if t == 0: # NT_NONE
          v = default
        return v

    @staticmethod
    def int64(v):
        """Whenever a 64bit number is needed use this method to construct an object"""
        return PyIdc_cvt_int64__(v)

    @staticmethod
    def byref(val):
        """
        Method to create references to immutable objects
        Currently we support references to int/strings
        Objects need not be passed by reference (this will be done automatically)
        """
        return PyIdc_cvt_refclass__(val)

    @staticmethod
    def buffer(str = None, size = 0, fill="\x00"):
        """
        Creates a string buffer. The returned value (r) will be a byref object.
        Use r.value to get the contents and r.size to get the buffer's size
        """
        if str is None:
            str = ""
        left = size - len(str)
        if left > 0:
            str = str + (fill * left)
        r = Appcall__.byref(str)
        r.size = size
        return r

    @staticmethod
    def obj(**kwds):
        """Returns an empty object or objects with attributes as passed via its keywords arguments"""
        return object_t(**kwds)

    @staticmethod
    def cstr(val):
        return as_cstr(val)

    @staticmethod
    def unicode(s):
        return as_unicode(s)

    @staticmethod
    def array(type_name):
        """Defines an array type. Later you need to pack() / unpack()"""
        return Appcall_array__(type_name)

    @staticmethod
    def typedobj(typestr, ea=None):
        """
        Parses a type string and returns an appcall object.
        One can then use retrieve() member method
        @param ea: Optional parameter that later can be used to retrieve the type
        @return: Appcall object or raises ValueError exception
        """
        # parse the type
        result = _idaapi.idc_parse_decl(_idaapi.cvar.idati, typestr, 1 | 2 | 4) # PT_SIL | PT_NDC | PT_TYP
        if result is None:
            raise ValueError, "Could not parse type: " + typestr
        # Return the callable method with type info
        return Appcall_callable__(ea, result[1], result[2])

    @staticmethod
    def set_appcall_options(opt):
        """Method to change the Appcall options globally (not per Appcall)"""
        old_opt = Appcall__.get_appcall_options()
        _idaapi.cvar.inf.appcall_options = opt
        return old_opt

    @staticmethod
    def get_appcall_options():
        """Return the global Appcall options"""
        return _idaapi.cvar.inf.appcall_options

    @staticmethod
    def cleanup_appcall(tid = 0):
        """Equivalent to IDC's CleanupAppcall()"""
        return _idaapi.cleanup_appcall(tid)

Appcall = Appcall__()
#</pycode(py_idd)>

# ----------------------------------------------------------------------------------------------------------------------------------------------

#<pycode(appcalltest)>
a = Appcall # Take a shortcut to Appcall
c = Appcall.Consts # take shortcut to constants

# -----------------------------------------------------------------------
# - Adds missing types
# - ...
def init():
    # add neeeded types
    if a.valueof("ERROR_FILE_NOT_FOUND") == 0:
        add_type("MACRO_ERROR")

    setattr(c, "ERROR_FILE_NOT_FOUND", 2)

    if a.valueof("MEM_COMMIT") == 0:
        add_type("MACRO_PAGE")

    # open log file
    global test_log
    try:
        test_log = file("python_test.log", "a")
    except:
        test_log = None

# -----------------------------------------------------------------------
def deinit():
    global test_log
    test_log.close()
    test_log = None
    return 1

# -----------------------------------------------------------------------
def logprint(s):
    if not test_log:
        print s
    else:
        test_log.write(s + "\n")
    return 1

# -----------------------------------------------------------------------
def add_type(t):
        print "adding type:", t
        idaapi.import_type(idaapi.cvar.idati, 0, t)

# -----------------------------------------------------------------------
def test_init():
    hmod = getmodulehandlew(a.unicode("kernel32.dll"))
    print "k32hmod=%x" % hmod
    if hmod == 0:
        return -1
    p = getprocaddr(hmod, "VirtualAlloc")
    if p == 0:
        return -2
    print "VirtualAlloc->%x" % p
    virtualalloc.ea = p

    p = getprocaddr(hmod, "VirtualFree")
    if p == 0:
        return -3
    print "VirtualFree->%x" % p
    virtualfree.ea = p

    m = virtualalloc(0, c.MEM_COMMIT, 0x1000, c.PAGE_EXECUTE_READWRITE)
    idc.RefreshDebuggerMemory()
    print "%x: allocated memory\n" % m
    global WRITE_AREA
    WRITE_AREA = m

    return 1

# -----------------------------------------------------------------------
def test_deinit():
    virtualfree(WRITE_AREA, 0, c.MEM_FREE)

# -----------------------------------------------------------------------
# Tests changedir/setdir/buffer creation (two methods) and cstr()
def test_enum_files():
    # create a buffer
    savedpath = a.byref("\x00" * 260)
    # get current directory
    n = getcurdir(250, savedpath)
    out = []
    out.append("curdir=%s" % savedpath.value[0:n])

    # get windir
    windir = a.buffer(size=260) # create a buffer using helper function
    n = getwindir(windir, windir.size)
    if n == 0:
        return -1 # could not get current directory

    windir = windir.value[:n]
    out.append("windir=%s" % windir)

    # change to windows folder
    setcurdir(windir)

    # initiate find
    fd = a.obj()
    h = findfirst("*.exe", fd)
    if h == -1:
        return -2 # no files found!

    found = -6
    while True:
        fn = a.cstr(fd.cFileName)
        if "regedit" in fn:
            found = 1
        out.append("fn=%s<" % fn)
        fd = a.obj() # reset the FD object
        ok = findnext(h, fd)
        if not ok:
            break
    #
    findclose(h)

    # restore cur dir
    setcurdir(savedpath.value)

    # verify
    t = a.buffer(size=260)
    n = getcurdir(t.size, t)
    if t.cstr() != savedpath.cstr():
        return -4 # could not restore cur dir

    out.append("curdir=%s<" % t.cstr())
#    print "all done!"
#    for l in out:
#        print l

    return found
# -----------------------------------------------------------------------
def test_gpa():
    h = loadlib("user32.dll")
    if h == 0:
        print "failed to load library!"
        return -1
    p = getprocaddr(h, "FindWindowA")
    if p == 0:
        print "failed to gpa!"
        return -2
    findwin = a.proto(p, "int FindWindow(LPCTSTR lpClassName, LPCTSTR lpWindowName);")
    hwnd = findwin("TIdaWindow", 0)
    freelib(h)
    print "%x: ok!->hwnd=%x" % (p, hwnd)

    return 1

# -----------------------------------------------------------------------
# Packs a simple structure (into the database) and unpacks it back using the idaapi methods
def test_pck_idb_raw():
    name, tp, flds = idc.ParseType("struct { int a, b; char x[5];};", 0)
    o = a.obj(a=15, b=17,x="hi")
    idaapi.pack_object_to_idb(o, idaapi.cvar.idati, tp, flds, WRITE_AREA, 0)

    ok, obj = idaapi.unpack_object_from_idb(idaapi.cvar.idati, tp, flds, WRITE_AREA, 0)
    if obj.a != 15 and obj.b != 17 and obj != "hi":
        return -2
    return 1

# -----------------------------------------------------------------------
# Packs a simple structure (into a string) and unpacks it back using the idaapi methods
def test_pck_bv_raw():
    name, tp, flds = idc.ParseType("struct { int a; char x[5]; int b;};", 0)
    va,vb,vx = 15,17,"hi"
    o = a.obj(a=va, b=vb,x=vx)
    ok, s = idaapi.pack_object_to_bv(o, idaapi.cvar.idati, tp, flds, WRITE_AREA, 0)
    if not ok:
        return -1
    ok, obj = idaapi.unpack_object_from_idb(idaapi.cvar.idati, tp, flds, WRITE_AREA, 0)
    if obj.a != va and obj.b != vb and obj.x != vx:
        return -2
    return 1

# -----------------------------------------------------------------------
# 1. Unpacks the DOS header at 0x400000 and verify the fields
# 2. Unpacks a string and see if it is unpacked correctly
def test_unpack_raw():
    name, tp, flds = idc.ParseType("IMAGE_DOS_HEADER;", 0)
    ok, obj = idaapi.unpack_object_from_idb(idaapi.cvar.idati, tp, flds, 0x400000, 0)
    if obj.e_magic != 23117 and obj.e_cblp != 144:
        return -1

    name, tp, flds = idc.ParseType("struct abc_t { int a, b;};", 0)
    ok, obj = idaapi.unpack_object_from_bv(idaapi.cvar.idati, tp, flds, "\x01\x00\x00\x00\x02\x00\x00\x00", 0)
    if obj.a != 1 and obj.b != 2:
        return -2

    return 1

# -----------------------------------------------------------------------
# Packs/Unpacks a structure to the database using appcall facilities
def test_pck_idb():
    print "%x: ..." % WRITE_AREA
    tp = a.typedobj("struct { int a, b; char x[5];};")
    o = a.obj(a=16, b=17,x="zzzhi")
    if tp.store(o, WRITE_AREA) != 0:
        return -1
    idc.RefreshDebuggerMemory()

    ok, r = tp.retrieve(WRITE_AREA)
    if not ok:
        return -2
    if r.a != o.a and r.b != o.b and r.x != o.x:
        return -3

    return 1

# -----------------------------------------------------------------------
# Packs/Unpacks a structure to/from a string
def test_pck_bv():
    tp = a.typedobj("struct { int a, b; char x[5];};")
    o = a.obj(a=16, b=17,x="zzzhi")
    ok, packed = tp.store(o)
    if not ok:
        return -1
    print "packed->", repr(packed)
    ok, r = tp.retrieve(packed)
    if not ok:
        return -2

    if r.a != o.a and r.b != o.b and r.x != o.x:
        return -3

    return 1

# -----------------------------------------------------------------------
# various tests
def test1(stage):
    # call a method that takes a string buffer and appends a dot to its end
    if stage == st_ref2:
        buf = a.buffer("test", 100)
        vals = [378, 424, 470]
        for i in xrange(0, 2+1):
            n = a._ref2(buf)
            if buf.value[4+i] != '.':
                return -st_ref2
            if vals[i] != n:
                return -stage
    # call a method that takes an integer reference
    elif stage == st_ref1:
        v = 5
        i = a.byref(v)
        a._ref1(i)
        if v + 1 != i.value:
            return -stage
    # call a method that takes an array of integers
    elif stage == st_ref3:
        # create an array type
        arr = a.array("int")
        # create a list
        L = [x for x in xrange(1, 10)]
        # pack the list
        p_list = arr.pack(L)
        # appcall to compute the total
        c_total = a._ref3(p_list, len(L))
        # internally compute the total
        total = reduce(operator.add, L)
        if total != c_total:
            return -stage
    # subst()
    elif stage == st_subst:
        v = a._subst(5, 1)
        if v != 4:
            return -stage
        v = subst(5, 1) # subst() / pascal
        if v != -4:
            return -stage*2
    elif stage == st_make2:
        x = a._str2_make(5)
        s = a.cstr(x.next.str)
#        print "len=%d;<%s>" % (len(s), s)
        if s != "This is string 2":
            return -stage
        n = a._str2_print(x)
        if n != 5:
            return -st_make2*2
    elif stage == st_make1:
        x = a._str1_make(6)
        if x.val != 1 and x.next.val != 2:
            return -st_make1
        n = a._str1_print(x)
        if n != 6:
            return -stage
    # 64bit test
    elif stage == st_make3:
        global gr
        try:
            x = a._str3_make(6)
            gr = x
        except Exception as e:
            print "Exception: ", str(e)
            return -stage
        print "x.val32=", x.val32
        if (x.val32 != 1) and (x.val64 != (1 << 32)):
            return -stage * 2
        va = 0
        vb = 0
        r = x
        i = 0
        while x != 0:
            i += 1
            print "1"
            va += x.val32
            print "2"
            vb += x.val64.value
            print "3"
            x = x.next
            print "i=", i, "a=", va, "b=", vb
        if va != 21 and vb != 90194313216:
            return -stage*3
    elif stage == st_asm:
        n = asm1(5, 1)
        if n != 4:
            return -stage
        n = asm2(5, 1, 1)
        if n != 7:
            return -stage*2
    elif stage == st_byvalref1:
        v1 = a.obj(val=5, next=0)
        v2 = a.obj(str="Hello", next=0)
        n = a._byvalref1(v1, 1, v2)
        if n != 78:
            return -stage
        # v1 is passed by ref, thus it will be changed
        if n + 1 != v1.val:
            return -stage * 2
    elif stage == st_altsum:
        # 1 + 2 - 3 + 5 = 5
        n = altsum(1, 2, 3, 5, 0)
        if n != 5:
          return -stage;
    elif stage == st_op64:
        # invalid opcode, should return -1
        r = a._op_two64(1, 2, 6).value
        print "r=", r
        if r != -1:
            return -stage
        r = a._op_two64(6, a.int64(2), 3).value
        if r != 12:
            return -stage * 2
        return 1
    elif stage == st_byval3:
        o = a.obj(val=6,next=a.obj(val=-1, next=0))
#        print "before: o.val=%d o.next.val=%d" % (o.val, o.next.val)
        n = a._byval3(o)
        if n != 5:
            return -stage
#        print "after: o.val=%d o.next.val=%d, n=%d" % (o.val, o.next.val, n)
    #---------
    elif stage == st_ex:
        def doit():
            try:
                # causes a DebugBreak()
                a._ex2(1)
            except Exception as e:
                if not "Software breakpoint" in e.message:
                    return -stage
            try:
                a._ex1(1, 2)
                return -st_ex * 2
            except Exception as e:
                if not "referenced memory" in e.message:
                    return -stage
            return 1
        old = a.set_appcall_options(0)
        r = doit()
        a.set_appcall_options(old)
        if r <= 0:
            return r
    #---------
    elif stage == st_ref4:
        i = a.int64(5)
        v = a.byref(i)
        if a._ref4(v) != 1:
            return -st_ref4
        # test (in case recycling failed)
        if v.value.value != 6:
            return -st_ref4 * 2
        # test recycling
        if i.value != 6:
            return -st_ref4 * 3
    # return success
    return 1

# -----------------------------------------------------------------------
def test2():
    fn = "pc_win32_appcall.pe"

    # Try to open an non-existing file
    h = a._file_open(fn + ".1")
    if h != 0:
        return -1

    n = getlasterror()
    print "gle=", n
    if n != c.ERROR_FILE_NOT_FOUND:
        return -2

    # Should succeed
    h = a._file_open(fn)
    if h == 0:
        return -3

    s = a.buffer("", 10, "!")
    n = a._file_read(h, s, 2)
#    print "read=%d; buf=%s" % (n, repr(s.value))
    if s.value[:2] != "MZ":
        return -4

    n = a._file_close(h)
    if n != h-1:
        return -5

    return 1

# -----------------------------------------------------------------------
# This test changes the appcall options and sees if the appcall
# generates an exception and if we get it properly
# An appcall can throw an exception:
# - ValueError: conversion from/to idc/py failed
# - OSError: an OSError when APPCALL_DEBEV in Appcall_Options. In that case check the exc.args[0] to get the debug event
# - Exception: in all other cases
def test_exec_throw():
    old = a.set_appcall_options(0)
    print "old_opt=", old, "new=0"
    try:
        # causes a divide by zero exception (will be reported as an Exception)
        print a._op_two64(2,0,4).value
        return -1
    except Exception as e:
        print "runtime error!"

    # now appcall exceptions will be reported as OSErr and other exceptions as Exception
    print "old_opt=", a.set_appcall_options(a.APPCALL_DEBEV), "new=2"
    try:
        # causes an error: Wrong number of arguments
        print a._op_two64(2).value
        return -2
    except OSError, e:
        return -3
    except Exception as e:
        print "Got other exception:", e # good

    try:
        # causes an OS error and "e" will contain the last debug_event
        # in our case exception, and the code is int_divide_zero = 0xC0000094
        print a._op_two64(2, 0, 4).value
        return -4
    except OSError, e:
        if idaapi.as_uint32(e.args[0].code) != 0xC0000094:
            return -5
    except Exception as e:
        print "Got other exception:", e
        return -6
    a.set_appcall_options(old)
    return 1
# -----------------------------------------------------------------------
# all the tests that take zero parameters
tests0 = (test_gpa, test_pck_idb_raw, test_pck_bv_raw,
          test_unpack_raw, test_pck_idb, test_pck_bv,
          test_enum_files, test2, test_exec_throw)
test_log = None # test log file

# -----------------------------------------------------------------------
def test_all():
    if test_init() <= 0:
        print "test_init() failed!"
        return -1

    # tests 0
    for t in tests0:
        print "testing->", t
        r = t()
        if r <= 0:
            return r
    # test 1
    for i in xrange(1, st_last):
        print "test1 #", i
        r = test1(i)
        if r <= 0:
            return r

    logprint(datetime.date.today().strftime("Python was here: %Y-%m-%d @ %I:%M:%S%p"))

    test_deinit()

    return 1

# -----------------------------------------------------------------------
init()

# reference to an integer. use i.value to dereference
i = a.byref(5)

# object representing the str1_t type
o = a.obj(val=5,next=a.obj(val=-2, next=0))

# dictionary representing the str1_t type
# (dictionaries will be converted into IDC objects)
d = {'val':5, 'next': {'val':-2, 'next':0} }

# initialize some pointers
findfirst           = a["__imp__FindFirstFileA@8"]
findnext            = a["__imp__FindNextFileA@8"]
findclose           = a["__imp__FindClose@4"]
getlasterror        = a["__imp__GetLastError@0"]
setcurdir           = a["__imp__SetCurrentDirectoryA@4"]
beep                = a["__imp__Beep@8"]
getwindir           = a["__imp__GetWindowsDirectoryA@8"]
getprocaddr         = a.proto("__imp__GetProcAddress@8", "int (__stdcall *GetProcAddress)(int hModule, LPCSTR lpProcName);")
getcurdir           = a["__imp__GetCurrentDirectoryA@8"]
loadlib             = a.proto("__imp__LoadLibraryA@4", "int (__stdcall *LoadLibraryA)(const char *lpLibFileName);")
freelib             = a.proto("__imp__FreeLibrary@4", "int (__stdcall *FreeLibrary)(int hLibModule);")
setlasterror        = a.typedobj("void __stdcall SetLastError(int dwErrCode);")
getmodulehandlew    = a.proto("__imp__GetModuleHandleW@4", "int (__stdcall *GetModuleHandleW)(LPCWSTR lpModuleName);")
virtualalloc        = a.typedobj("int __stdcall VirtualAlloc(int lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);")
# typed objects can become calling if an EA was provided. Thus virtualfree.ea = some_address, then we can call virtualfree(., .., ...)
virtualfree         = a.typedobj("BOOL __stdcall VirtualFree(int lpAddress, SIZE_T dwSize, DWORD dwFreeType);")
asm1                = a.proto("_asm1", "int __usercall asm1<eax>(int a<esi>, int b<edi>);")
asm2                = a.proto("_asm2", "int __usercall asm2<eax>(int a, int b, int c<ecx>);")
asm3                = a.proto("_asm3", "int __usercall asm3<edx>(int f<eax>, int a, int b, int c<ecx>);")
asm4                = a.proto("_asm4", "unsigned __int16 __usercall asm4<al:ah>(unsigned __int8 a<bl>, unsigned __int8 b<cl>);")
asm5                = a.proto("_asm5", "unsigned int __usercall asm5<si:bx>(unsigned __int8 a<al>, unsigned __int8 b<cl>, unsigned __int8 c<dl>, int d<ebx>);")
altsum              = a.proto("_va_altsum", "int __cdecl va_altsum(int n1, ...);")
getcommandline      = a.proto("__imp__GetCommandLineA@0", "LPSTR (__stdcall *GetCommandLineA)();")

# make an appcall with a user defined prototype
subst               = a.proto("_subst", "int __pascal subst(int a, int b);")

# some test identifiers
st_ref1 = 1
st_ref2 = 2
st_ref3 = 3
st_subst = 4
st_make1 = 5
st_make2 = 6
st_asm = 7
st_ex = 8
st_byval3 = 9
st_byvalref1 = 10
st_altsum = 11
st_make3 = 12
st_op64 = 13
st_ref4 = 14
st_last = 15
# some area where we can write some bytes _safely_
WRITE_AREA   = 0x400020
gr = None
#</pycode(appcalltest)>

# initialize the test
#test_init()
