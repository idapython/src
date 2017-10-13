
#<pycode(py_idd)>
NO_PROCESS = 0xFFFFFFFF
NO_THREAD  = 0

import types
import _ida_idaapi
import _ida_dbg
import _ida_typeinf
import _ida_name
import _ida_bytes
import _ida_ida
import ida_idaapi

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
        if isinstance(buf, ida_idaapi.PyIdc_cvt_refclass__):
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
            r = _ida_idd.appcall(
               self.ea,
               _ida_dbg.get_current_thread(),
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
        r = _ida_typeinf.calc_type_size(None, self.__type)
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
            return _ida_typeinf.unpack_object_from_bv(None, self.type, self.fields, src, flags)
        else:
            return _ida_typeinf.unpack_object_from_idb(None, self.type, self.fields, src, flags)

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
            return _ida_typeinf.pack_object_to_bv(obj,
                                             None,
                                             self.type,
                                             self.fields,
                                             base_ea,
                                             flags)
        else:
            return _ida_typeinf.pack_object_to_idb(obj,
                                              None,
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
            ea = _ida_name.get_name_ea(_ida_idaapi.BADADDR, name_or_ea)
        else:
            ea = name_or_ea
        # could not resolve name or invalid address?
        if ea == _ida_idaapi.BADADDR or not _ida_bytes.is_mapped(ea):
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

        result = _ida_typeinf.idc_parse_decl(None, prototype, flags)
        if result is None:
            raise ValueError, "Could not parse type: " + prototype

        # Return the callable method with type info
        return Appcall_callable__(ea, result[1], result[2])

    def __getattr__(self, name_or_ea):
        """Allows you to call functions as if they were member functions (by returning a callable object)"""
        # resolve and raise exception on error
        ea = self.__name_or_ea(name_or_ea)
        if ea == _ida_idaapi.BADADDR:
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
        t, v = _ida_name.get_name_value(_ida_idaapi.BADADDR, name)
        if t == 0: # NT_NONE
          v = default
        return v

    @staticmethod
    def int64(v):
        """Whenever a 64bit number is needed use this method to construct an object"""
        return ida_idaapi.PyIdc_cvt_int64__(v)

    @staticmethod
    def byref(val):
        """
        Method to create references to immutable objects
        Currently we support references to int/strings
        Objects need not be passed by reference (this will be done automatically)
        """
        return ida_idaapi.PyIdc_cvt_refclass__(val)

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
        return ida_idaapi.object_t(**kwds)

    @staticmethod
    def cstr(val):
        return ida_idaapi.as_cstr(val)

    @staticmethod
    def unicode(s):
        return ida_idaapi.as_unicode(s)

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
        result = _ida_typeinf.idc_parse_decl(None, typestr, 1 | 2 | 4) # PT_SIL | PT_NDC | PT_TYP
        if result is None:
            raise ValueError, "Could not parse type: " + typestr
        # Return the callable method with type info
        return Appcall_callable__(ea, result[1], result[2])

    @staticmethod
    def set_appcall_options(opt):
        """Method to change the Appcall options globally (not per Appcall)"""
        old_opt = Appcall__.get_appcall_options()
        _ida_ida.cvar.inf.appcall_options = opt
        return old_opt

    @staticmethod
    def get_appcall_options():
        """Return the global Appcall options"""
        return _ida_ida.cvar.inf.appcall_options

    @staticmethod
    def cleanup_appcall(tid = 0):
        """Equivalent to IDC's CleanupAppcall()"""
        return _ida_idd.cleanup_appcall(tid)

Appcall = Appcall__()
#</pycode(py_idd)>

#<pycode_BC695(py_idd)>
PROCESS_NO_THREAD=NO_THREAD
#</pycode_BC695(py_idd)>
