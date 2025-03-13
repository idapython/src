
def calc_type_size(til: til_t, type: bytes):
    """
    Returns the size of a type
    @param til: Type info library. 'None' can be passed.
    @param type: serialized type byte string
    @return:
        - None on failure
        - The size of the type
    """
    pass

def apply_type(til: til_t, type: bytes, fields: bytes, ea: ida_idaapi.ea_t, flags: int) -> bool:
    """
    Apply the specified type to the address

    @param til: Type info library. 'None' can be used.
    @param type: type string
    @param fields: fields string (may be empty or None)
    @param ea: the address of the object
    @param flags: combination of TINFO_... constants or 0
    @return: Boolean
    """
    pass

def get_arg_addrs(caller: ida_idaapi.ea_t):
    """
    Retrieve addresses of argument initialization instructions

    @param caller: the address of the call instruction
    @return: list of instruction addresses
    """
    pass

def unpack_object_from_idb(til: til_t, type: bytes, fields: bytes, ea: ida_idaapi.ea_t, pio_flags: int = 0):
    """
    Unpacks from the database at 'ea' to an object.
    Please refer to unpack_object_from_bv()
    """
    pass

def unpack_object_from_bv(til: til_t, type: bytes, fields: bytes, bytes, pio_flags: int = 0):
    """
    Unpacks a buffer into an object.
    Returns the error_t returned by idaapi.pack_object_to_idb

    @param til: Type library. 'None' can be passed.
    @param type: type string
    @param fields: fields string (may be empty or None)
    @param bytes: the bytes to unpack
    @param pio_flags: flags used while unpacking
    @return:
        - tuple(0, err) on failure
        - tuple(1, obj) on success
    """
    pass

def pack_object_to_idb(obj, til: til_t, type: bytes, fields: bytes, ea: ida_idaapi.ea_t, pio_flags: int = 0):
    """
    Write a typed object to the database.
    Raises an exception if wrong parameters were passed or conversion fails
    Returns the error_t returned by idaapi.pack_object_to_idb

    @param til: Type library. 'None' can be passed.
    @param type: type string
    @param fields: fields string (may be empty or None)
    @param ea: ea to be used while packing
    @param pio_flags: flags used while unpacking
    """
    pass

def pack_object_to_bv(obj, til: til_t, type: bytes, fields: bytes, base_ea: ida_idaapi.ea_t, pio_flags: int = 0):
    """
    Packs a typed object to a string

    @param til: Type library. 'None' can be passed.
    @param type: type string
    @param fields: fields string (may be empty or None)
    @param base_ea: base ea used to relocate the pointers in the packed object
    @param pio_flags: flags used while unpacking
    @return:
        tuple(0, err_code) on failure
        tuple(1, packed_buf) on success
    """
    pass

def get_named_type(til: til_t, name: str, ntf_flags: int):
    """
    Get a type data by its name.

    @param til: Type library
    @param name: the type name
    @param ntf_flags: a combination of NTF_* constants
    @return:
        None on failure
        tuple(code, type_str, fields_str, cmt, field_cmts, sclass, value) on success
    """
    pass

class tinfo_t(object):
    def __init__(self, *args, ordinal=None, name=None, tid=None, til=None):
        """
        Create a type object with the provided argumens.

        This constructor has the following signatures:

            1. tinfo_t(decl_type: type_t)
            2. tinfo_t(decl: str, til: til_t = None, pt_flags: int = 0)

        The latter form will create the type object by parsing the type declaration

        Alternatively, you can use a form accepting the following keyword arguments:

        * ordinal: int
        * name: str
        * tid: int
        * til: til_t=None # `None` means `get_idati()`

        E.g.,

        * tinfo_t(ordinal=3)
        * tinfo_t(ordinal=10, til=get_idati())
        * tinfo_t(name="mytype_t")
        * tinfo_t(name="thattype_t", til=my_other_til)
        * tinfo_t(tid=ida_nalt.get_strid(some_address))

        The constructor may raise an exception if data was invalid, or if parsing failed.

        @param decl_type A simple type
        @param decl A valid C declaration
        @param til A type library, or `None` to use the (`get_idati()`) default
        @param ordinal An ordinal in the type library
        @param name A valid type name
        @param pt_flags Parsing flags
        """
        pass

    def get_udm(self, *args) -> Union[Tuple[int, 'udm_t'], Tuple[None, None]]:
        """
        Retrieve a structure/union member with either the specified name
        or the specified index, in the specified tinfo_t object.

        This function has the following signatures:

            1. get_udm(index: int)
            2. get_udm(name: str)

        @param index a member index (1st form)
        @param name a member name (2nd form)
        @return a tuple (int, udm_t), or (-1, None) if member not found
        """
        pass

    def get_udm_by_offset(self, offset: int):
        """
        Retrieve a structure/union member with the specified offset,
        in the specified tinfo_t object.

        @param offset the member offset
        @return a tuple (int, udm_t), or (-1, None) if member not found
        """
        pass

    def add_udm(self, *args):
        """
        Add a member to the current structure/union.

        When creating a new structure/union from scratch, you might
        want to first call `create_udt()`

        This method has the following signatures:

            1. add_udm(udm: udm_t, etf_flags: int = 0, times: int = 1, idx: int = -1)
            2. add_udm(name: str, type: type_t | tinfo_t | str, offset: int = 0, etf_flags: int = 0, times: int = 1, idx: int = -1)

        In the 2nd form, the 'type' descriptor, can be one of:

        * type_t: if the type is simple (integral/floating/bool). E.g., `BTF_INT`
        * tinfo_t: can handle more complex types (structures, pointers, arrays, ...)
        * str: a C type declaration

        If an input argument is incorrect, the constructor may raise an exception

        @param udm       The member, fully initialized (1st form)
        @param name      Member name - must not be empty
        @param type      Member type
        @param offset    the member offset in bits. It is the caller's responsibility
               to specify correct offsets.
        @param etf_flags an OR'ed combination of ETF_ flags
        @param times     how many times to add the new member
        @param idx       the index in the udm array where the new udm should be placed.
                         If the specified index cannot be honored because it would spoil
                         the udm sorting order, it is silently ignored.
        """
        pass

    def get_edm(self, *args) -> Tuple[int, 'edm_t']:
        """
        Retrieve an enumerator with either the specified name
        or the specified index, in the specified tinfo_t object.

        This function has the following signatures:

            1. get_edm(index: int)
            2. get_edm(name: str)

        @param index an enumerator index (1st form).
        @param name an enumerator name (2nd form).
        @return a tuple (int, edm_t), or (-1, None) if member not found
        """
        pass

    def get_edm_by_value(self, value: int, bmask: int = DEFMASK64, serial: int = 0) -> Tuple[int, 'edm_t']:
        """
        Retrieve an enumerator with the specified value,
        in the specified tinfo_t object.

        @param value the enumerator value
        @return a tuple (int, edm_t), or (-1, None) if member not found
        """
        pass

    def add_edm(self, *args):
        """
        Add an enumerator to the current enumeration.

        When creating a new enumeration from scratch, you might
        want to first call `create_enum()`

        This method has the following signatures:

            1. add_edm(edm: edm_t, bmask: int = -1, etf_flags: int = 0, idx: int = -1)
            2. add_edm(name: str, value: int, bmask: int = -1, etf_flags: int = 0, idx: int = -1)

        If an input argument is incorrect, the constructor may raise an exception

        @param edm       The member, fully initialized (1st form)
        @param name      Enumerator name - must not be empty
        @param value     Enumerator value
        @param bmask     A bitmask to which the enumerator belongs
        @param etf_flags an OR'ed combination of ETF_ flags
        @param idx       the index in the edm array where the new udm should be placed.
                         If the specified index cannot be honored because it would spoil
                         the edm sorting order, it is silently ignored.
        """
        pass

    def del_edm(self, *args):
        """
        Delete an enumerator with the specified name
        or the specified index, in the specified tinfo_t object.

        This method has the following signatures:

            1. del_edm(name: str) -> int
            2. del_edm(index: int) -> int

        @param name an enumerator name (1st form)
        @param index an enumerator index (2nd form)
        @return TERR_OK in case of success, or another TERR_* value in case of error
        """
        pass

    def del_edm_by_value(self, value: int, etf_flags: int=0, bmask: int = DEFMASK64, serial: int = 0):
        """
        Delete an enumerator with the specified value,
        in the specified tinfo_t object.

        @param value the enumerator value
        @return TERR_OK in case of success, or another TERR_* value in case of error
        """
        pass

    def iter_struct(self):
        """
        Iterate on the members composing this structure.

        Example:

            til = ida_typeinf.get_idati()
            tif = til.get_named_type("my_struc")
            for udm in tif.iter_struct():
                print(f"{udm.name} at bit offset {udm.offset}")

        Will raise an exception if this type is not a structure.

        @return a udm_t-producing generator
        """
        pass

    def iter_union(self):
        """
        Iterate on the members composing this union.

        Example:

            til = ida_typeinf.get_idati()
            tif = til.get_named_type("my_union")
            for udm in tif.iter_union():
                print(f"{udm.name}, with type {udm.type}")

        Will raise an exception if this type is not a union.

        @return a udm_t-producing generator
        """
        pass

    def iter_udt(self):
        """
        Iterate on the members composing this structure, or union.

        Example:

            til = ida_typeinf.get_idati()
            tif = til.get_named_type("my_type")
            for udm in tif.iter_udt():
                print(f"{udm.name} at bit offset {udm.offset} with type {udm.type}")

        Will raise an exception if this type is not a structure, or union

        @return a udm_t-producing generator
        """
        pass

    def iter_enum(self):
        """
        Iterate on the members composing this enumeration.

        Example:

            til = ida_typeinf.get_idati()
            tif = til.get_named_type("my_enum")
            for edm in tif.iter_enum():
                print(f"{edm.name} = {edm.value}")

        Will raise an exception if this type is not an enumeration

        @return a edm_t-producing generator
        """
        pass

    def iter_func(self):
        """
        Iterate on the arguments contained in this function prototype

        Example:

            address = ...
            func = ida_funcs.get_func(address)
            func_type = func.prototype
            for arg in func_type.iter_func():
                print(f"{arg.name}, of type {arg.type}")

        Will raise an exception if this type is not a function

        @return a funcarg_t-producing generator
        """
        pass

class edm_t(object):
    def __init__(self, *args):
        """
        Create an enumerator, with the specified name and value

        This constructor has the following signatures:

            1. edm_t(edm: edm_t)
            2. edm_t(name: str, value: int, cmt: str=None)

        @param name  Enumerator name. Must not be empty (1st form)
        @param value Enumerator value (1st form)
        @param cmt   Enumerator repeatable comment. May be empty (1st form)
        @param edm   An enum member to copy
        """
        pass

class udm_t(object):
    def __init__(self, *args):
        """
        Create a structure/union member, with the specified name and type.

        This constructor has the following signatures:

            1. udm_t(udm: udm_t)
            2. udm_t(name: str, type, offset: int)

        The 'type' descriptor, can be one of:

        * type_t: if the type is simple (integral/floating/bool). E.g., `BTF_INT`
        * tinfo_t: can handle more complex types (structures, pointers, arrays, ...)
        * str: a C type declaration

        If an input argument is incorrect, the constructor may raise an exception
        The size will be computed automatically.

        @param udm a source udm_t
        @param name a valid member name. Must not be empty.
        @param type the member type
        @param offset the member offset in bits. It is the caller's responsibility
               to specify correct offsets.
        """
        pass

    def copy(self, src):
        """
        Copy the src, into this instance

        @param src The source udm_t
        """
        pass

class udt_type_data_t(object):
    def get_best_fit_member(self, disp):
        """
        Get the member that is most likely referenced by the specified offset.

        @param disp the byte offset
        @return a tuple (int, udm_t), or (-1, None) if member not found
        """
        pass


class funcarg_t(object):
    def __init__(self, *args):
        """
        Create a function argument, with the specified name and type.

        This constructor has the following signatures:

            1. funcarg_t(name: str, type, argloc: argloc_t)
            2. funcarg_t(funcarg: funcarg_t)

        In the 1st form, the 'type' descriptor, can be one of:

            * type_t: if the type is simple (integral/floating/bool). E.g., `BTF_INT`
            * tinfo_t: can handle more complex types (structures, pointers, arrays, ...)
            * str: a C type declaration

        If an input argument is incorrect, the constructor may raise an exception

        @param name a valid argument name. May not be empty (1st form).
        @param type the member type (1st form).
        @param argloc the argument location. Can be empty (1st form).
        @param funcarg a funcarg_t to copy
        """
        pass

class til_t(object):
    def import_type(self, src):
        """
        Import a type (and all its dependencies) into this type info library.

        @param src The type to import
        @return the imported copy, or None
        """

    def numbered_types(self):
        """
        Returns a generator over the numbered types contained in this
        type library.

        Every iteration returns a fresh new tinfo_t object

        @return a tinfo_t-producing generator
        """
        pass

    def named_types(self):
        """
        Returns a generator over the named types contained in this
        type library.

        Every iteration returns a fresh new tinfo_t object

        @return a tinfo_t-producing generator
        """
        pass

    def get_named_type(self, name):
        """
        Retrieves a tinfo_t representing the named type in this type library.

        @param name a type name
        @return a new tinfo_t object, or None if not found
        """
        pass

    def get_numbered_type(self, ordinal):
        """
        Retrieves a tinfo_t representing the numbered type in this type library.

        @param ordinal a type ordinal
        @return a new tinfo_t object, or None if not found
        """
        pass

def get_named_type64(til: til_t, name: str, ntf_flags: int=0) -> Union[Tuple[int, bytes, bytes, str, str, int, int],  None]:
    """
    Get a named type from a type library.

    Please use til_t.get_named_type instead.
    """
    pass

def get_numbered_type(til: til_t, ordinal: int) -> Union[Tuple[bytes, bytes, str, str, int], None]:
    """
    Get a type from a type library, by its ordinal

    Please use til_t.get_numbered_type instead.
    """
    pass

def idc_get_local_type_raw(ordinal) -> Tuple[bytes, bytes]:
    """
    """
    pass

def idc_parse_decl(til: til_t, decl: str, flags: int) -> Tuple[str, bytes, bytes]:
    """
    """
    pass

def idc_print_type(type: bytes, fields: bytes, name: str, flags: int) -> str:
    """
    """
    pass

def print_decls(printer: text_sink_t, til: til_t, ordinals: List[int], flags: int) -> int:
    """
    Print types (and possibly their dependencies) in a format suitable for using in
    a header file. This is the reverse parse_decls().

    @param printer a handler for printing text
    @param til the type library holding the ordinals
    @param ordinals a list of ordinals corresponding to the types to print
    @param flags a combination of PDF_ constants
    @return
            >0: the number of types exported
             0: an error occurred
            <0: the negated number of types exported. There were minor errors and
                the resulting output might not be compilable.
    """
    pass

def remove_tinfo_pointer(tif: tinfo_t, name: str, til: til_t) -> Tuple[bool, str]:
    """
    Remove pointer of a type. (i.e. convert "char *" into "char"). Optionally remove
    the "lp" (or similar) prefix of the input name. If the input type is not a
    pointer, then fail.

    @param tif the type info
    @param name the name of the type to "unpointerify"
    @param til the type library
    @return a tuple (success, new-name)
    """
    pass



