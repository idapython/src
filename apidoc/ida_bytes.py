
class data_type_t(object):
    """
    Information about a data type
    """

    def may_create_at(self, ea, nbytes):
        """May create data?
        No such callback means: always succeed (i.e., no restriction where
        such a data type can be created.)
        @param ea: candidate address for the data item
        @param nbytes: candidate size for the data item
        @return: True/False
        """
        return True

    def calc_item_size(self, ea, maxsize):
        """This callback is used to determine size of the (possible)
        item at `ea`.
        No such callback means that datatype is of fixed size `value_size`.
        (thus, this callback is required only for varsize datatypes.)
        @param ea: address of the item
        @param maxsize: maximum size of the item
        @return: 0 - no such item can be created/displayed
        """
        return 0


class data_format_t(object):
    """
    Information about a data format
    """

    def printf(self, value, current_ea, operand_num, dtid):
        """Convert `value` to colored string using custom format.
        @param value: value to print (of type 'str', sequence of bytes)
        @param current_ea: current address (BADADDR if unknown)
        @param operand_num: current operand number
        @param dtid: custom data type id
        @return: string representing data
        """
        return None

    def scan(self, input, current_ea, operand_num):
        """Convert uncolored string (user input) to the value.
        This callback is called from the debugger when an user enters a
        new value for a register with a custom data representation (e.g.,
        an MMX register.)
        @param input: input string
        @param current_ea: current address (BADADDR if unknown)
        @param operand_num: current operand number (-1 if unknown)
        @return: tuple(bool, string)
                 (True, output value) or
                 (False, error message)
        """
        return (False, "Not implemented")

    def analyze(self, current_ea, operand_num):
        """Analyze custom data format occurrence.
        This callback is called in 2 cases:
        - after emulating an instruction (after a call of
          'ev_emu_insn') if its operand is marked as "custom data
          representation"
        - when emulating data (this is done using a call of
          'ev_out_data' with analyze_only == true). This is the right
          place to create cross references from the current item.
        @param current_ea: current address (BADADDR if unknown)
        @param operand_num: current operand number
        """
        pass


def register_custom_data_type(dt):
    """
    Registers a custom data type.

    @param dt: an instance of the data_type_t class
    @return:
        < 0 if failed to register
        > 0 data type id
    """
    pass


def unregister_custom_data_type(dtid):
    """
    Unregisters a custom data type.

    @param dtid: the data type id
    @return: Boolean
    """
    pass


def register_custom_data_format(df):
    """
    Registers a custom data format with a given data type.

    @param df: an instance of data_format_t
    @return:
        < 0 if failed to register
        > 0 data format id
    """
    pass

def unregister_custom_data_format(dfid):
    """
    Unregisters a custom data format

    @param dfid: data format id
    @return: Boolean
    """
    pass

def visit_patched_bytes(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, callable):
    """
    Enumerates patched bytes in the given range and invokes a callable

    @param ea1: start address
    @param ea2: end address
    @param callable: a Python callable with the following prototype:
                     callable(ea, fpos, org_val, patch_val).
                     If the callable returns non-zero then that value will be
                     returned to the caller and the enumeration will be
                     interrupted.
    @return: Zero if the enumeration was successful or the return
             value of the callback if enumeration was interrupted.
    """
    pass

def get_bytes(ea: ida_idaapi.ea_t, size: int, gmb_flags: int=GMB_READALL):
    """
    Get the specified number of bytes of the program.

    @param ea: program address
    @param size: number of bytes to return
    @param gmb_flags: OR'ed combination of GMB_* values (defaults to GMB_READALL)
    @return: the bytes (as bytes object), or None in case of failure
    """
    pass

def get_bytes_and_mask(ea: ida_idaapi.ea_t, size: int, gmb_flags: int=GMB_READALL):
    """
    Get the specified number of bytes of the program, and a bitmask
    specifying what bytes are defined and what bytes are not.

    @param ea: program address
    @param size: number of bytes to return
    @param gmb_flags: OR'ed combination of GMB_* values (defaults to GMB_READALL)
    @return: a tuple (bytes, mask), or None in case of failure.
             Both 'bytes' and 'mask' are 'str' instances.
    """
    pass

# Conversion options for get_strlit_contents():
STRCONV_ESCAPE   = 0x00000001 # convert non-printable characters to C escapes (\n, \xNN, \uNNNN)

def get_strlit_contents(ea: ida_idaapi.ea_t, len: int, type: int, flags: int = 0):
  """
  Get contents of string literal, as UTF-8-encoded codepoints.
  It works even if the string has not been created in the database yet.

  Note that the returned value will be of type 'bytes'; if
  you want auto-conversion to unicode strings (that is: real Python
  strings), you should probably be using the idautils.Strings class.

  @param ea: linear address of the string
  @param len: length of the string in bytes (including terminating 0)
  @param type: type of the string. Represents both the character encoding,
               <u>and</u> the 'type' of string at the given location.
  @param flags: combination of STRCONV_..., to perform output conversion.
  @return: a bytes-filled str object.
  """
  pass


def op_stroff(*args) -> bool:
    """
    Set operand representation to be 'struct offset'.

    This function has the following signatures:

        1. op_stroff(ins: ida_ua.insn_t, n: int, path: List[int], delta: int)
        2. op_stroff(ins: ida_ua.insn_t, n: int, path: ida_pro.tid_array, path_len: int, delta: int) (backward-compatibility only)

    Here is an example using this function:

        ins = ida_ua.insn_t()
        if ida_ua.decode_insn(ins, some_address):
            operand = 0
            path = [ida_typeinf.get_named_type_tid("my_stucture_t")] # a one-element path
            ida_bytes.op_stroff(ins, operand, path, 0)
    """
    pass

def get_stroff_path(*args):
    """
    Get the structure offset path for operand `n`, at the
    specified address.

    This function has the following signatures:

        1. get_stroff_path(ea: ida_idaapi.ea_t, n : int) -> Tuple[List[int], int]
        2. get_stroff_path(path: tid_array, delta: sval_pointer, ea: ida_idaapi.ea_t, n : int) (backward-compatibility only)

    @param ea address where the operand holds a path to a structure offset (1st form)
    @param n operand number (1st form)
    @return a tuple holding a (list_of_tid_t's, delta_within_the_last_type), or (None, None)
    """
    pass

def bin_search(*args):
    """
    Search for a set of bytes in the program

    This function has the following signatures:

        1. bin_search(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, data: compiled_binpat_vec_t, flags: int) -> Tuple[ida_idaapi.ea_t, int]
        2. bin_search(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, image: bytes, mask: bytes, len: int, flags: int) -> ida_idaapi.ea_t

    The return value type will differ depending on the form:

        1. a tuple `(matched-address, index-in-compiled_binpat_vec_t)` (1st form)
        2. the address of a match, or ida_idaapi.BADADDR if not found (2nd form)

    This is a low-level function; more user-friendly alternatives
    are available. Please see 'find_bytes' and 'find_string'.

    @param start_ea: linear address, start of range to search
    @param end_ea: linear address, end of range to search (exclusive)
    @param data: (1st form) the prepared data to search for (see parse_binpat_str())
    @param bytes: (2nd form) a set of bytes to match
    @param mask: (2nd form) a mask to apply to the set of bytes
    @param flags: combination of BIN_SEARCH_* flags
    @return: either a tuple holding both the address of the match and the index of the compiled pattern that matched, or the address of a match (ida_idaapi.BADADDR if not found)
    """
    pass





