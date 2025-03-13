def parse_command_line(cmdline):
    """
    Parses a space separated string (quotes and escape character are supported)
    @param cmdline: The command line to parse
    @return: A list of strings or None on failure
    """
    pass

def set_script_timeout(timeout):
    """
    Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses.
    See also L{disable_script_timeout}.

    @param timeout: This value is in seconds.
                    If this value is set to zero then the script will never timeout.
    @return: Returns the old timeout value
    """
    pass

def disable_script_timeout():
    """
    Disables the script timeout and hides the script wait box.
    Calling L{set_script_timeout} will not have any effects until the script is compiled and executed again

    @return: None
    """
    pass

def enable_extlang_python(enable):
    """
    Enables or disables Python extlang.
    When enabled, all expressions will be evaluated by Python.

    @param enable: Set to True to enable, False otherwise
    """
    pass

def RunPythonStatement(stmt):
    """
    This is an IDC function exported from the Python plugin.
    It is used to evaluate Python statements from IDC.
    @param stmt: The statement to evaluate
    @return: 0 - on success otherwise a string containing the error
    """
    pass

class loader_input_t(pyidc_opaque_object_t):
    """
    A helper class to work with linput_t related functions.
    This class is also used by file loaders scripts.
    """
    def __init__(self, pycapsule=None):
        pass

    def close(self):
        """Closes the file"""
        pass

    def open(self, filename, remote = False):
        """
        Opens a file (or a remote file)

        @param filename: the file name
        @param remote: whether the file is local, or remote
        @return: Boolean
        """
        pass

    def set_linput(self, linput):
        """
        Links the current loader_input_t instance to a linput_t instance

        @param linput: the linput_t to link to
        """
        pass

    @staticmethod
    def from_fp(fp):
        """
        A static method to construct an instance from a FILE*

        @param fp: a FILE pointer
        @return: a new instance, or None
        """
        pass

    def open_memory(self, start: ea_t, size: int):
        """
        Create a linput for process memory (By internally calling idaapi.create_memory_linput())
        This linput will use dbg->read_memory() to read data

        @param start: starting address of the input
        @param size: size of the memory range to represent as linput
                    if unknown, may be passed as 0
        """
        pass

    def seek(self, offset: int, whence = SEEK_SET):
        """
        Set input source position

        @param offset: the seek offset
        @param whence: the position to seek from
        @return: the new position (not 0 as fseek!)
        """
        pass

    def tell(self):
        """Returns the current position"""
        pass

    def getz(self, size: int, fpos: int=-1):
        """
        Returns a zero terminated string at the given position

        @param size: maximum size of the string
        @param fpos: if != -1 then seek will be performed before reading
        @return: The string or None on failure.
        """
        pass

    def gets(self, len: int):
        """
        Reads a line from the input file. Returns the read line or None

        @param len: the maximum line length
        @return: a str, or None
        """
        pass

    def read(self, size: int=-1):
        """
        Read up to size bytes (all data if size is negative). Return an empty bytes object on EOF.

        @param size: the maximum number of bytes to read
        @return a bytes object
        """
        pass

    def readbytes(self, size: int, big_endian: bool):
        """
        Similar to read() but it respect the endianness

        @param size: the maximum number of bytes to read
        @param big_endian: endianness
        @return a str, or None
        """
        pass

    def file2base(self, pos: int, ea1: ea_t, ea2: ea_t, patchable: bool):
        """
        Load portion of file into the database
        This function will include (ea1..ea2) into the addressing space of the
        program (make it enabled)

        @param li: pointer ot input source
        @param pos: position in the file
        @param (ea1..ea2): range of destination linear addresses
        @param patchable: should the kernel remember correspondance of
                          file offsets to linear addresses.
        @return: 1-ok,0-read error, a warning is displayed
        """
        pass

    def get_byte(self):
        """Reads a single byte from the file. Returns None if EOF or the read byte"""
        pass

    def opened(self):
        """Checks if the file is opened or not"""
        pass
