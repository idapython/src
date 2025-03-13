
class qfile_t(pyidc_opaque_object_t):

    """A helper class to work with FILE related functions."""

    def __init__(self, *args):
        pass

    def close(self):
        """Closes the file"""
        pass

    def open(self, filename, mode):
        """
        Opens a file

        @param filename: the file name
        @param mode: The mode string, ala fopen() style
        @return: Boolean
        """
        pass

    def set_linput(self, linput):
        """Links the current loader_input_t instance to a linput_t instance"""
        pass

    @staticmethod
    def tmpfile():
        """A static method to construct an instance using a temporary file"""
        pass

    def seek(self, offset, whence = ida_idaapi.SEEK_SET):
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

    def gets(self, len):
        """
        Reads a line from the input file. Returns the read line or None

        @param len: the maximum line length
        """
        pass

    def read(self, size):
        """
        Reads from the file. Returns the buffer or None

        @param size: the maximum number of bytes to read
        @return: a str, or None
        """
        pass

    def write(self, buf):
        """
        Writes to the file. Returns 0 or the number of bytes written

        @param buf: the str to write
        @return: result code
        """
        pass

    def readbytes(self, size, big_endian):
        """
        Similar to read() but it respect the endianness

        @param size: the maximum number of bytes to read
        @param big_endian: endianness
        @return a str, or None
        """
        pass

    def writebytes(self, size, big_endian):
        """
        Similar to write() but it respect the endianness

        @param buf: the str to write
        @param big_endian: endianness
        @return: result code
        """
        pass

    def flush(self):
        pass

    def get_byte(self):
        """Reads a single byte from the file. Returns None if EOF or the read byte"""
        pass

    def put_byte(self):
        """
        Writes a single byte to the file

        @param chr: the byte value
        """
        pass

    def opened(self):
        """Checks if the file is opened or not"""
        pass
