
def get_fchunk_referer(ea: int, idx):
    pass

def get_idasgn_desc(n):
    """
    Get information about a signature in the list.
    It returns: (name of signature, names of optional libraries)

    See also: get_idasgn_desc_with_matches

    @param n: number of signature in the list (0..get_idasgn_qty()-1)
    @return: None on failure or tuple(signame, optlibs)
    """
    pass

def get_idasgn_desc_with_matches(n):
    """
    Get information about a signature in the list.
    It returns: (name of signature, names of optional libraries, number of matches)

    @param n: number of signature in the list (0..get_idasgn_qty()-1)
    @return: None on failure or tuple(signame, optlibs, nmatches)
    """
    pass

class func_t(object):
    def get_name(self):
        """
        Get the function name

        @return the function name
        """
        pass

    def get_frame_object(self):
        """
        Retrieve the function frame, in the form of a structure
        where frame offsets that are accessed by the program, as well
        as areas for "saved registers" and "return address", are
        represented by structure members.

        If the function has no associated frame, return None

        @return a ida_typeinf.tinfo_t object representing the frame, or None
        """
        pass

    def get_prototype(self):
        """
        Retrieve the function prototype.

        Once you have obtained the prototype, you can:

        * retrieve the return type through ida_typeinf.tinfo_t.get_rettype()
        * iterate on the arguments using ida_typeinf.tinfo_t.iter_func()

        If the function has no associated prototype, return None

        @return a ida_typeinf.tinfo_t object representing the prototype, or None
        """
        pass

