# -----------------------------------------------------------------------
# Standalone and testing code
import sys
try:
    import pywraps
    pywraps_there = True
    print "Using pywraps"
except:
    pywraps_there = False
    print "Not using pywraps"

try:
    import _idaapi
except:
    print "Please try me from inside IDA"
    sys.exit(0)

import struct

if pywraps_there:
    _idaapi.register_custom_data_type     = pywraps.register_custom_data_type
    _idaapi.unregister_custom_data_type   = pywraps.unregister_custom_data_type
    _idaapi.register_custom_data_format   = pywraps.register_custom_data_format
    _idaapi.unregister_custom_data_format = pywraps.unregister_custom_data_format
    _idaapi.get_custom_data_format        = pywraps.get_custom_data_format
    _idaapi.get_custom_data_type          = pywraps.get_custom_data_type

# -----------------------------------------------------------------------
#<pycode(py_bytes)>
DTP_NODUP = 0x0001

class data_type_t(object):
    """
    Custom data type definition. All data types should inherit from this class.
    """

    def __init__(self, name, value_size = 0, menu_name = None, hotkey = None, asm_keyword = None, props = 0):
        """Please refer to bytes.hpp / data_type_t in the SDK"""
        self.name  = name
        self.props = props
        self.menu_name = menu_name
        self.hotkey = hotkey
        self.asm_keyword = asm_keyword
        self.value_size = value_size

        self.id = -1 # Will be initialized after registration
        """Contains the data type id after the data type is registered"""

    def register(self):
        """Registers the data type and returns the type id or < 0 on failure"""
        return _idaapi.register_custom_data_type(self)

    def unregister(self):
        """Unregisters the data type and returns True on success"""
        # Not registered?
        if self.id < 0:
            return True

        # Try to unregister
        r = _idaapi.unregister_custom_data_type(self.id)

        # Clear the ID
        if r:
            self.id = -1
        return r
#<pydoc>
#    def may_create_at(self, ea, nbytes):
#        """
#        (optional) If this callback is not defined then this means always may create data type at the given ea.
#        @param ea: address of the future item
#        @param nbytes: size of the future item
#        @return: Boolean
#        """
#
#        return False
#
#    def calc_item_size(self, ea, maxsize):
#        """
#        (optional) If this callback is defined it means variable size datatype
#        This function is used to determine size of the (possible) item at 'ea'
#        @param ea: address of the item
#        @param maxsize: maximal size of the item
#        @return: integer
#            Returns: 0-no such item can be created/displayed
#                     this callback is required only for varsize datatypes
#        """
#        return 0
#</pydoc>
# -----------------------------------------------------------------------
# Uncomment the corresponding callbacks in the inherited class
class data_format_t(object):
    """Information about a data format"""
    def __init__(self, name, value_size = 0, menu_name = None, props = 0, hotkey = None, text_width = 0):
        """Custom data format definition.
        @param name: Format name, must be unique
        @param menu_name: Visible format name to use in menus
        @param props: properties (currently 0)
        @param hotkey: Hotkey for the corresponding menu item
        @param value_size: size of the value in bytes. 0 means any size is ok
        @text_width: Usual width of the text representation
        """
        self.name = name
        self.menu_name = menu_name
        self.props = props
        self.hotkey = hotkey
        self.value_size = value_size
        self.text_width = text_width

        self.id = -1 # Will be initialized after registration
        """contains the format id after the format gets registered"""

    def register(self, dtid):
        """Registers the data format with the given data type id and returns the type id or < 0 on failure"""
        return _idaapi.register_custom_data_format(dtid, self)

    def unregister(self, dtid):
        """Unregisters the data format with the given data type id"""

        # Not registered?
        if self.id < 0:
            return True

        # Unregister
        r = _idaapi.unregister_custom_data_format(dtid, self.id)

        # Clear the ID
        if r:
            self.id = -1
        return r
#<pydoc>
#    def printf(self, value, current_ea, operand_num, dtid):
#        """
#        Convert a value buffer to colored string.
#
#        @param value: The value to be printed
#        @param current_ea: The ea of the value
#        @param operand_num: The affected operand
#        @param dtid: custom data type id (0-standard built-in data type)
#        @return: a colored string representing the passed 'value' or None on failure
#        """
#        return None
#
#    def scan(self, input, current_ea, operand_num):
#        """
#        Convert from uncolored string 'input' to byte value
#
#        @param input: input string
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number (-1 if unknown)
#
#        @return: tuple (Boolean, string)
#            - (False, ErrorMessage) if conversion fails
#            - (True, Value buffer) if conversion succeeds
#        """
#        return (False, "Not implemented")
#
#    def analyze(self, current_ea, operand_num):
#        """
#        (optional) Analyze custom data format occurrence.
#        It can be used to create xrefs from the current item.
#
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number
#        @return: None
#        """
#
#        pass
#</pydoc>
# -----------------------------------------------------------------------
def __walk_types_and_formats(formats, type_action, format_action, installing):
    broken = False
    for f in formats:
        if len(f) == 1:
            if not format_action(f[0], 0):
                broken = True
                break
        else:
            dt  = f[0]
            dfs = f[1:]
            # install data type before installing formats
            if installing and not type_action(dt):
                broken = True
                break
            # process formats using the correct dt.id
            for df in dfs:
                if not format_action(df, dt.id):
                    broken = True
                    break
            # uninstall data type after uninstalling formats
            if not installing and not type_action(dt):
                broken = True
                break
    return not broken

# -----------------------------------------------------------------------
def register_data_types_and_formats(formats):
    """
    Registers multiple data types and formats at once.
    To register one type/format at a time use register_custom_data_type/register_custom_data_format

    It employs a special table of types and formats described below:

    The 'formats' is a list of tuples. If a tuple has one element then it is the format to be registered with dtid=0
    If the tuple has more than one element, then tuple[0] is the data type and tuple[1:] are the data formats. For example:
    many_formats = [
      (pascal_data_type(), pascal_data_format()),
      (simplevm_data_type(), simplevm_data_format()),
      (makedword_data_format(),),
      (simplevm_data_format(),)
    ]
    The first two tuples describe data types and their associated formats.
    The last two tuples describe two data formats to be used with built-in data types.
    """
    def __reg_format(df, dtid):
        df.register(dtid)
        if dtid == 0:
            print "Registered format '%s' with built-in types, ID=%d" % (df.name, df.id)
        else:
            print "   Registered format '%s', ID=%d (dtid=%d)" % (df.name, df.id, dtid)
        return df.id != -1

    def __reg_type(dt):
        dt.register()
        print "Registered type '%s', ID=%d" % (dt.name, dt.id)
        return dt.id != -1
    ok = __walk_types_and_formats(formats, __reg_type, __reg_format, True)
    return 1 if ok else -1

# -----------------------------------------------------------------------
def unregister_data_types_and_formats(formats):
    """As opposed to register_data_types_and_formats(), this function
    unregisters multiple data types and formats at once.
    """
    def __unreg_format(df, dtid):
        print "%snregistering format '%s'" % ("U" if dtid == 0 else "   u", df.name)
        df.unregister(dtid)
        return True

    def __unreg_type(dt):
        print "Unregistering type '%s', ID=%d" % (dt.name, dt.id)
        dt.unregister()
        return True
    ok = __walk_types_and_formats(formats, __unreg_type, __unreg_format, False)
    return 1 if ok else -1

#</pycode(py_bytes)>
# -----------------------------------------------------------------------
