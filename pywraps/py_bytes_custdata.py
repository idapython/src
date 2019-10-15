from __future__ import print_function
# -----------------------------------------------------------------------
#<pycode(py_bytes_custdata)>
DTP_NODUP = 0x0001
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
    The data format may be attached to several data types. The id of the
    data format is stored in the first data_format_t object. For example:
    assert many_formats[1][1] != -1
    assert many_formats[2][0] != -1
    assert many_formats[3][0] == -1
    """
    def __reg_format(df, dtid):
        dfid = register_custom_data_format(df);
        if dfid == -1:
            dfid = find_custom_data_format(df.name);
            if dfid == -1:
              return False
        attach_custom_data_format(dtid, dfid)
        if dtid == 0:
            print("Registered format '%s' with built-in types, ID=%d" % (df.name, dfid))
        else:
            print("   Registered format '%s', ID=%d (dtid=%d)" % (df.name, dfid, dtid))
        return True

    def __reg_type(dt):
        register_custom_data_type(dt)
        print("Registered type '%s', ID=%d" % (dt.name, dt.id))
        return dt.id != -1
    ok = __walk_types_and_formats(formats, __reg_type, __reg_format, True)
    return 1 if ok else -1

# -----------------------------------------------------------------------
def unregister_data_types_and_formats(formats):
    """
    As opposed to register_data_types_and_formats(), this function
    unregisters multiple data types and formats at once.
    """
    def __unreg_format(df, dtid):
        print("%snregistering format '%s'" % ("U" if dtid == 0 else "   u", df.name))
        unregister_custom_data_format(df.id)
        return True

    def __unreg_type(dt):
        print("Unregistering type '%s', ID=%d" % (dt.name, dt.id))
        unregister_custom_data_type(dt.id)
        return True
    ok = __walk_types_and_formats(formats, __unreg_type, __unreg_format, False)
    return 1 if ok else -1

#--------------------------------------------------------------------------
#
#
#<pydoc>
#class data_type_t(object):
#    """
#    The following optional callback methods can be implemented
#    in a data_type_t subclass
#    """
#
#    def may_create_at(self, ea, nbytes):
#        """May create data?
#        No such callback means: always succeed (i.e., no restriction where
#        such a data type can be created.)
#        @param ea: candidate address for the data item
#        @param nbytes: candidate size for the data item
#        @return: True/False
#        """
#        return True
#
#    def calc_item_size(self, ea, maxsize):
#        """This callback is used to determine size of the (possible)
#        item at `ea`.
#        No such callback means that datatype is of fixed size `value_size`.
#        (thus, this callback is required only for varsize datatypes.)
#        @param ea: address of the item
#        @param maxsize: maximum size of the item
#        @return: 0 - no such item can be created/displayed
#        """
#        return 0
#
#
#class data_format_t(object):
#    """
#    The following callback methods can be implemented
#    in a data_format_t subclass
#    """
#
#    def printf(self, value, current_ea, operand_num, dtid):
#        """Convert `value` to colored string using custom format.
#        @param value: value to print (of type 'str', sequence of bytes)
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number
#        @param dtid: custom data type id
#        @return: string representing data
#        """
#        return None
#
#    def scan(self, input, current_ea, operand_num):
#        """Convert uncolored string (user input) to the value.
#        This callback is called from the debugger when an user enters a
#        new value for a register with a custom data representation (e.g.,
#        an MMX register.)
#        @param input: input string
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number (-1 if unknown)
#        @return: tuple(bool, string)
#                 (True, output value) or
#                 (False, error message)
#        """
#        return (False, "Not implemented")
#
#    def analyze(self, current_ea, operand_num):
#        """Analyze custom data format occurrence.
#        This callback is called in 2 cases:
#        - after emulating an instruction (after a call of
#          'ev_emu_insn') if its operand is marked as "custom data
#          representation"
#        - when emulating data (this is done using a call of
#          'ev_out_data' with analyze_only == true). This is the right
#          place to create cross references from the current item.
#        @param current_ea: current address (BADADDR if unknown)
#        @param operand_num: current operand number
#        """
#        pass
#
#
#</pydoc>
#</pycode(py_bytes_custdata)>
# -----------------------------------------------------------------------
