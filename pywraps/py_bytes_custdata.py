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

#</pycode(py_bytes_custdata)>
