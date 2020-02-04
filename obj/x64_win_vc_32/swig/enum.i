%module(docstring="IDA Plugin SDK API wrapper: enum",directors="1",threads="1") ida_enum
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_ENUM
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_ENUM
  #define HAS_DEP_ON_INTERFACE_ENUM
#endif
%include "header.i"
%{
#include <enum.hpp>
%}
%ignore get_enum_name(tid_t);

%constant bmask_t DEFMASK = bmask_t(-1);

%include "enum.hpp"
%pythoncode %{
if _BC695:
    CONST_ERROR_ENUM=ENUM_MEMBER_ERROR_NAME
    CONST_ERROR_ILLV=ENUM_MEMBER_ERROR_VALUE
    CONST_ERROR_MASK=ENUM_MEMBER_ERROR_ENUM
    CONST_ERROR_NAME=ENUM_MEMBER_ERROR_MASK
    CONST_ERROR_VALUE=ENUM_MEMBER_ERROR_ILLV
    add_const=add_enum_member
    del_const=del_enum_member
    get_const=get_enum_member
    get_const_bmask=get_enum_member_bmask
    get_const_by_name=get_enum_member_by_name
    get_const_cmt=get_enum_member_cmt
    get_const_enum=get_enum_member_enum
    get_const_name=get_enum_member_name
    get_const_serial=get_enum_member_serial
    get_const_value=get_enum_member_value
    get_first_const=get_first_enum_member
    get_first_serial_const=get_first_serial_enum_member
    get_last_const=get_last_enum_member
    get_last_serial_const=get_last_serial_enum_member
    get_next_const=get_next_enum_member
    get_next_serial_const=get_next_serial_enum_member
    get_prev_const=get_prev_enum_member
    get_prev_serial_const=get_prev_serial_enum_member
    set_const_cmt=set_enum_member_cmt
    set_const_name=set_enum_member_name
    def get_next_serial_enum_member(*args):
        serial, cid = args[0], args[1]
        if serial > 0xFF:
            serial, cid = cid, serial
        return _ida_enum.get_next_serial_enum_member(serial, cid)
    def get_prev_serial_enum_member(*args):
        serial, cid = args[0], args[1]
        if serial > 0xFF:
            serial, cid = cid, serial
        return _ida_enum.get_prev_serial_enum_member(serial, cid)

%}