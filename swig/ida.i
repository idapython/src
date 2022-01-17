// Ignore kernel-only symbols
%ignore idainfo::align_short_demnames;
%ignore idainfo::align_strtype;
%ignore idainfo::align_long_demnames;
%ignore idainfo::store_user_info;
%ignore idainfo::zero;
%ignore idainfo::padding;
%ignore idainfo::netdelta;
%ignore idainfo::privrange;
%ignore idainfo::padding2;
%ignore idainfo::idainfo;
%ignore idainfo::~idainfo;

%ignore inf_get_procname();
%ignore inf_get_strlit_pref();

%ignore hook_cb_t;
%ignore hook_type_t;
%ignore hook_to_notification_point;
%ignore unhook_from_notification_point;
%ignore invoke_callbacks;
%ignore post_event_visitor_t;
%ignore register_post_event_visitor;
%ignore unregister_post_event_visitor;

%ignore getinf;
%ignore getinf_buf;
%ignore getinf_flag;
%ignore setinf;
%ignore setinf_buf;
%ignore setinf_flag;

%extend idainfo
{
  qstring get_abiname()
  {
    qnotused($self);
    qstring buf;
    get_abi_name(&buf);
    return buf;
  }

  %pythoncode {
    abiname = property(get_abiname)
#ifdef MISSED_BC695
    minEA = ida_idaapi._make_missed_695bwcompat_property("minEA", "min_ea", has_setter=True)
    maxEA = ida_idaapi._make_missed_695bwcompat_property("maxEA", "max_ea", has_setter=True)
    procName = ida_idaapi._make_missed_695bwcompat_property("procName", "procname", has_setter=False)
#endif
  }
}

%ignore setflag(uchar &where,uchar bit,int value);
%ignore setflag(ushort &where,ushort bit,int value);
%ignore setflag(uint32 &where,uint32 bit,int value);

// Make idainfo::get_proc_name() work
%include "cstring.i"
%cstring_bounded_output(char *buf, 8);

%ignore BADADDR;
%ignore BADSEL;

%predefine_uint32_macro(AF_FINAL, 0x80000000);

%include "ida.hpp"

%clear(char *buf);

%pythoncode %{
#<pycode(py_ida)>
#</pycode(py_ida)>
%}
