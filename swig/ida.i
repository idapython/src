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

#ifdef BC695
  // Compat 6.95; since inf is a cvar, I can't just add properties to it..
  ea_t get_minEA() const { return $self->min_ea; }
  void set_minEA(ea_t ea) { $self->min_ea = ea; }
  ea_t get_maxEA() const { return $self->max_ea; }
  void set_maxEA(ea_t ea) { $self->max_ea = ea; }
  qstring get_procName() const { return $self->procname; }
#endif

  %pythoncode {
    abiname = property(get_abiname)
#ifdef BC695
    minEA = property(get_minEA, set_minEA)
    maxEA = property(get_maxEA, set_maxEA)
    procName = property(get_procName)
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
