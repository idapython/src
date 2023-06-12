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
%ignore idainfo::lflags;

%ignore inf_get_procname();
%ignore inf_get_strlit_pref();

%ignore ea_helper_t;
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
#ifdef NOTEAMS
%ignore idbattr_info_t;
%ignore idbattr_valmap_t;
#endif

%extend idainfo
{
  qstring get_abiname()
  {
    qnotused($self);
    qstring buf;
    get_abi_name(&buf);
    return buf;
  }

  uint32 _get_lflags() const { return $self->lflags; }
  void _set_lflags(uint32 _f)
  {
    const uint32 _was = $self->lflags;
#define _DEF_BITSET(Bit, Setter) if ( (_was & Bit) != (_f & Bit) ) Setter((_f & Bit) != 0);
    _DEF_BITSET(LFLG_PC_FPP, inf_set_decode_fpp);
    _DEF_BITSET(LFLG_PC_FLAT, inf_set_32bit);
    _DEF_BITSET(LFLG_64BIT, inf_set_64bit);
    _DEF_BITSET(LFLG_IS_DLL, inf_set_dll);
    _DEF_BITSET(LFLG_FLAT_OFF32, inf_set_flat_off32);
    _DEF_BITSET(LFLG_MSF, inf_set_be);
    _DEF_BITSET(LFLG_WIDE_HBF, inf_set_wide_high_byte_first);
    _DEF_BITSET(LFLG_DBG_NOPATH, inf_set_dbg_no_store_path);
    _DEF_BITSET(LFLG_SNAPSHOT, inf_set_snapshot);
    _DEF_BITSET(LFLG_PACK, inf_set_pack_idb);
    _DEF_BITSET(LFLG_COMPRESS, inf_set_compress_idb);
    _DEF_BITSET(LFLG_KERNMODE, inf_set_kernel_mode);
#undef _DEF_BITSET
  }

  %pythoncode {
    abiname = property(get_abiname)
    lflags = property(_get_lflags, _set_lflags)
#ifdef MISSED_BC695
    minEA = ida_idaapi._make_missed_695bwcompat_property("minEA", "min_ea", has_setter=True)
    maxEA = ida_idaapi._make_missed_695bwcompat_property("maxEA", "max_ea", has_setter=True)
    procName = ida_idaapi._make_missed_695bwcompat_property("procName", "procname", has_setter=False)
#endif
  }
}

%apply size_t { uintptr_t offset }

%extend idbattr_info_t
{
  idbattr_info_t(
          const char *name,
          uintptr_t offset,
          size_t width,
          uint64 bitmask=0,
          uchar tag=0,
          uint idi_flags=0)
  {
    idbattr_info_t *ii = new idbattr_info_t();
    ii->name = nullptr;
    if ( name != nullptr )
    {
      // mimick SWiG's `new`-based string allocation
      size_t len = strlen(name) + 1;
      ii->name = (char *) memcpy(new char[len], name, len);
    }
    ii->offset = offset;
    ii->width = width;
    ii->bitmask = bitmask;
    ii->tag = tag;
    ii->idi_flags = idi_flags;
    return ii;
  }

  ~idbattr_info_t()
  {
    delete [] $self->name;
    $self->name = nullptr;
    delete $self;
  }
};

%ignore setflag(uchar &where,uchar bit,int value);
%ignore setflag(ushort &where,ushort bit,int value);
%ignore setflag(uint32 &where,uint32 bit,int value);

/* // `config.hpp` - note: ideally, this should be in its own module, */
/* // but it might be an overkill to have an `ida_config` module for */
/* // just one function (as of this writing in any case.) */
/* %ignore cfgopt_t; */
/* %ignore cfgopt_t::params_t; */
/* %ignore cfgopt_t::num_range_t; */
/* %ignore read_config; */
/* %ignore read_config2; */
/* %ignore read_config_file; */
/* %ignore read_config_file2; */
/* %ignore read_config_string; */
/* %ignore register_cfgopts; */
/* %ignore parse_config_value; */
/* %ignore cfgopt_t__apply; */
/* %ignore cfgopt_t__apply2; */
/* %ignore cfgopt_t__apply3; */
/* %ignore cfgopt_set_t; */
/* %ignore cfgopt_set_vec_t; */

// Make idainfo::get_proc_name() work
%include "cstring.i"
%cstring_bounded_output(char *buf, 8);

%ignore BADADDR;
%ignore BADSEL;

%predefine_uint32_macro(AF_FINAL, 0x80000000);

%include "ida.hpp"
/* %include "config.hpp" */

%clear(char *buf);

%pythoncode %{
#<pycode(py_ida)>
#</pycode(py_ida)>
%}
