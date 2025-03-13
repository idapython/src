%{
#include <typeinf.hpp>
%}

%constant bmask64_t DEFMASK64 = bmask64_t(-1);

// Most of these could be wrapped if needed
%ignore get_cc;
%ignore get_effective_cc;
%ignore ::use_golang_abi;
%ignore get_cc_type_size;
%ignore get_de;
%ignore skip_ptr_type_header;
%ignore skip_array_type_header;
%ignore pack_object_to_idb;
%ignore typend;
%ignore typlen;
%ignore typncpy;
%ignore tppncpy;
%ignore typcmp;
%ignore typdup;
%ignore get_int_type_bit;
%ignore get_unk_type_bit;
%ignore tns;
%ignore get_frame_var;
%ignore tinfo_get_func_frame;

%ignore til_t::syms;
%ignore til_t::types;
%ignore til_t::macros;

%ignore add_base_tils;
%ignore sort_til;
%ignore til_add_macro;
%ignore til_next_macro;

%ignore parse_subtype;

%ignore descr_t;

%ignore show_type;
%ignore show_plist;
%ignore show_bytes;
%ignore skip_function_arg_names;
%ignore perform_funcarg_conversion;
%ignore get_argloc_info;
%ignore argloc_t::dstr;
%ignore argloc_t::consume_scattered(scattered_aloc_t *p);
%ignore argloc_t::scattered() const;
%ignore argloc_t::get_rrel() const;
%ignore argpart_t::copy_from;

%ignore get_idainfo_by_type(size_t *,flags64_t *,opinfo_t *,tinfo_t const &);

// because default args!
%ignore ::get_numbered_type(const til_t *, uint32, const type_t **, const p_list **, const char **, const p_list **, sclass_t *);
%ignore ::get_numbered_type(const til_t *, uint32, const type_t **, const p_list **, const char **, const p_list **);
%ignore ::get_numbered_type(const til_t *, uint32, const type_t **, const p_list **, const char **);
%ignore ::get_numbered_type(const til_t *, uint32, const type_t **, const p_list **);
%ignore ::get_numbered_type(const til_t *, uint32, const type_t **);
%ignore ::get_numbered_type(const til_t *, uint32);
%ignore tinfo_t::get_innermost_udm(uint64, size_t *) const;
%ignore tinfo_t::get_innermost_udm(uint64) const;
%ignore tinfo_t::get_innermost_member_type(uint64) const;
%rename (get_numbered_type) py_get_numbered_type;

%ignore NTF_NOSYNC;

%ignore skipName;
%ignore extract_comment;
%ignore skipComment;
%ignore extract_fargcmt;
%ignore skip_argloc;

%ignore h2ti;
%ignore h2ti_warning;
// We want to handle 'get_named_type()' in a special way,
// but not tinfo_t::get_named_type().
//  http://stackoverflow.com/questions/27417884/how-do-i-un-ignore-a-specific-method-on-a-templated-class-in-swig
%ignore get_named_type;
%rename (get_named_type) py_get_named_type;
%ignore get_named_type64;
%rename (get_named_type64) py_get_named_type64;
%rename ("%s") tinfo_t::get_named_type;

%ignore set_numbered_type;
%rename (set_numbered_type) py_set_numbered_type;
%rename ("%s") tinfo_t::set_numbered_type;

%rename (print_decls) py_print_decls;
%ignore print_decls;

// let's get rid of this one, without prohibiting tinfo_t::set_named_type()
%ignore set_named_type(
        til_t *,
        const char *,
        int,
        const type_t *,
        const p_list *,
        const char *,
        const p_list *,
        const sclass_t *,
        const uint32 *);
%ignore get_named_type_size;

%ignore decorate_name;
%ignore calc_bare_name3;
%ignore tinfo_predicate_t;
%ignore local_tinfo_predicate_t;
%ignore get_default_align;
%ignore align_size;
%ignore align_size;
%ignore fix_type_align;
%ignore get_arg_align;
%ignore align_stkarg_up;
%ignore get_default_enum_size;
%ignore max_ptr_size;
%ignore based_ptr_name_and_size;

%ignore apply_callee_type;
%ignore get_arg_addrs;
%rename (get_arg_addrs) py_get_arg_addrs;

%ignore calc_names_cmts;
%ignore idb_type_to_til;
%ignore get_idb_type;

%ignore calc_type_size;
%rename (calc_type_size) py_calc_type_size;
%ignore apply_type;
%rename (apply_type) py_apply_type;

%ignore use_regarg_type_cb;
%ignore is_stkarg_load_t;
%ignore has_delay_slot_t;
%ignore gen_use_arg_types;
%ignore compact_numbered_types;

%ignore callregs_t::findreg;

%ignore format_data_info_t;
%ignore valinfo_t;
%ignore print_cdata;
%ignore format_cdata;
%ignore format_c_number;
%ignore extend_sign;

// Kernel-only symbols
%ignore build_anon_type_name;
%ignore bitfield_type_data_t::serialize;
%ignore func_type_data_t::serialize;
%ignore func_type_data_t::deserialize;
%ignore name_requires_qualifier;
%ignore tinfo_visitor_t::level;
%ignore tinfo_t::serialize(qtype *, qtype *, qtype *, int) const;
%ignore tinfo_t::get_stkvar(sval_t *, const insn_t &, const op_t *, sval_t);
%ignore tinfo_t::deserialize(const til_t *, const qtype *, const qtype *, const qtype *, const char *);
%ignore tinfo_get_innermost_udm;
%ignore save_tinfo2;

// Let's declare our own version of `deserialize_tinfo` before
// SWiG hits the one that's in `typeinf.hpp` (and cannot, alas,
// enjoy the addition of the default value.)
%inline %{
idaman bool ida_export deserialize_tinfo(tinfo_t *tif, const til_t *til, const type_t **ptype, const p_list **pfields, const p_list **pfldcmts, const char *cmt=nullptr);
%}
%ignore deserialize_tinfo;
%ignore get_udm_by_tid(tinfo_t *tif, udm_t *udm, tid_t tid);
%ignore get_edm_by_tid(tinfo_t *tif, edm_t *edm, tid_t tid);
%ignore get_type_by_tid(tinfo_t *tif, tid_t tid);
%ignore get_tinfo_by_edm_name(tinfo_t *tif, til_t *til, const char *mname);
%ignore get_frame_var(tinfo_t *tif, sval_t *actval, const insn_t &insn, const op_t &x, sval_t v);
%ignore value_repr_t__parse_value_repr;
%ignore enum_type_data_t__get_value_repr;
%ignore enum_type_data_t__set_value_repr;
%ignore enum_type_data_t__get_max_serial;
%ignore enum_type_data_t::get_constant_group(size_t *, size_t *, size_t);
%ignore get_tinfo_tid;

%ignore custloc_desc_t;
%ignore install_custom_argloc;
%ignore remove_custom_argloc;
%ignore retrieve_custom_argloc;
%ignore enum_type_visitor_t;
%ignore visit_edms;

%make_argout_errbuf_raise_when_null_result();

%{
//<code(py_typeinf)>
//</code(py_typeinf)>
%}

%extend argloc_t {
  void consume_scattered(const scattered_aloc_t &p)
  {
    $self->consume_scattered(new scattered_aloc_t(p));
  }
}

%extend til_t {

  til_t *base(int n)
  {
    return (n < 0 || n >= $self->nbases) ? nullptr : $self->base[n];
  }

  bool operator==(const til_t *r)
  {
    return $self == r;
  }

  bool operator!=(const til_t *r)
  {
    return $self != r;
  }

  tinfo_t import_type(const tinfo_t &src)
  {
    tinfo_t tif;
    if ( !src.empty() )
    {
      qstring src_name;
      if ( src.get_type_name(&src_name) )
      {
        const til_t *src_til = src.get_til();
        if ( src_til != nullptr )
        {
          uint32 ord = copy_named_type($self, src_til, src_name.c_str());
          if ( ord != 0 )
            tif.get_numbered_type($self, ord);
        }
      }
    }
    return tif;
  }

    %pythoncode {
        def named_types(self):
            for name in self.type_names:
                tif = tinfo_t() # a new type. Always
                if tif.get_named_type(self, name):
                    yield tif

        def numbered_types(self):
            for ord in range(1, get_ordinal_limit(self)):
                tif = tinfo_t() # a new type. Always
                if tif.get_numbered_type(self, ord):
                    yield tif

        def get_named_type(self, name):
            tif = tinfo_t()
            if tif.get_named_type(self, name):
                return tif

        def get_numbered_type(self, ordinal):
            tif = tinfo_t()
            if tif.get_numbered_type(self, ordinal):
                return tif

        def get_type_names(self):
            n = first_named_type(self, NTF_TYPE)
            while n:
                yield n
                n = next_named_type(self, n, NTF_TYPE)

        type_names = property(get_type_names)
    }
}

//-------------------------------------------------------------------------
%extend tinfo_t {

  PyObject *serialize(
          int sudt_flags=SUDT_FAST|SUDT_TRUNC) const
  {
    return py_tinfo_t_serialize($self, sudt_flags);
  }

  bool deserialize(
          const til_t *til,
          const type_t *type,
          const p_list *fields,
          const p_list *cmts = nullptr)
  {
    return $self->deserialize(til, &type, &fields, cmts == nullptr ? nullptr : &cmts);
  }

  ssize_t get_stkvar(
          const insn_t &insn,
          const op_t x,
          sval_t v)
  {
    return ::get_frame_var($self, nullptr, insn, &x, v);
  }

  tinfo_t copy() const
  {
    return *$self;
  }

  qstring __str__() const
  {
    qstring qs;
    $self->print(&qs);
    return qs;
  }
}

%apply size_t *OUTPUT {size_t *out_index};
%apply uint64 *OUTPUT {uint64 *out_bitoffset};

//---------------------------------------------------------------------
%define %tinfo_t_or_simple_tinfo_t_container_lifecycle(Type)
// Instead of re-defining all constructors, add the registering
// to a specialized 'ret' typemap
%typemap(ret) Type* Type::Type
{
  // %typemap(ret) Type* Type::Type
  til_register_python_##Type##_instance($1);
}
%extend Type {
  ~Type(void)
  {
    til_deregister_python_##Type##_instance($self);
    delete $self;
  }
}
%enddef

%tinfo_t_or_simple_tinfo_t_container_lifecycle(ptr_type_data_t);
%tinfo_t_or_simple_tinfo_t_container_lifecycle(array_type_data_t);
%tinfo_t_or_simple_tinfo_t_container_lifecycle(func_type_data_t);
%tinfo_t_or_simple_tinfo_t_container_lifecycle(udt_type_data_t);

// We can't use tinfo_t_or_simple_tinfo_t_container_lifecycle() for tinfo_t,
// as it would call til_register_python_tinfo_t_instance() a second time
// after '%typemap(out) tinfo_t *' already did it.
%extend tinfo_t {
  ~tinfo_t()
  {
    til_deregister_python_tinfo_t_instance($self);
    delete $self;
  }
}

%ignore tinfo_t::~tinfo_t();

%template(funcargvec_t)      qvector<funcarg_t>;
%template(reginfovec_t)      qvector<reg_info_t>;
%template(edmvec_t)          qvector<edm_t>;
%template(argpartvec_t)      qvector<argpart_t>;
%uncomparable_elements_qvector(valstr_t, valstrvec_t);
%uncomparable_elements_qvector(regobj_t, regobjvec_t);
%uncomparable_elements_qvector(type_attr_t, type_attrs_t);

%extend value_repr_t
{
  inline qstring __str__() const { qstring tmp; $self->print(&tmp); return tmp; }
}
%template(udtmembervec_template_t) qvector<udm_t>;
%ignore udt_type_data_t::VERSION;
%ignore udt_type_data_t::get_best_fit_member(asize_t) const;

%feature("shadow") tinfo_t::tinfo_t %{
def __init__(self, *args, ordinal=None, name=None, tid=None, til=None):
    _ida_typeinf.tinfo_t_swiginit(self, _ida_typeinf.new_tinfo_t(*args))
    if args and self.empty():
        raise ValueError("Invalid input data: %s" % str(args))
    elif ordinal is not None:
        if not self.get_numbered_type(til, ordinal):
            raise ValueError("No type with ordinal %s in type library %s" % (ordinal, til))
    elif name is not None:
        if not self.get_named_type(til, name):
            raise ValueError("No type with name %s in type library %s" % (name, til))
    elif tid is not None:
        if not self.get_type_by_tid(tid):
            raise ValueError("No type with ID %s in type library %s" % (name, til))
%}

// We want to make it possible to support both:
//   tinfo_t::get_edm(size_t idx)
//   tinfo_t::get_edm(edm_t *out, size_t idx)
// but to do that, we cannot just apply an out typemap to `edm_t *`:
// SWiG will collapse the 2 methods into 1. So we resort to a
// made-up type!
%inline %{
  typedef edm_t out_edm_t;
%}

%typemap(in,numinputs=0) out_edm_t *out_edm (out_edm_t temp)
{
  // %typemap(in,numinputs=0) out_edm_t *out_edm (out_edm_t temp)
  $1 = &temp;
}
%typemap(argout) out_edm_t *out_edm
{
  // %typemap(argout) out_edm_t *out_edm
  if ( result > -1 )
  {
    PyObject *py_edm = SWIG_NewPointerObj(new out_edm_t(*($1)), $1_descriptor, SWIG_POINTER_OWN | 0);
    $result = SWIG_Python_AppendOutput($result, py_edm, /*is_void=*/ 1);
  }
  else
  {
    Py_INCREF(Py_None);
    $result = SWIG_Python_AppendOutput($result, Py_None, /*is_void=*/ 1);
  }
}
%typemap(freearg) out_edm_t *out_edm
{
  // %typemap(freearg) out_edm_t *out_edm
  // Nothing. We certainly don't want 'temp' to be deleted.
}

%extend tinfo_t {
  PyObject *get_attr(const qstring &key, bool all_attrs=true)
  {
    bytevec_t bv;
    if ( $self->get_attr(key, &bv, all_attrs) )
      return PyUnicode_FromStringAndSize((const char *) bv.begin(), bv.size());
    else
      Py_RETURN_NONE;
  }

  int get_edm(out_edm_t *out_edm, size_t idx) const
  {
    tinfo_code_t rc = $self->get_edm((edm_t *) out_edm, idx);
    return rc == TERR_OK ? idx : -1;
  }

  // bw-compat
  ssize_t find_edm(edm_t *edm, uint64 value, bmask64_t bmask=DEFMASK64, uchar serial=0) const
  { return $self->get_edm_by_value(edm, value, bmask, serial); }

  // bw-compat
  ssize_t find_edm(edm_t *edm, const char *name) const
  { return $self->get_edm(edm, name); }

  %pythoncode {

    def __repr__(self):
        if self.present():
            til = self.get_til()
            if til == get_idati():
                name = self.get_type_name()
                if name:
                    return f'{self.__class__.__module__}.{self.__class__.__name__}(get_idati(), "{name}")'
                else:
                    ord = self.get_ordinal()
                    if ord > 0:
                        return f'{self.__class__.__module__}.{self.__class__.__name__}(get_idati(), {ord})'
            return f'{self.__class__.__module__}.{self.__class__.__name__}("""{self._print()}""")'
        return f'{self.__class__.__module__}.{self.__class__.__name__}()'

    def iter_struct(self):
        udt = udt_type_data_t()
        if not self.is_struct() or not self.get_udt_details(udt):
            raise TypeError("Type is not a structure")
        for udm in udt:
            yield udm_t(udm)


    def iter_union(self):
        udt = udt_type_data_t()
        if not self.is_union() or not self.get_udt_details(udt):
            raise TypeError("Type is not a union")
        for udm in udt:
            yield udm_t(udm)

    def iter_udt(self):
        udt = udt_type_data_t()
        if not self.is_udt() or not self.get_udt_details(udt):
            raise TypeError("Type is not a structure or union")
        for udm in udt:
            yield udm_t(udm)

    def iter_enum(self):
        edt = enum_type_data_t()
        if not self.is_enum() or not self.get_enum_details(edt):
            raise TypeError("Type is not a structure")
        for edm in edt:
            yield edm_t(edm)

    def iter_func(self):
        fdt = func_type_data_t()
        if not self.is_func() or not self.get_func_details(fdt):
            raise TypeError("Type is not a function")
        for arg in fdt:
            yield funcarg_t(arg)

    get_edm_by_name = get_by_edm_name # bw-compat
  }
}
%ignore tinfo_t::get_attr;

%extend enum_type_data_t
{
  // \ref enum_type_data_t::get_constant_group but return tupple (group_start_index, group_size)
  PyObject *get_constant_group(size_t idx) const
  {
    size_t group_start_index;
    size_t group_size;
    if ( $self->get_constant_group(&group_start_index, &group_size, idx) )
      return Py_BuildValue("(nn)", group_start_index, group_size);
    else
      Py_RETURN_NONE;
  }

  %pythoncode {
    def all_groups(self, skip_trivial=False):
        """
        Generate tuples for bitmask enum groups.
        Each tupple is:
        [0] enum member index of group start
        [1] group size
        Tupples may include or not the group with 1 element.
        """
        if len(self.group_sizes) != 0 and self.is_valid_group_sizes():
            grp_start = 0
            for grp_size in self.group_sizes:
                if not skip_trivial or grp_size != 1:
                    yield (grp_start, grp_size)
                grp_start += grp_size
            return None


    def all_constants(self):
        """
        Generate tupples of all constants except of bitmasks.
        Each tupple is:
        [0] constant index
        [1] enum member index of group start
        [2] group size
        In case of regular enum the second element of tupple is 0 and the third element of tupple is the number of enum members.
        """
        if len(self.group_sizes) != 0:  # bitmask enum
            for (grp_start, grp_size) in self.all_groups():
                grp_end = grp_start + grp_size
                if grp_size != 1:
                    grp_start += 1
                for idx in range(grp_start, grp_end):
                    yield (idx, grp_start, grp_size)
        else: # regular enum
            sz = self.size()
            for idx in range(0, sz):
                yield (idx, 0, sz)
        return None
  }
}

%feature("director") predicate_t;

%ignore remove_tinfo_pointer;
%rename (remove_tinfo_pointer) py_remove_tinfo_pointer;

%cstring_output_buf_and_size_returning_charptr(
        2,
        ea_t ea,
        char *buf,
        size_t bufsize); // idc_guess_type, idc_get_type

// set_numbered_type()
%typemap(in) const sclass_t * {
  // %typemap(in) const sclass_t *
  if ( $input == Py_None )
    $1 = new sclass_t(SC_UNK);
  else if ( PyLong_Check($input) )
    $1 = new sclass_t(sclass_t(PyLong_AsLong($input)));
  else
    SWIG_exception_fail(
            SWIG_ValueError,
            "invalid argument " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) const sclass_t * {
  // %typemap(typecheck,precedence=SWIG_TYPECHECK_POINTER) const sclass_t *
  $1 = ($input == Py_None || PyLong_Check($input)) ? 1 : 0;
}

%typemap(freearg) const sclass_t * {
  // %typemap(freearg) const sclass_t *
  delete $1;
}

//-------------------------------------------------------------------------
%feature("pythonappend") udm_t::udm_t %{
    if args and self.empty():
        raise ValueError("Invalid input data: %s" % str(args))
%}

%feature("pythonappend") funcarg_t::funcarg_t %{
    if args and self.type.empty():
        raise ValueError("Invalid input data: %s" % str(args))
%}

%feature("pythonappend") tinfo_t::add_udm %{
    if val != 0:
        raise ValueError("Invalid input data: %s" % tinfo_errstr(val))
%}

%feature("pythonappend") tinfo_t::add_edm %{
    if val != 0:
        raise ValueError("Invalid input data: %s" % tinfo_errstr(val))
%}

%include "typeinf.hpp"

%extend udm_t {

  udm_t(const udm_t &r)
  {
    return new udm_t(r);
  }
}

%extend edm_t {

  edm_t(const edm_t &r)
  {
    return new edm_t(r);
  }
}

%extend funcarg_t {

  funcarg_t(const funcarg_t &r)
  {
    return new funcarg_t(r);
  }
}

// Custom wrappers

%rename (idc_get_type_raw) py_idc_get_type_raw;
%rename (idc_get_local_type_raw) py_idc_get_local_type_raw;
%rename (unpack_object_from_idb) py_unpack_object_from_idb;
%rename (unpack_object_from_bv) py_unpack_object_from_bv;
%rename (pack_object_to_idb) py_pack_object_to_idb;
%rename (pack_object_to_bv) py_pack_object_to_bv;
%inline %{
//<inline(py_typeinf)>
//</inline(py_typeinf)>
%}

%cstring_output_maxsize(char *buf, size_t maxsize);

%pythoncode %{
#<pycode(py_typeinf)>
#</pycode(py_typeinf)>
%}
