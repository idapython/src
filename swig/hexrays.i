%{
#undef HEXDSP
hexdsp_t *get_idapython_hexdsp();
#define HEXDSP get_idapython_hexdsp()
#include <hexrays.hpp>
%}

%{
SWIGINTERN void __raise_vdf(const vd_failure_t &e)
{
  PyErr_SetString(PyExc_RuntimeError, e.desc().c_str());
}
%}

%force_declare_SWiG_type(TPopupMenu);

//---------------------------------------------------------------------
// SWIG bindings for Hexray Decompiler's hexrays.hpp
//
// Author: EiNSTeiN_ <einstein@g3nius.org>
// Copyright (C) 2013 ESET
//
// Integrated into IDAPython project by the IDAPython Team <idapython@googlegroups.com>
//---------------------------------------------------------------------

#define _STD_BEGIN

#ifdef __NT__
%include <windows.i>
#endif

%typemap(check) ctype_t cexpr_op {
  // %typemap(check) ctype_t cexpr_op
  if ( $1 < cot_empty || $1 > cot_last )
    SWIG_exception_fail(SWIG_ValueError, "invalid op " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%typemap(check) const tinfo_t *type {
  // %typemap(check) const tinfo_t *type
}

%define %define_hexrays_lifecycle_object(TypeName)
%feature("ref") TypeName
{
  hexrays_register_python_clearable_instance($this, hxclr_##TypeName);
}
%feature("unref") TypeName
{
  hexrays_deregister_python_clearable_instance($this);
  delete $this;
}
%extend TypeName {
  void _register() { hexrays_register_python_clearable_instance($self, hxclr_##TypeName); }
  void _deregister() { hexrays_deregister_python_clearable_instance($self); }
}
%enddef

%define %method_sets_type_and_gains_ownership_of_regular_object_argument(TYPE, METHOD)
%feature("pythonprepend") TYPE::METHOD %{
    o = args[0]
    self._ensure_cond(self.t == mop_z, "self.t == mop_z")
%}
%feature("pythonappend") TYPE::METHOD %{
    self._acquire_ownership(o, True)
%}
%enddef

%typemap(directorin) (const char *format, ...)
{
  // %typemap(directorin) (const char *format, ...)
  // AFAICT we should only ever be called from C++, so we can assume
  // 'format' is followed with actual parameters, should it require them.
  qstring $input_buf;
  va_list $input_va;
  va_start($input_va, format);
  $input_buf.vsprnt(format, $input_va);
  va_end($input_va);
  $input = SWIG_Python_str_FromChar($input_buf.c_str());
}

%ignore string_printer_t::vprint;
%ignore vdui_t::vdui_t;
%ignore cblock_t::find;
%ignore citem_t::op;
%ignore cfunc_t::cfunc_t;
%ignore cfunc_t::sv;         // lazy member. Use get_pseudocode() instead
%ignore cfunc_t::boundaries; // lazy member. Use get_boundaries() instead
%ignore cfunc_t::eamap;      // lazy member. Use get_eamap() instead
%ignore cfunc_t::reserved;
%ignore ctree_item_t::verify;
%ignore ccases_t::find_value;
%ignore ccases_t::print;
%ignore ccase_t::set_insn;
%ignore ccase_t::print;
%ignore carglist_t::print;
%ignore cblock_t::remove_gotos;
%ignore casm_t::genasm;
%ignore cblock_t::use_curly_braces;
%ignore casm_t::print;
%ignore cgoto_t::print;
%ignore cexpr_t::is_aliasable;
%ignore cexpr_t::like_boolean;
%ignore cexpr_t::contains_expr;
%ignore cexpr_t::contains_expr;
%ignore cexpr_t::cexpr_t(mba_t *mba, const lvar_t &v);
%ignore cexpr_t::is_type_partial;
%ignore cexpr_t::set_type_partial;
%ignore cexpr_t::is_value_used;
%ignore lvar_t::is_promoted_arg;
%ignore lvar_t::lvar_t;
%ignore lvar_t::is_partialy_typed;
%ignore lvar_t::set_partialy_typed;
%ignore lvar_t::clr_partialy_typed;
%ignore lvar_t::force_lvar_type;
%ignore vdloc_t::is_fpu_mreg;
%ignore strtype_info_t::find_strmem;
%ignore file_printer_t::_print;
%ignore file_printer_t;
%ignore qstring_printer_t::qstring_printer_t(const cfunc_t *, qstring &, bool);
%rename (_replace_by) cinsn_t::replace_by;
%rename (_replace_by) cexpr_t::replace_by;
%ignore vcall_helper;
%ignore vcreate_helper;
%ignore term_hexrays_plugin;
%rename (term_hexrays_plugin) py_term_hexrays_plugin;
%rename (debug_hexrays_ctree) py_debug_hexrays_ctree;
%ignore vd_interr_t::vd_interr_t(ea_t, const qstring &);

%ignore bitset_t::print;
%ignore bitset_t::extract;
%ignore bitset_t::fill_gaps;
%template(array_of_bitsets) qvector<bitset_t>;

%ignore ivl_t::print;
%ignore ivl_t::allmem;

%ignore mlist_t::has_allmem;

%ignore mba_t::mba_t;
%ignore mba_t::reserved;
%ignore mba_t::vdump_mba;
%ignore mba_t::idaloc2vd(const argloc_t &, int, sval_t);
%ignore mba_t::idaloc2vd(const mba_t *, const argloc_t &, int);
%ignore mba_t::range_contains;
%ignore mba_t::get_stkvar;

%feature("nodirector") codegen_t;
%ignore codegen_t::reserved;

%feature("nodirector") simple_graph_t;
%ignore simple_graph_t::simple_graph_t;
%ignore simple_graph_t::~simple_graph_t;

%feature("nodirector") mbl_graph_t;
%ignore mbl_graph_t::mbl_graph_t;
%ignore mbl_graph_t::~mbl_graph_t;

%define_hexrays_lifecycle_object(minsn_t);
%ignore minsn_t::find_ins_op(const mop_t **, mcode_t) const;
%ignore minsn_t::find_num_op(const mop_t **) const;
%ignore minsn_t::set_combined;

%define_hexrays_lifecycle_object(mop_t);
%ignore mop_t::_make_strlit(qstring *);
%template(mopvec_t) qvector<mop_t>;
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_cases)
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_callinfo)
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_pair)
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_insn)

%template(mcallargs_t) qvector<mcallarg_t>;

%uncomparable_elements_qvector(block_chains_t, block_chains_vec_t);

%ignore mblock_t::mblock_t;
%ignore mblock_t::find_first_use(mlist_t *, const minsn_t *, const minsn_t *, maymust_t) const;
%ignore mblock_t::find_redefinition(const mlist_t &, const minsn_t *, const minsn_t *, maymust_t) const;
%ignore mblock_t::reserved;
%ignore mblock_t::vdump_block;
// Note: we cannot use %delobject here, as that would disown
// the block itself, not the instruction.
%feature("pythonappend") mblock_t::insert_into_block %{
    mn = args[0]
    mn._maybe_disown_and_deregister()
%}
// Note: we could be using %newobject here, but for the sake of
// symmetry with 'insert_into_block', let's go with "pythonappend".
%feature("pythonprepend") mblock_t::remove_from_block %{
    mn = args[0]
%}
%feature("pythonappend") mblock_t::remove_from_block %{
    if mn:
      mn._own_and_register()
%}
%feature("nodirector") mblock_t;
%extend mblock_t {
   %pythoncode {
     def preds(self):
         """
         Iterates the list of predecessor blocks
         """
         for ser in self.predset:
             yield self.mba.get_mblock(ser)

     def succs(self):
         """
         Iterates the list of successor blocks
         """
         for ser in self.succset:
             yield self.mba.get_mblock(ser)
   }
};

%extend mba_t {
   %pythoncode {
     """
     Deprecated. Please do not use.
     """
     idb_node = property(lambda self: self.deprecated_idb_node)
   }
};

%ignore op_parent_info_t::really_alloc;

%ignore getf_reginsn(const minsn_t *);
%ignore getb_reginsn(const minsn_t *);
%ignore lvar_t::dstr;
%ignore lvar_locator_t::dstr;
%ignore fnumber_t::dstr;
%ignore range_item_iterator_t;
%ignore mba_item_iterator_t;
%ignore range_chunk_iterator_t;
%ignore mba_ranges_t::range_contains;

%newobject gen_microcode;
%define_hexrays_lifecycle_object(mba_t);
%const_void_pointer_and_size(uchar, bytes, nbytes);
%const_void_pointer_and_size(void, bytes, _size);

%define_hexrays_lifecycle_object(valrng_t);
%apply uint64 *OUTPUT { uvlr_t *v };    // valrng_t::cvt_to_single_value
%apply uint64 *OUTPUT { uvlr_t *val };  // valrng_t::cvt_to_cmp
%apply int    *OUTPUT { cmpop_t *cmp }; // valrng_t::cvt_to_cmp

%define %def_opt_handler(TypeName, Install, Remove, Hxclr)
%ignore Install;
%ignore Remove;
%ignore Hxclr;
%extend TypeName {
    void install()
    {
        hexrays_register_python_clearable_instance($self, Hxclr);
        Install($self);
    }
    bool remove()
    {
        hexrays_deregister_python_clearable_instance($self);
        return Remove($self);
    }
    ~TypeName()
    {
      hexrays_deregister_python_clearable_instance($self);
      Remove($self);
      delete $self;
    }
};
%enddef
%def_opt_handler(optinsn_t, install_optinsn_handler, remove_optinsn_handler, hxclr_optinsn_t)
%def_opt_handler(optblock_t, install_optblock_handler, remove_optblock_handler, hxclr_optblock_t)
%def_opt_handler(udc_filter_t, install_udc_filter, remove_udc_filter, hxclr_udc_filter_t)

// udc_filter_t::init() will create a tinfo_t from the user-provided
// declaration. We must also ensure the instance is registered
// even if only init() is called (but install() isn't)
%extend udc_filter_t {
    bool init(const char *decl)
    {
        const bool ok = $self->init(decl);
        if ( ok )
            hexrays_register_python_clearable_instance($self, hxclr_udc_filter_t);
        return ok;
    }
};


// "Warning 473: Returning a pointer or reference in a director method is not recommended."
%warnfilter(473) codegen_t::emit_micro_mvm;

%apply uchar { char ignore_micro };
%feature("nodirector") udc_filter_t::apply;

// The following must:
//  - transfer ownership to the result object, if the argument object had it
//    That's because we don't know when one of those functions create
//    a new object under the hood
%rename (_ll_lnot) lnot;
%rename (_ll_make_ref) make_ref;
%rename (_ll_dereference) dereference;

// The following must:
//  - mark new object as being owned
//  - disown the 'args' object passed as parameter
%rename (_ll_call_helper) call_helper;

// The following must:
//  - mark new object as being owned
%rename (_ll_new_block) new_block;
%rename (_ll_make_num) make_num;
%rename (_ll_create_helper) create_helper;

%delobject create_cfunc;

%fragment("cvt_cfunc_t", "header")
{
  int cvt_cfunc_t(cfunc_t **out, PyObject *obj)
  {
    cfunc_t *cfunc = 0;
    int res = SWIG_ConvertPtr(obj, (void **) &cfunc, SWIGTYPE_p_cfunc_t, 0 | 0);
    if ( SWIG_IsOK(res) )
    {
      *out = cfunc;
    }
    else
    {
      cfuncptr_t *cfuncptr = 0;
      res = SWIG_ConvertPtr(obj, (void **) &cfuncptr, SWIGTYPE_p_qrefcnt_tT_cfunc_t_t, 0 | 0);
      if ( SWIG_IsOK(res) )
        *out = *cfuncptr;
    }
    return res;
  }
}

%typemap(typecheck, fragment="cvt_cfunc_t", precedence=SWIG_TYPECHECK_POINTER) cfunc_t * {
  // %typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) cfunc_t *
  cfunc_t *cfunc = nullptr;
  const int res$argnum = cvt_cfunc_t(&cfunc, $input);
  _v = SWIG_CheckState(res$argnum);
}

%typemap(in, fragment="cvt_cfunc_t") cfunc_t * {
  // %typemap(in, fragment="cvt_cfunc_t") cfunc_t *
  int res$argnum = cvt_cfunc_t(&$1, $input);
  if ( !SWIG_IsOK(res$argnum) )
    SWIG_exception_fail(SWIG_ArgError(res$argnum), "in method '$symname', argument $argnum of type $1_type");
}

%extend cfunc_t {
    %immutable argidx;

   PyObject *find_item_coords(const citem_t *item)
   {
     int px = 0;
     int py = 0;
     if ( $self->find_item_coords(item, &px, &py) )
       return Py_BuildValue("(ii)", px, py);
     else
       return Py_BuildValue("(OO)", Py_None, Py_None);
   }

   qstring __str__() const {
     qstring qs;
     qstring_printer_t p($self, qs, 0);
     $self->print_func(p);
     return qs;
   }
};

%ignore qstring_printer_t::qstring_printer_t(const cfunc_t *, qstring &, bool);
%ignore qstring_printer_t::~qstring_printer_t();

%extend qstring_printer_t {

   qstring_printer_t(const cfunc_t *f, bool tags);
   ~qstring_printer_t();

   qstring get_s() {
     return $self->s;
   }

   %pythoncode {
     s = property(lambda self: self.get_s())
   }
};

%rename(dereference_uint16) operator uint16*;
%rename(dereference_const_uint16) operator const uint16*;

// Provide trivial std::map facade so basic operations are available.
template<class key_type, class mapped_type> class std::map {
public:
    mapped_type& at(const key_type& _Keyval);
    size_t size() const;
};

//-------------------------------------------------------------------------
%define %monitored_lifecycle_object_t(TypeName)
%extend TypeName {

    int __dbg_get_registered_kind() const
    {
      return hexrays_is_registered_python_clearable_instance(self);
    }

    PyObject *_obj_id() const { return PyLong_FromSize_t(size_t(self)); }

    %pythoncode {
      obj_id = property(_obj_id)

      def _ensure_cond(self, ok, cond_str):
          if not ok:
              raise Exception("Condition \"%s\" not verified" % cond_str)
          return True

      def _ensure_no_obj(self, o, attr, attr_is_acquired):
          if attr_is_acquired and o is not None:
              raise Exception("%s already owns attribute \"%s\" (%s); cannot be modified" % (self, attr, o))
          return True

      def _ensure_ownership_transferrable(self, v):
          if not v.thisown:
              raise Exception("%s is already owned, and cannot be reused" % v)

      def _acquire_ownership(self, v, acquire):
          if acquire and (v is not None) and not isinstance(v, ida_idaapi.integer_types):
              self._ensure_ownership_transferrable(v)
              v.thisown = False
              dereg = getattr(v, "_deregister", None)
              if dereg:
                  dereg()
          return True

      def _maybe_disown_and_deregister(self):
          if self.thisown:
              self.thisown = False
              self._deregister()

      def _own_and_register(self):
          assert(not self.thisown)
          self.thisown = True
          self._register()

      def replace_by(self, o):
          assert(isinstance(o, (cexpr_t, cinsn_t)))
          o._maybe_disown_and_deregister()
          self._replace_by(o)

      def _meminfo(self):
          cpp = self.__dbg_get_meminfo()
          rkind = self.__dbg_get_registered_kind()
          rkind_str = [
                  "(not owned)",
                  "cfuncptr_t",
                  "cinsn_t",
                  "cexpr_t",
                  "cblock_t",
                  "mba_t",
                  "mop_t",
                  "minsn_t",
                  "optinsn_t",
                  "optblock_t",
                  "valrng_t",
                  "udc_filter_t"][rkind]
          return "%s [thisown=%s, owned by IDAPython as=%s]" % (
                  cpp,
                  self.thisown,
                  rkind_str)
      meminfo = property(_meminfo)
    }
};
%enddef

%define %define_node_property_accessors(TNAME, PNAME, PTYPE)
  %extend TNAME {
    PTYPE _get_##PNAME() const { return $self->PNAME; }
    void _set_##PNAME(PTYPE _v) { $self->PNAME = _v; }
  }
%enddef

%define %define_node_cstring_property_accessors(TNAME, PNAME)
  %extend TNAME {
    const char *_get_##PNAME() const { return $self->PNAME; }
    void _set_##PNAME(const char *_v)
    {
      if ( $self->PNAME != nullptr )
      {
        ::qfree($self->PNAME);
        $self->PNAME = nullptr;
      }
      $self->PNAME = ::qstrdup(_v);
    }
  }
%enddef

%define %define_node_obj_property(TNAME, COND, PNAME, DEFVAL, ACQUIRE)
  %extend TNAME {
    %pythoncode {
      PNAME = property(
              lambda self: self._get_##PNAME() if COND else DEFVAL,
              lambda self, v: self._ensure_cond(COND, #COND) \
                              and self._ensure_no_obj(self._get_##PNAME(), #PNAME, ACQUIRE) \
                              and self._acquire_ownership(v, ACQUIRE) \
                              and self._set_##PNAME(v))
    }
  }
%enddef

%define %define_node_scalar_property(TNAME, COND, PNAME, DEFVAL)
  %extend TNAME {
    %pythoncode {
      PNAME = property(
              lambda self: self._get_##PNAME() if COND else DEFVAL,
              lambda self, v: self._ensure_cond(COND, #COND) and self._set_##PNAME(v))
    }
  }
%enddef

// ------------------------------

%define %override_node_obj_property(TNAME, COND, PNAME, PTYPE, DEFVAL, ACQUIRE)
  %define_node_property_accessors(TNAME, PNAME, PTYPE);
  %define_node_obj_property(TNAME, COND, PNAME, DEFVAL, ACQUIRE);
  %ignore TNAME::PNAME;
%enddef

%define %override_node_scalar_property(TNAME, COND, PNAME, PTYPE, DEFVAL)
  %define_node_property_accessors(TNAME, PNAME, PTYPE);
  %define_node_scalar_property(TNAME, COND, PNAME, DEFVAL);
  %ignore TNAME::PNAME;
%enddef

%define %override_node_cstring_property(TNAME, COND, PNAME)
  %define_node_cstring_property_accessors(TNAME, PNAME);
  %define_node_obj_property(TNAME, COND, PNAME, None, False);
  %ignore TNAME::PNAME;
%enddef


//-------------------------------------------------------------------------
//                               mop_t
//-------------------------------------------------------------------------

%define %override_mop_t_obj_property(MOP_OP, PNAME, PTYPE)
  %override_node_obj_property(mop_t, self.t == MOP_OP, PNAME, PTYPE, None, True);
%enddef

%define %override_mop_t_scalar_property(MOP_OP, PNAME, PTYPE)
  %override_node_scalar_property(mop_t, self.t == MOP_OP, PNAME, PTYPE, None);
%enddef

%define %override_mop_t_cstring_property(MOP_OP, PNAME)
  %override_node_cstring_property(mop_t, self.t == MOP_OP, PNAME);
%enddef

%extend mop_t {

    mopt_t _get_t() const { return self->t; }
    void _set_t(mopt_t v) { self->t = v; }
    %pythoncode {
      def _ensure_no_t(self):
          if self.t not in [mop_z]:
              raise Exception("%s has type %s; cannot be modified" % (self, self.t))
          return True
      t = property(
              _get_t,
              lambda self, v: self._ensure_no_t() and self._set_t(v))
    }

    qstring __dbg_get_meminfo() const
    {
      qstring s;
      s.sprnt("%p (t=%d)", self, self->t);
      return s;
    }
}

%monitored_lifecycle_object_t(mop_t);

%override_mop_t_obj_property(mop_n, nnn, mnumber_t *);
%override_mop_t_obj_property(mop_d, d, minsn_t *);
%override_mop_t_obj_property(mop_S, s, stkvar_ref_t *);
%override_mop_t_obj_property(mop_f, f, mcallinfo_t *);
%override_mop_t_obj_property(mop_l, l, lvar_ref_t *);
%override_mop_t_obj_property(mop_a, a, mop_addr_t *);
%override_mop_t_obj_property(mop_c, c, mcases_t *);
%override_mop_t_obj_property(mop_fn, fpc, fnumber_t *);
%override_mop_t_obj_property(mop_p, pair, mop_pair_t *);
%override_mop_t_obj_property(mop_sc, scif, scif_t *);
%override_mop_t_obj_property(mop_sc, scif, scif_t *);
%override_mop_t_scalar_property(mop_r, r, mreg_t);
%override_mop_t_scalar_property(mop_v, g, ea_t);
%override_mop_t_scalar_property(mop_b, b, int);
%override_mop_t_cstring_property(mop_str, cstr);
%override_mop_t_cstring_property(mop_h, helper);

//-------------------------------------------------------------------------
//                               minsn_t
//-------------------------------------------------------------------------
%extend minsn_t {
    qstring __dbg_get_meminfo() const
    {
      qstring s;
      s.sprnt("%p (opcode=%d)", self, self->opcode);
      return s;
    }
}
%monitored_lifecycle_object_t(minsn_t);

%typemap(in,numinputs=0) (mop_t **other) (mop_t *tmp_op)
{
  // %typemap(in,numinputs=0) (mop_t **other)
  $1 = &tmp_op;
}
%typemap(argout) (mop_t **other)
{
  // %typemap(argout) (mop_t **other)
  $result = Py_BuildValue(
          "(OO)",
          $result,
          SWIG_NewPointerObj(SWIG_as_voidptr(result != nullptr ? *$1 : nullptr), SWIGTYPE_p_mop_t, 0 | 0));
}


//-------------------------------------------------------------------------
//                               bitset_t
//-------------------------------------------------------------------------
%extend bitset_t {

    int itv(const_iterator it) { qnotused(self); return *it; }

    %pythoncode {
     __len__ = count
     def __iter__(self):
         it = self.begin()
         for i in range(self.count()):
             yield self.itv(it)
             self.inc(it)
    }
};

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
%typemap(check) citem_t *self
{
  if ( $1 == INS_EPILOG )
    SWIG_exception_fail(SWIG_ValueError, "invalid INS_EPILOG " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%typemap(check) cinsn_t *self
{
  if ( $1 == INS_EPILOG )
    SWIG_exception_fail(SWIG_ValueError, "invalid INS_EPILOG " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

//-------------------------------------------------------------------------
//                             citem_t
//---------------------------------------------------------------------
%extend citem_t {
    // define these two struct members that can be used for casting.
    cinsn_t *cinsn const;
    cexpr_t *cexpr const;

    ctype_t _get_op() const { return self->op; }
    void _set_op(ctype_t v) { self->op = v; }
    %pythoncode {
      def _ensure_no_op(self):
          if self.op not in [cot_empty, cit_empty]:
              raise Exception("%s has op %s; cannot be modified" % (self, self.op))
          return True
      op = property(
              _get_op,
              lambda self, v: self._ensure_no_op() and self._set_op(v))
    }

    qstring __dbg_get_meminfo() const
    {
      qstring s;
      s.sprnt("%p (op=%s)", self, get_ctype_name(self->op));
      return s;
    }
};
%monitored_lifecycle_object_t(citem_t);

%{
cinsn_t *citem_t_cinsn_get(citem_t *item) { return (cinsn_t *) item; }
cexpr_t *citem_t_cexpr_get(citem_t *item) { return (cexpr_t *) item; }
%}

//---------------------------------------------------------------------
//                               cinsn_t
//---------------------------------------------------------------------
%define_hexrays_lifecycle_object(cinsn_t);
%extend cinsn_t {
  static bool insn_is_epilog(const cinsn_t *insn) { return insn == INS_EPILOG; }

  %pythoncode {
    def is_epilog(self):
        return cinsn_t.insn_is_epilog(self)
  }
};


%define %override_cinsn_t_obj_property(CIT_OP, PNAME, PTYPE)
  %override_node_obj_property(cinsn_t, self.op == CIT_OP, PNAME, PTYPE, None, True);
%enddef
%override_cinsn_t_obj_property(cit_block,  cblock,  cblock_t *);
%override_cinsn_t_obj_property(cit_expr,   cexpr,   cexpr_t *);
%override_cinsn_t_obj_property(cit_if,     cif,     cif_t *);
%override_cinsn_t_obj_property(cit_for,    cfor,    cfor_t *);
%override_cinsn_t_obj_property(cit_while,  cwhile,  cwhile_t *);
%override_cinsn_t_obj_property(cit_do,     cdo,     cdo_t *);
%override_cinsn_t_obj_property(cit_switch, cswitch, cswitch_t *);
%override_cinsn_t_obj_property(cit_return, creturn, creturn_t *);
%override_cinsn_t_obj_property(cit_goto,   cgoto,   cgoto_t *);
%override_cinsn_t_obj_property(cit_asm,    casm,    casm_t *);

//-------------------------------------------------------------------------
//                             cexpr_t
//-------------------------------------------------------------------------
%define_hexrays_lifecycle_object(cexpr_t);
%extend cexpr_t {
  var_ref_t* get_v() { if ( self->op == cot_var ) { return &self->v; } else { return nullptr; } }
  void set_v(const var_ref_t *v) { if ( self->op == cot_var ) { self->v = *v; } }
  %pythoncode {
    v = property(lambda self: self.get_v(), lambda self, v: self.set_v(v))
  }
};
%ignore cexpr_t::v;

%define %override_cexpr_t_obj_property(COND, PNAME, PTYPE, DEFVAL, ACQUIRE)
  %override_node_obj_property(cexpr_t, COND, PNAME, PTYPE, DEFVAL, ACQUIRE);
%enddef
%define %override_cexpr_t_scalar_property(COND, PNAME, PTYPE, DEFVAL)
  %override_node_scalar_property(cexpr_t, COND, PNAME, PTYPE, DEFVAL);
%enddef
%define %override_cexpr_t_cstring_property(COND, PNAME)
  %override_node_cstring_property(cexpr_t, COND, PNAME);
%enddef

%override_cexpr_t_obj_property(self.op == cot_num, n, cnumber_t *, None, True);
%override_cexpr_t_obj_property(self.op == cot_fnum, fpc, fnumber_t *, None, True);
%override_cexpr_t_obj_property(op_uses_x(self.op), x, cexpr_t *, None, True);
%override_cexpr_t_obj_property(op_uses_y(self.op), y, cexpr_t *, None, True);
%override_cexpr_t_obj_property(op_uses_z(self.op), z, cexpr_t *, None, True);
%override_cexpr_t_obj_property(self.op == cot_call, a, carglist_t *, None, True);
%override_cexpr_t_obj_property(self.op == cot_insn, insn, cinsn_t *, None, True);
%override_cexpr_t_scalar_property(self.op == cot_memptr or self.op == cot_memref, m, int, 0);
%override_cexpr_t_scalar_property(self.op == cot_ptr or self.op == cot_memptr, ptrsize, int, 0);
%override_cexpr_t_scalar_property(self.op == cot_obj, obj_ea, ea_t, ida_idaapi.BADADDR);
%override_cexpr_t_scalar_property(True, refwidth, int, 0);
%override_cexpr_t_cstring_property(self.op == cot_helper, helper);
%override_cexpr_t_cstring_property(self.op == cot_str, string);

%feature("pythonprepend") cexpr_t::cexpr_t %{
    for arg in args[1:]: # skip copy constructor's arg
        if isinstance(arg, cexpr_t):
            self._ensure_ownership_transferrable(arg)
%}
%feature("pythonappend") cexpr_t::cexpr_t %{
    for arg in args[1:]: # skip copy constructor's arg
        if isinstance(arg, cexpr_t):
            self._acquire_ownership(arg, True)
%}

//-------------------------------------------------------------------------
//                             ctree_item_t
//-------------------------------------------------------------------------
// FIXME: I can't enable setters, because the ctree_item_t doesn't
// have a cleanup() function that would greatly help getting rid of
// objects that were referenced by SWiG proxies, but which have been
// de-owned (see cexpr_t above.)
// #define CTREE_ITEM_MEMBER_REF(type, name)                             \
//   type get_##name() const { return self->##name; }                    \
//   void set_##name(type _v) { self->##name = _v; }                     \
//   %pythoncode {                                                       \
//     name = property(lambda self: self.get_##name(), lambda self, v: self.set_##name(v)) \
//   }
//
// #define CTREE_CONDITIONAL_ITEM_MEMBER_REF(type, name, wanted_citype)  \
//   type get_##name() const { if ( self->citype == wanted_citype ) { return self->##name; } else { return nullptr; } } \
//   void set_##name(type _v) { if ( self->citype == wanted_citype ) { self->##name = _v; } } \
//   %pythoncode {                                                       \
//     name = property(lambda self: self.get_##name(), lambda self, v: self.set_##name(v)) \
//   }

#define CTREE_ITEM_MEMBER_REF(type, name)                               \
  type _get_##name() const { return self->##name; }                     \
  %pythoncode {                                                         \
    name = property(lambda self: self._get_##name())                    \
      }

#define CTREE_CONDITIONAL_ITEM_MEMBER_REF(type, name, wanted_citype)    \
  type _get_##name() const                                              \
  {                                                                     \
    if ( self->citype == wanted_citype )                                \
      return self->##name;                                              \
    else                                                                \
      return nullptr;                                                   \
  }                                                                     \
  %pythoncode {                                                         \
    name = property(lambda self: self._get_##name())                    \
      }


%extend ctree_item_t {
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(citem_t *, it, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cexpr_t*, e, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cinsn_t*, i, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(lvar_t*, l, VDI_LVAR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cfunc_t*, f, VDI_FUNC);
  treeloc_t *loc const;
};

%ignore ctree_item_t::loc;

%{
treeloc_t *ctree_item_t_loc_get(ctree_item_t *item) { return item->citype == VDI_TAIL ? &item->loc : nullptr; }
%}

#undef CTREE_CONDITIONAL_ITEM_MEMBER_REF
#undef CTREE_ITEM_MEMBER_REF

//-------------------------------------------------------------------------
/* for qvector instanciations where the class is a pointer (cinsn_t, citem_t) we need
   to fix the at() return type, otherwise swig mistakenly thinks it is "cinsn_t *&" and nonsense ensues. */
%extend qvector< cinsn_t *> {
  cinsn_t *at(size_t n) { return self->at(n); }
};
%extend qvector< citem_t *> {
  citem_t *at(size_t n) { return self->at(n); }
};

// ignore future declarations of at() for these classes
/* %ignore qvector< cinsn_t *>::at(size_t) const; */
/* %ignore qvector< cinsn_t *>::at(size_t); */
/* %ignore qvector< citem_t *>::at(size_t) const; */
/* %ignore qvector< citem_t *>::at(size_t); */
%ignore qvector< citem_t *>::grow;
%ignore qvector< cinsn_t *>::grow;

// At this point, SWIG doesn't know about this
// type yet (kernwin.i is included later). Therefore,
// unless we do this, swig will consider 'strvec_t' to be
// just a regular type, and when retrieving structure
// members of type 'strvec_t', 2 issues:
//  - an additional copy will be made, and
//  - SWIG will use SWIGTYPE_p_strvec_t, which has a != Python type
//    information than SWIGTYPE_p_qvectorT_simpleline_t_t, and no
//    proper Python 'strvec_t' proxy instance will be created.
typedef qvector<simpleline_t> strvec_t;

// hexrays templates
%template(user_numforms_t) std::map<operand_locator_t, number_format_t>;
%template(lvar_mapping_t) std::map<lvar_locator_t, lvar_locator_t>;
%template(hexwarns_t) qvector<hexwarn_t>;
%template(ctree_items_t) qvector<citem_t *>;
%template(user_labels_t) std::map<int, qstring>;
%template(user_cmts_t) std::map<treeloc_t, citem_cmt_t>;
%template(user_iflags_t) std::map<citem_locator_t, int32>;
%template(user_unions_t) std::map<ea_t, intvec_t>;
%template(cinsnptrvec_t) qvector<cinsn_t *>;
%template(eamap_t) std::map<ea_t, cinsnptrvec_t>;
%template(boundaries_t) std::map<cinsn_t *, rangeset_t>;

%define %constify_iterator_value(NameBase, ReturnType)
%ignore NameBase ## _second;
%rename (NameBase ## _second) py_ ## NameBase ## _second;
%inline %{
inline const ReturnType &py_ ## NameBase ## _second(NameBase ## _iterator_t p) { return NameBase ## _second(p); }
%}
%enddef
%constify_iterator_value(user_iflags, int32);

%ignore boundaries_find;
%rename (boundaries_find) py_boundaries_find;
%ignore boundaries_insert;
%rename (boundaries_insert) py_boundaries_insert;

// WARNING: The order here is VERY important:
//  1) The '%extend' directive. Note that
//    - the template name must be used, not the typedef (i.e., not 'cfuncptr_t')
//    - to override the destructor, the destructor must have the template parameters.
//  2) The '%ignore' directive.
//    - Again, using the template name, but this time
//    - not qualifying the destructor with template parameters
//  3) The '%template' directive, that will indeed instantiate
//     the template for swig.
%{ void hexrays_deregister_python_clearable_instance(void *ptr); %}
%extend qrefcnt_t<cfunc_t> {
  // The typemap above will take care of registering newly-constructed cfuncptr_t
  // instances. However, there's no such thing as a destructor typemap.
  // Therefore, we need to do the grunt work of de-registering ourselves.
  // Note: The 'void' here is important: Without it, SWIG considers it to
  //       be a different destructor (which, of course, makes a ton of sense.)
  ~qrefcnt_t<cfunc_t>(void)
  {
    hexrays_deregister_python_clearable_instance($self);
    delete $self;
  }
}
%ignore qrefcnt_t<cfunc_t>::~qrefcnt_t(void);
%template(cfuncptr_t) qrefcnt_t<cfunc_t>;
%template(qvector_history_t) qvector<history_item_t>;
%template(history_t) qstack<history_item_t>;
typedef int iterator_word;

%qlist_template(cinsn_list_t, cinsn_t);

%template(qvector_lvar_t) qvector<lvar_t>;
%template(qvector_carg_t) qvector<carg_t>;
%template(qvector_ccase_t) qvector<ccase_t>;
%template(lvar_saved_infos_t) qvector<lvar_saved_info_t>;
%template(ui_stroff_ops_t) qvector<ui_stroff_op_t>;

%extend cblock_t {
  cblock_t(void)
  {
    cblock_t *cb = new cblock_t();
    hexrays_register_python_clearable_instance(cb, hxclr_cblock_t);
    return cb;
  }

  ~cblock_t(void)
  {
    hexrays_deregister_python_clearable_instance($self);
    delete $self;
  }

  void _deregister() { hexrays_deregister_python_clearable_instance($self); }
}
%ignore cblock_t::cblock_t;

%extend citem_cmt_t {
    const char *c_str() const { return self->c_str(); }

    const char *__str__() const
    {
      return $self->c_str();
    }
};

void qswap(cinsn_t &a, cinsn_t &b);
%include "typemaps.i"

%typemap(out) void
{
  Py_INCREF(Py_None);
  $1obj = Py_None;
}

%{
//<code(py_hexrays)>
//</code(py_hexrays)>
%}

%ignore init_hexrays_plugin;
%rename(init_hexrays_plugin) py_init_hexrays_plugin;

%ignore install_hexrays_callback;
%ignore remove_hexrays_callback;

%ignore decompile_snippet;

%ignore get_widget_vdui;
%rename (get_widget_vdui) py_get_widget_vdui;

%feature("pythonappend") decompile_func %{
  if val.__deref__() is None:
      val = None
%}


//-------------------------------------------------------------------------
#if SWIG_VERSION == 0x40000 || SWIG_VERSION == 0x40001
%typemap(out) cfuncptr_t {}
%typemap(ret) cfuncptr_t
{
  // ret cfuncptr_t
  cfuncptr_t *ni = new cfuncptr_t($1);
  hexrays_register_python_clearable_instance(ni, hxclr_cfuncptr);
  $result = SWIG_NewPointerObj(ni, $&1_descriptor, SWIG_POINTER_OWN | 0);
}


%typemap(out) cfuncptr_t *{}
%typemap(ret) cfuncptr_t *
{
  // ret cfuncptr_t*
  cfuncptr_t *ni = new cfuncptr_t(*($1));
  hexrays_register_python_clearable_instance(ni, hxclr_cfuncptr);
  $result = SWIG_NewPointerObj(ni, $1_descriptor, SWIG_POINTER_OWN | 0);
}
#else
#error Ensure cfuncptr_t wrapping is compatible with this version of SWIG
#endif

//---------------------------------------------------------------------
%define %python_callback_in(CB)
%typemap(check) CB {
  if (!PyCallable_Check($1))
  {
      PyErr_SetString(PyExc_TypeError, "Need a callable object!");
      return nullptr;
  }
}
%enddef

%python_callback_in(PyObject *hx_callback);
%python_callback_in(PyObject *custom_viewer_popup_item_callback);

%ignore cexpr_t::get_1num_op(const cexpr_t **, const cexpr_t **) const;
%ignore cexpr_t::find_ptr_or_array(bool) const;

#pragma SWIG nowarn=503

// http://www.swig.org/Doc2.0/SWIGDocumentation.html#Python_nn36
// http://www.swig.org/Doc2.0/SWIGDocumentation.html#Customization_exception_special_variables
%define %possible_director_exc(Method)
%exception Method {
  try {
    $action
  } catch ( Swig::DirectorException & ) {
    // A DirectorException might be raised in deeper layers.
    SWIG_fail;
  }
}
%enddef
%possible_director_exc(ctree_visitor_t::apply_to)
%possible_director_exc(ctree_visitor_t::apply_to_exprs)

%inline %{
//<inline(py_hexrays)>
//</inline(py_hexrays)>
%}

%define_Hooks_class(Hexrays);
%ignore Hexrays_Hooks::hooked;

%inline %{
//<inline(py_hexrays_hooks)>
//</inline(py_hexrays_hooks)>
%}

%{
//<code(py_hexrays_hooks)>
//</code(py_hexrays_hooks)>
%}

%import "hexrays_templates.hpp";
%template(uval_ivl_t) ivl_tpl<uval_t>;
%template(uval_ivl_ivlset_t) ivlset_tpl<ivl_t, uval_t>;
%template(array_of_ivlsets) qvector<ivlset_t>;

%include "hexrays_notemplates.hpp"
%exception; // Delete & restore handlers
%exception_set_default_handlers();

%pythoncode %{
#<pycode(py_hexrays)>
#</pycode(py_hexrays)>
%}

//-------------------------------------------------------------------------
%init %{
//<init(py_hexrays)>
//</init(py_hexrays)>
%}
