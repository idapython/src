%module(docstring="IDA Plugin SDK API wrapper: hexrays",directors="1",threads="1") ida_hexrays
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_HEXRAYS
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_HEXRAYS
  #define HAS_DEP_ON_INTERFACE_HEXRAYS
#endif
#ifndef HAS_DEP_ON_INTERFACE_TYPEINF
  #define HAS_DEP_ON_INTERFACE_TYPEINF
#endif
%include "header.i"
%{
#include <hexrays.hpp>
%}

%import "typeinf.i"

// KLUDGE: I have no idea how to force SWiG to declare a type for a module,
// unless that type is indeed used. That's why this wrapper exists..
%{
static void _kludge_use_TPopupMenu(TPopupMenu *) {}
%}
%inline %{
static void _kludge_use_TPopupMenu(TPopupMenu *m);
%}

//---------------------------------------------------------------------
// SWIG bindings for Hexray Decompiler's hexrays.hpp
//
// Author: EiNSTeiN_ <einstein@g3nius.org>
// Copyright (C) 2013 ESET
//
// Integrated into IDAPython project by the IDAPython Team <idapython@googlegroups.com>
//---------------------------------------------------------------------

// Suppress 'previous definition of XX' warnings
#pragma SWIG nowarn=302
// and others...
#pragma SWIG nowarn=312
#pragma SWIG nowarn=325
#pragma SWIG nowarn=314
#pragma SWIG nowarn=362
#pragma SWIG nowarn=383
#pragma SWIG nowarn=389
#pragma SWIG nowarn=401
#pragma SWIG nowarn=451
#pragma SWIG nowarn=454 // Setting a pointer/reference variable may leak memory

#define _STD_BEGIN

#ifdef __NT__
%include <windows.i>
#endif

//---------------------------------------------------------------------
// some defines to calm SWIG down.
#define DEFINE_MEMORY_ALLOCATION_FUNCS()
//#define DECLARE_UNCOPYABLE(f)
#define AS_PRINTF(format_idx, varg_idx)

%ignore vd_printer_t::vprint;
%ignore vd_printer_t::tmpbuf;
%ignore string_printer_t::vprint;
%ignore vdui_t::vdui_t;
%ignore cblock_t::find;
%ignore citem_t::op;
%ignore cfunc_t::cfunc_t;
%ignore cfunc_t::sv;         // lazy member. Use get_pseudocode() instead
%ignore cfunc_t::boundaries; // lazy member. Use get_boundaries() instead
%ignore cfunc_t::eamap;      // lazy member. Use get_eamap() instead
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
%ignore cexpr_t::cexpr_t(mbl_array_t *mba, const lvar_t &v);
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

// ignore microcode related stuff for now
%ignore bitset_t;
%ignore mlist_t;
%ignore rlist_t;
%ignore mbl_array_t;
%ignore mbl_graph_t;
%ignore mblock_t;
%ignore minsn_t;
%ignore mop_t;
%ignore mcode_t;
%ignore mop_addr_t;
%ignore mop_pair_t;
%ignore mcases_t;
%ignore mcallarg_t;
%ignore mcallinfo_t;
%ignore mnumber_t;
%ignore lvar_ref_t;
%ignore stkvar_ref_t;
%ignore scif_t;
%ignore op_parent_info_t;
%ignore scif_visitor_t;
%ignore mop_visitor_t;
%ignore mlist_mop_visitor_t;
%ignore minsn_visitor_t;
%ignore srcop_visitor_t;
%ignore chain_t;
%ignore block_chains_t;
%ignore block_chains_iterator_t;
%ignore block_chains_begin;
%ignore block_chains_clear;
%ignore block_chains_end;
%ignore block_chains_erase;
%ignore block_chains_find;
%ignore block_chains_free;
%ignore block_chains_get;
%ignore block_chains_insert;
%ignore block_chains_new;
%ignore block_chains_next;
%ignore block_chains_prev;
%ignore block_chains_size;
%ignore graph_chains_t;
%ignore chain_visitor_t;
%ignore gctype_t;
%ignore simple_graph_t;
%ignore get_signed_mcode;
%ignore get_unsigned_mcode;
%ignore mcode_modifies_d;
%ignore is_may_access;
%ignore is_mcode_addsub;
%ignore is_mcode_call;
%ignore is_mcode_commutative;
%ignore is_mcode_convertible_to_jmp;
%ignore is_mcode_convertible_to_set;
%ignore is_mcode_fpu;
%ignore is_mcode_j1;
%ignore is_mcode_jcond;
%ignore is_mcode_propagatable;
%ignore is_mcode_rotate;
%ignore is_mcode_set;
%ignore is_mcode_set1;
%ignore is_mcode_shift;
%ignore is_mcode_xdsu;
%ignore is_signed_mcode;
%ignore is_unsigned_mcode;
%ignore is_kreg;
%ignore get_first_stack_reg;
%ignore jcnd2set;
%ignore must_mcode_close_block;
%ignore negate_mcode_relation;
%ignore set2jcnd;
%ignore swap_mcode_relation;
%ignore get_mreg_name;
%ignore gen_microcode;
%ignore install_optinsn_handler;
%ignore remove_optinsn_handler;
%ignore install_optblock_handler;
%ignore remove_optblock_handler;
%ignore optinsn_t;
%ignore optblock_t;
%ignore getf_reginsn;
%ignore getb_reginsn;
%ignore reg2mreg;
%ignore mreg2reg;
%ignore chain_keeper_t;
%ignore lvar_t::dstr;
%ignore lvar_locator_t::dstr;
%ignore fnumber_t::dstr;
%ignore dstr;
%ignore range_item_iterator_t;
%ignore mba_item_iterator_t;
%ignore range_chunk_iterator_t;
%ignore mba_range_iterator_t;
%ignore mba_ranges_t;
%ignore deserialize_mbl_array;
%ignore get_temp_regs;
%ignore ivl_t;
%ignore ivlset_t;
%ignore ivl_with_name_t;
%ignore vivl_t;
%ignore voff_t;
%ignore voff_set_t;
%ignore gco_info_t;
%ignore get_current_operand;
%ignore valrng_t;

// "Warning 473: Returning a pointer or reference in a director method is not recommended."
// In this particular case, we are telling SWiG that the object is always a
// %newobject (thus: even for base classes), but it seems it's not enough to
// shut the warning up.
%warnfilter(473) codegen_t::emit_micro_mvm;
%newobject codegen_t::emit_micro_mvm;
%newobject codegen_t::emit;

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
    cinsn_t *cinsn const { return (cinsn_t *)self; }
    cexpr_t *cexpr const { return (cexpr_t *)self; }

    ctype_t _get_op() const { return self->op; }
    void _set_op(ctype_t v) { self->op = v; }

    PyObject *_obj_id() const { return PyLong_FromSize_t(size_t(self)); }

#ifdef TESTABLE_BUILD
    qstring __dbg_get_meminfo() const
    {
      qstring s;
      s.sprnt("%p (op=%s)", self, get_ctype_name(self->op));
      return s;
    }

    int __dbg_get_registered_kind() const
    {
      return hexrays_is_registered_python_clearable_instance(self);
    }
#endif

    %pythoncode {
      obj_id = property(_obj_id)
      op = property(
              _get_op,
              lambda self, v: self._ensure_no_op() and self._set_op(v))

      def _ensure_cond(self, ok, cond_str):
          if not ok:
              raise Exception("Condition \"%s\" not verified" % cond_str)
          return True

      def _ensure_no_op(self):
          if self.op not in [cot_empty, cit_empty]:
              raise Exception("%s has op %s; cannot be modified" % (self, self.op))
          return True

      def _ensure_no_obj(self, o, attr, attr_is_acquired):
          if attr_is_acquired and o is not None:
              raise Exception("%s already owns attribute \"%s\" (%s); cannot be modified" % (self, attr, o))
          return True

      def _acquire_ownership(self, v, acquire):
          if acquire and (v is not None) and not isinstance(v, (int, long)):
              if not v.thisown:
                  raise Exception("%s is already owned, and cannot be reused" % v)
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

#ifdef TESTABLE_BUILD
      def _meminfo(self):
          cpp = self.__dbg_get_meminfo()
          rkind = self.__dbg_get_registered_kind()
          rkind_str = [
                  "(not owned)",
                  "cfuncptr",
                  "cinsn",
                  "cexpr",
                  "cblock"][rkind]
          return "%s [thisown=%s, owned by IDAPython as=%s]" % (
                  cpp,
                  self.thisown,
                  rkind_str)
      meminfo = property(_meminfo)
#endif
    }
};

//-------------------------------------------------------------------------
#define ___MEMBER_REF_BASE(Type, PName, Cond, Defval, Acquire, Setexpr) \
  Type _get_##PName() const { return self->##PName; }                   \
  void _set_##PName(Type _v) { self->##PName = Setexpr; }               \
  %pythoncode {                                                         \
    PName = property(                                                   \
            lambda self: self._get_##PName() if Cond else Defval,       \
            lambda self, v:                                             \
                self._ensure_cond(Cond, #Cond)                          \
                and self._ensure_no_obj(self._get_##PName(), #PName, Acquire) \
                and self._acquire_ownership(v, Acquire)                 \
                and self._set_##PName(v))                               \
      }


//---------------------------------------------------------------------
//                               cinsn_t
//---------------------------------------------------------------------
#define CINSN_MEMBER_REF(Name)                                          \
  ___MEMBER_REF_BASE(c##Name##_t*, c##Name, self.op == cit_##Name, None, True, _v)

%feature("ref") cinsn_t
{
  hexrays_register_python_clearable_instance($this, hxclr_cinsn);
  if ( $this->op == cit_empty )
    $this->cblock = NULL; // force clean instance
}
%feature("unref") cinsn_t
{
  hexrays_deregister_python_clearable_instance($this);
  delete $this;
}
%extend cinsn_t {
  void _deregister() { hexrays_deregister_python_clearable_instance($self); }
  void _register() { hexrays_register_python_clearable_instance($self, hxclr_cinsn); }

  CINSN_MEMBER_REF(block);
  CINSN_MEMBER_REF(expr);
  CINSN_MEMBER_REF(if);
  CINSN_MEMBER_REF(for);
  CINSN_MEMBER_REF(while);
  CINSN_MEMBER_REF(do);
  CINSN_MEMBER_REF(switch);
  CINSN_MEMBER_REF(return);
  CINSN_MEMBER_REF(goto);
  CINSN_MEMBER_REF(asm);

  static bool insn_is_epilog(const cinsn_t *insn) { return insn == INS_EPILOG; }

  %pythoncode {
    def is_epilog(self):
        return cinsn_t.insn_is_epilog(self)
  }
};
#undef CINSN_MEMBER_REF

//-------------------------------------------------------------------------
//                             cexpr_t
//-------------------------------------------------------------------------
#define CEXPR_MEMBER_REF(Type, PName, Cond, Defval, Acquire) \
  ___MEMBER_REF_BASE(Type, PName, Cond, Defval, Acquire, _v)

#define CEXPR_MEMBER_REF_STR(Type, PName, Cond, Defval)      \
  ___MEMBER_REF_BASE(Type, PName, Cond, Defval, False, ::qstrdup(_v))

%feature("ref") cexpr_t
{
  hexrays_register_python_clearable_instance($this, hxclr_cexpr);
}
%feature("unref") cexpr_t
{
  hexrays_deregister_python_clearable_instance($this);
  delete $this;
}
%extend cexpr_t {
  void _deregister() { hexrays_deregister_python_clearable_instance($self); }
  void _register() { hexrays_register_python_clearable_instance($self, hxclr_cexpr); }

  CEXPR_MEMBER_REF(cnumber_t*, n, self.op == cot_num, None, True);
  CEXPR_MEMBER_REF(fnumber_t*, fpc, self.op == cot_fnum, None, True);
  var_ref_t* get_v() { if ( self->op == cot_var ) { return &self->v; } else { return NULL; } }
  void set_v(const var_ref_t *v) { if ( self->op == cot_var ) { self->v = *v; } }
  %pythoncode {
    v = property(lambda self: self.get_v(), lambda self, v: self.set_v(v))
  }
  CEXPR_MEMBER_REF(ea_t, obj_ea, self.op == cot_obj, ida_idaapi.BADADDR, False);
  CEXPR_MEMBER_REF(int, refwidth, True, 0, False);
  CEXPR_MEMBER_REF(cexpr_t*, x, op_uses_x(self.op), None, True);
  CEXPR_MEMBER_REF(cexpr_t*, y, op_uses_y(self.op), None, True);
  CEXPR_MEMBER_REF(carglist_t*, a, self.op == cot_call, None, True);
  CEXPR_MEMBER_REF(int, m, (self.op == cot_memptr or self.op == cot_memref), 0, False);
  CEXPR_MEMBER_REF(cexpr_t*, z, op_uses_z(self.op), None, True);
  CEXPR_MEMBER_REF(int, ptrsize, (self.op == cot_ptr or self.op == cot_memptr), 0, False);
  CEXPR_MEMBER_REF(cinsn_t*, insn, self.op == cot_insn, None, True);
  CEXPR_MEMBER_REF_STR(char*, helper, self.op == cot_helper, None);
  CEXPR_MEMBER_REF_STR(char*, string, self.op == cot_str, None);
};

#undef CEXPR_MEMBER_REF_STR
#undef CEXPR_MEMBER_REF

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
//   type get_##name() const { if ( self->citype == wanted_citype ) { return self->##name; } else { return NULL; } } \
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
      return NULL;                                                      \
  }                                                                     \
  %pythoncode {                                                         \
    name = property(lambda self: self._get_##name())                    \
      }


%extend ctree_item_t {
  CTREE_ITEM_MEMBER_REF(citem_t *, it);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cexpr_t*, e, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cinsn_t*, i, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(lvar_t*, l, VDI_LVAR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cfunc_t*, f, VDI_FUNC);
  treeloc_t* loc const { if ( self->citype == VDI_TAIL ) { return &self->loc; } else { return NULL; } }
};

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
%ignore qvector< cinsn_t *>::at(size_t) const;
%ignore qvector< cinsn_t *>::at(size_t);
%ignore qvector< citem_t *>::at(size_t) const;
%ignore qvector< citem_t *>::at(size_t);
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

/* no support for nested classes in swig means we need to wrap
    this iterator and do some magic...

    to use it, call qlist< cinsn_t >::begin() which will return the
    proper iterator type which can then be used to get the current item.
*/
%{
typedef qlist<cinsn_t>::iterator qlist_cinsn_t_iterator;
%}
class qlist_cinsn_t_iterator {};
%extend qlist_cinsn_t_iterator {
    const cinsn_t &cur { return *(*self); }
    void next(void) { (*self)++; }
    bool operator==(const qlist_cinsn_t_iterator *x) const { return &(self->operator*()) == &(x->operator*()); }
    bool operator!=(const qlist_cinsn_t_iterator *x) const { return &(self->operator*()) != &(x->operator*()); }
};

%extend qlist<cinsn_t> {
    qlist_cinsn_t_iterator begin() { return self->begin(); }
    qlist_cinsn_t_iterator end(void) { return self->end(); }
    qlist_cinsn_t_iterator insert(qlist_cinsn_t_iterator p, const cinsn_t& x) { return self->insert(p, x); }
    void erase(qlist_cinsn_t_iterator p) { self->erase(p); }
};
%ignore qlist< cinsn_t >::insert();
%ignore qlist< cinsn_t >::erase();
%ignore qlist< cinsn_t >::begin();
%ignore qlist< cinsn_t >::begin() const;
%ignore qlist< cinsn_t >::end();
%ignore qlist< cinsn_t >::end() const;

//%template(qvector_meminfo_t) qvector<meminfo_t>;
%template(qvector_lvar_t) qvector<lvar_t>;
%template(qlist_cinsn_t) qlist<cinsn_t>;
%template(qvector_carg_t) qvector<carg_t>;
%template(qvector_ccase_t) qvector<ccase_t>;
%template(lvar_saved_infos_t) qvector<lvar_saved_info_t>;

%extend cblock_t {
  cblock_t(void)
  {
    cblock_t *cb = new cblock_t();
    hexrays_register_python_clearable_instance(cb, hxclr_cblock);
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
#ifdef WITH_HEXRAYS
static int _debug_hexrays_ctree = -1;
static bool is_debug_hexrays_ctree()
{
  if ( _debug_hexrays_ctree < 0 )
    _debug_hexrays_ctree = qgetenv("IDAPYTHON_DEBUG_HEXRAYS_CTREEE");
  return bool(_debug_hexrays_ctree);
}

//-------------------------------------------------------------------------
static void debug_hexrays_ctree(const char *format, ...)
{
  if ( is_debug_hexrays_ctree() )
  {
    va_list va;
    va_start(va, format);
    msg("HEXRAYS CTREE: ");
    vmsg(format, va);
    va_end(va);
  }
}

//-------------------------------------------------------------------------
// The hexrays+IDAPython term sequence goes as follows:
//   - hexrays is unloaded before IDAPython
//   - we receive the notification about hexrays going away and:
//        + call hexrays_unloading__clear_python_clearable_references();
//        + set 'hexdsp = exit_time_dummy_hexdsp' (an NOP hexdsp)
//   - we receive 'ui_term', and
//        + set 'hexdsp = init_time_dummy_hexdsp'
//   - IDAPython is unloaded, and during cleanup of the runtime data,
//     reachable citem_t's will get destroyed.
// => this means we vill receive 'hx_c*t_cleanup' and 'hx_remitem'
//    notifications most likely in the init_time_dummy_hexdsp(),
//    rather than in exit_time_dummy_hexdsp() -- which is more than
//    just a little counter-intuitive.
static void *idaapi init_time_dummy_hexdsp(int code, ...)
{
  switch ( code )
  {
    case hx_remitem:
    case hx_cexpr_t_cleanup:
    case hx_cinsn_t_cleanup:
      {
#ifdef _DEBUG
        va_list va;
        va_start(va, code);
        citem_t *item = va_arg(va, citem_t *);
        // catch leaks
        if ( code == hx_cexpr_t_cleanup )
          QASSERT(30497, ((cexpr_t *)item)->op == cot_empty && ((cexpr_t *)item)->n == NULL);
        else if ( code == hx_cinsn_t_cleanup )
          QASSERT(30498, ((cinsn_t *)item)->op == cit_empty && ((cinsn_t *)item)->cblock == NULL);
        else // code == hx_remitem
          QASSERT(30529, item->op == cot_empty || item->op == cit_empty);
        va_end(va);
#endif
      }
      break;
    default:
      warning("Hex-Rays Decompiler got called from Python without being loaded");
      break;
  }
  return NULL;
}

hexdsp_t *hexdsp = init_time_dummy_hexdsp;
#endif // WITH_HEXRAYS

#define MODULE_NAME   "Hex-Rays Decompiler" // Copied from vd/hexrays.cpp

//-------------------------------------------------------------------------
qstring_printer_t *new_qstring_printer_t(const cfunc_t *f, bool tags)
{
  return new qstring_printer_t(f, * (new qstring()), tags);
}

//-------------------------------------------------------------------------
void delete_qstring_printer_t(qstring_printer_t *qs)
{
  delete &(qs->s);
  delete qs;
}

//---------------------------------------------------------------------
static ref_t hexrays_python_call(ref_t fct, ref_t args)
{
  PYW_GIL_GET;

  newref_t resultobj(PyEval_CallObject(fct.o, args.o));
  if ( PyErr_Occurred() )
  {
    PyErr_Print();
    return borref_t(Py_None);
  }
  return resultobj;
}

//---------------------------------------------------------------------
static int hexrays_python_intcall(ref_t fct, ref_t args)
{
  PYW_GIL_GET;

  ref_t resultobj = hexrays_python_call(fct, args);
  int result;
  if ( SWIG_IsOK(SWIG_AsVal_int(resultobj.o, &result)) )
    return result;
  msg("IDAPython: Hex-rays python callback returned non-integer; value ignored.\n");
  return 0;
}

//---------------------------------------------------------------------
static bool idaapi __python_custom_viewer_popup_item_callback(void *ud)
{
  PYW_GIL_GET;

  int ret;
  borref_t fct((PyObject *)ud);
  newref_t nil(NULL);
  ret = hexrays_python_intcall(fct, nil);
  return ret ? true : false;
}

//-------------------------------------------------------------------------
//                        Clearable objects
//-------------------------------------------------------------------------
// A set of objects that were created from IDAPython. This is necessary in
// order to delete those objects before the hexrays plugin is unloaded.
// Otherwise, IDAPython will still delete them, but the plugin's 'hexdsp'
// dispatcher function will point to dlclose()'d code.
enum hx_clearable_type_t
{
  hxclr_unknown = 0,
  hxclr_cfuncptr,
  hxclr_cinsn,
  hxclr_cexpr,
  hxclr_cblock,
};
struct hx_clearable_t
{
  void *ptr;
  hx_clearable_type_t type;
};
DECLARE_TYPE_AS_MOVABLE(hx_clearable_t);

typedef qvector<hx_clearable_t> hx_clearables_t;
static hx_clearables_t python_clearables;
void hexrays_unloading__clear_python_clearable_references(void)
{
  debug_hexrays_ctree("hexrays_unloading__clear_python_clearable_references()\n");
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
  {
    const hx_clearable_t &hxc = python_clearables[i];
    debug_hexrays_ctree("cleaning up %p (%d)\n", hxc.ptr, int(hxc.type));
    switch ( hxc.type )
    {
      case hxclr_cfuncptr:
        ((cfuncptr_t*) hxc.ptr)->reset();
        break;
      case hxclr_cinsn:
        ((cinsn_t *) hxc.ptr)->cleanup();
        break;
      case hxclr_cexpr:
        ((cexpr_t *) hxc.ptr)->cleanup();
        break;
      case hxclr_cblock:
        ((cblock_t *) hxc.ptr)->clear();
        break;
      default: INTERR(30499);
    }
  }
}

//-------------------------------------------------------------------------
void hexrays_register_python_clearable_instance(
        void *ptr,
        hx_clearable_type_t type)
{
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
    if ( python_clearables[i].ptr == ptr )
      return;
  hx_clearable_t &hxc = python_clearables.push_back();
  hxc.ptr = ptr;
  hxc.type = type;
  debug_hexrays_ctree("registered %p\n", hxc.ptr);
}

//-------------------------------------------------------------------------
// Note: drop ownership, but don't cleanup! The cleanup will be done by
// the SWiG destructor wrapper if this object's still owned by the Python
// runtime, or it will be done by the C tree itself later.
void hexrays_deregister_python_clearable_instance(void *ptr)
{
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
  {
    const hx_clearable_t &hxc = python_clearables[i];
    if ( hxc.ptr == ptr )
    {
      python_clearables.erase(python_clearables.begin() + i);
      debug_hexrays_ctree("de-registered %p\n", hxc.ptr);
      break;
    }
  }
}

//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
hx_clearable_type_t hexrays_is_registered_python_clearable_instance(
        const void *ptr)
{
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
    if ( python_clearables[i].ptr == ptr )
      return python_clearables[i].type;
  return hxclr_unknown;
}
#endif

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
cfuncptr_t _decompile(func_t *pfn, hexrays_failure_t *hf)
{
  try
  {
    cfuncptr_t cfunc = decompile(pfn, hf);
    return cfunc;
  }
  catch(...)
  {
    error("Hex-Rays Python: decompiler threw an exception.\n");
  }
  return cfuncptr_t(0);
}

//-------------------------------------------------------------------------
static bool is_hexrays_plugin(const plugin_info_t *pinfo)
{
  bool is_hx = false;
  if ( pinfo != NULL && pinfo->entry != NULL )
  {
    const plugin_t *p = pinfo->entry;
    if ( streq(p->wanted_name, MODULE_NAME) )
      is_hx = true;
  }
  return is_hx;
}

//-------------------------------------------------------------------------
static void try_init()
{
  init_hexrays_plugin(0);
  if ( hexdsp != NULL )
    msg("IDAPython Hex-Rays bindings initialized.\n");
}

//-------------------------------------------------------------------------
static void *idaapi exit_time_dummy_hexdsp(int code, ...)
{
/* This callback exists to avoid crashes if the user calls any hexrays functions
   after unloading the decompiler.
  switch ( code )
  {
    case hx_cexpr_t_cleanup: break;
    case hx_cinsn_t_cleanup: break;
    default: break;
  }*/
  return NULL;
}

//-------------------------------------------------------------------------
inline bool hexdsp_inited()
{
  return hexdsp != NULL
      && hexdsp != init_time_dummy_hexdsp
      && hexdsp != exit_time_dummy_hexdsp;
}

//-------------------------------------------------------------------------
static void hexrays_unloading__unhook_hooks(void);
static ssize_t idaapi ida_hexrays_ui_notification(void *, int code, va_list va)
{
  switch ( code )
  {
    case ui_plugin_loaded:
      if ( !hexdsp_inited() )
      {
        const plugin_info_t *pi = va_arg(va, plugin_info_t *);
        if ( is_hexrays_plugin(pi) )
          try_init();
      }
      break;

    case ui_plugin_unloading:
      if ( hexdsp != NULL && hexdsp != init_time_dummy_hexdsp )
      {
        const plugin_info_t *pi = va_arg(va, plugin_info_t *);
        if ( is_hexrays_plugin(pi) )
        {
          QASSERT(30500, hexdsp != exit_time_dummy_hexdsp);

          // Make sure all the refcounted objects are cleared right away.
          hexrays_unloading__clear_python_clearable_references();

          // Make sure all hooks are unhooked
          hexrays_unloading__unhook_hooks();

          hexdsp = exit_time_dummy_hexdsp;
        }
      }
      break;
    case ui_term:
      hexdsp = init_time_dummy_hexdsp;
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
static void ida_hexrays_term(void)
{
  idapython_unhook_from_notification_point(
          HT_UI, ida_hexrays_ui_notification, NULL);
}

//-------------------------------------------------------------------------
static void ida_hexrays_closebase(void) {}
//</code(py_hexrays)>
%}

%ignore init_hexrays_plugin;
%rename(init_hexrays_plugin) py_init_hexrays_plugin;

%ignore install_hexrays_callback;
%ignore remove_hexrays_callback;

%ignore decompile_many;
%rename (decompile_many) py_decompile_many;

%ignore decompile;
%ignore decompile_func;
%ignore decompile_snippet;
%rename (decompile) decompile_func;

%ignore get_widget_vdui;
%rename (get_widget_vdui) py_get_widget_vdui;

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

%ignore decompile;

//---------------------------------------------------------------------
%define %python_callback_in(CB)
%typemap(check) CB {
  if (!PyCallable_Check($1))
  {
      PyErr_SetString(PyExc_TypeError, "Need a callable object!");
      return NULL;
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

%template (fnum_array) wrapped_array_t<uint16,6>;
%extend fnumber_t {
  wrapped_array_t<uint16,6> __get_fnum() {
    return wrapped_array_t<uint16,6>($self->fnum);
  }

  %pythoncode {
    fnum = property(__get_fnum)
  }
}


%inline %{
//<inline(py_hexrays)>
//-------------------------------------------------------------------------
void py_debug_hexrays_ctree(const char *msg)
{
  debug_hexrays_ctree(msg);
}

//---------------------------------------------------------------------
bool py_init_hexrays_plugin(int flags=0)
{
  // Only initialize one time
  return hexdsp_inited() || init_hexrays_plugin(flags);
}

cfuncptr_t _decompile(func_t *pfn, hexrays_failure_t *hf);

//-------------------------------------------------------------------------
bool py_decompile_many(const char *outfile, PyObject *funcaddrs, int flags)
{
  eavec_t leas, *eas = NULL;
  if ( funcaddrs != Py_None )
  {
    if ( !PySequence_Check(funcaddrs)
      || PyW_PyListToEaVec(&leas, funcaddrs) < 0 )
    {
      return false;
    }
    eas = &leas;
  }
  return decompile_many(outfile, eas, flags);
}

//-------------------------------------------------------------------------
// Some examples will want to use action_handler_t's whose update() method
// calls get_widget_vdui() to figure out whether the action should be enabled
// for the current widget. Unfortunately, if hexrays is first unloaded before
// the widget cleanup is performed (e.g., while loading another IDB),
// the action would crash. Ideally we should wrap all toplevel calls
// with such wrappers, but it doesn't seem to be really necessary at the
// moment: only corner-cases will reveal this issue (reported by
// the idapython_hr-decompile test.)
vdui_t *py_get_widget_vdui(TWidget *f)
{
  return hexdsp_inited() ? get_widget_vdui(f) : NULL;
}

inline boundaries_iterator_t py_boundaries_find(const boundaries_t *map, const cinsn_t *key)
{
  return boundaries_find(map, key);
}

inline boundaries_iterator_t py_boundaries_insert(boundaries_t *map, const cinsn_t *key, const rangeset_t &val)
{
  return boundaries_insert(map, key, val);
}

//-------------------------------------------------------------------------
void py_term_hexrays_plugin(void) {}
//</inline(py_hexrays)>
%}

%ignore Hexrays_Callback;

%inline %{
//<inline(py_hexrays_hooks)>
//-------------------------------------------------------------------------
// Hexrays hooks
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va);
class control_graph_t;

class Hexrays_Hooks
{
  friend ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va);
  static ssize_t handle_create_hint_output(PyObject *o, vdui_t *, qstring *out_hint, int *out_implines)
  {
    ssize_t rc = 0;
    if ( o != NULL && PySequence_Check(o) && PySequence_Size(o) == 3 )
    {
      newref_t py_rc(PySequence_GetItem(o, 0));
      newref_t py_hint(PySequence_GetItem(o, 1));
      newref_t py_implines(PySequence_GetItem(o, 2));
      if ( IDAPyInt_Check(py_rc.o) && IDAPyStr_Check(py_hint.o) && IDAPyInt_Check(py_implines.o) )
      {
        char *buf;
        Py_ssize_t bufsize;
        if ( IDAPyBytes_AsMemAndSize(py_hint.o, &buf, &bufsize) > -1 )
        {
          rc = IDAPyInt_AsLong(py_rc.o);
          qstring tmp(buf, bufsize);
          out_hint->swap(tmp);
          *out_implines = IDAPyInt_AsLong(py_implines.o);
        }
      }
    }
    return rc;
  }

  bool hooked;

public:
  Hexrays_Hooks();
  virtual ~Hexrays_Hooks();

  bool hook()
  {
    if ( !hooked )
      hooked = install_hexrays_callback(Hexrays_Callback, this);
    return hooked;
  }
  bool unhook()
  {
    if ( hooked )
      hooked = !remove_hexrays_callback(Hexrays_Callback, this);
    return !hooked;
  }

  // hookgenHEXRAYS:methods
virtual int flowchart(qflow_chart_t * fc) {qnotused(fc); return 0;}
virtual int stkpnts(mbl_array_t * mba, stkpnts_t * stkpnts) {qnotused(mba); qnotused(stkpnts); return 0;}
virtual int prolog(mbl_array_t * mba, qflow_chart_t * fc, bitset_t * reachable_blocks) {qnotused(mba); qnotused(fc); qnotused(reachable_blocks); return 0;}
virtual int microcode(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int preoptimized(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int locopt(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int prealloc(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int glbopt(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int structural(control_graph_t * ct) {qnotused(ct); return 0;}
virtual int maturity(cfunc_t * cfunc, ctree_maturity_t new_maturity) {qnotused(cfunc); qnotused(new_maturity); return 0;}
virtual int interr(int  errcode) {qnotused(errcode); return 0;}
virtual int combine(mblock_t * blk, minsn_t * insn) {qnotused(blk); qnotused(insn); return 0;}
virtual int print_func(cfunc_t * cfunc, vc_printer_t * vp) {qnotused(cfunc); qnotused(vp); return 0;}
virtual int func_printed(cfunc_t * cfunc) {qnotused(cfunc); return 0;}
virtual int resolve_stkaddrs(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int open_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int switch_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int refresh_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int close_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int keyboard(vdui_t * vu, int key_code, int shift_state) {qnotused(vu); qnotused(key_code); qnotused(shift_state); return 0;}
virtual int right_click(vdui_t * vu) {qnotused(vu); return 0;}
virtual int double_click(vdui_t * vu, int shift_state) {qnotused(vu); qnotused(shift_state); return 0;}
virtual int curpos(vdui_t * vu) {qnotused(vu); return 0;}
virtual PyObject * create_hint(vdui_t * vu) {qnotused(vu); Py_RETURN_NONE;}
virtual int text_ready(vdui_t * vu) {qnotused(vu); return 0;}
virtual int populating_popup(TWidget * widget, TPopupMenu * popup_handle, vdui_t * vu) {qnotused(widget); qnotused(popup_handle); qnotused(vu); return 0;}
virtual int lvar_name_changed(vdui_t * vu, lvar_t * v, const char * name, bool is_user_name) {qnotused(vu); qnotused(v); qnotused(name); qnotused(is_user_name); return 0;}
virtual int lvar_type_changed(vdui_t * vu, lvar_t * v, const tinfo_t * tinfo) {qnotused(vu); qnotused(v); qnotused(tinfo); return 0;}
virtual int lvar_cmt_changed(vdui_t * vu, lvar_t * v, const char * cmt) {qnotused(vu); qnotused(v); qnotused(cmt); return 0;}
virtual int lvar_mapping_changed(vdui_t * vu, lvar_t * from, lvar_t * to) {qnotused(vu); qnotused(from); qnotused(to); return 0;}
virtual int cmt_changed(cfunc_t * cfunc, const treeloc_t * loc, const char * cmt) {qnotused(cfunc); qnotused(loc); qnotused(cmt); return 0;}
};
//</inline(py_hexrays_hooks)>
%}

%{
//<code(py_hexrays_hooks)>
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class Hexrays_Hooks *proxy = (class Hexrays_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( event )
    {
      // hookgenHEXRAYS:notifications
case hxe_flowchart:
{
  qflow_chart_t * fc = va_arg(va, qflow_chart_t *);
  ret = proxy->flowchart(fc);
}
break;

case hxe_stkpnts:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  stkpnts_t * stkpnts = va_arg(va, stkpnts_t *);
  ret = proxy->stkpnts(mba, stkpnts);
}
break;

case hxe_prolog:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  qflow_chart_t * fc = va_arg(va, qflow_chart_t *);
  bitset_t * reachable_blocks = va_arg(va, bitset_t *);
  ret = proxy->prolog(mba, fc, reachable_blocks);
}
break;

case hxe_microcode:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->microcode(mba);
}
break;

case hxe_preoptimized:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->preoptimized(mba);
}
break;

case hxe_locopt:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->locopt(mba);
}
break;

case hxe_prealloc:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->prealloc(mba);
}
break;

case hxe_glbopt:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->glbopt(mba);
}
break;

case hxe_structural:
{
  control_graph_t * ct = va_arg(va, control_graph_t *);
  ret = proxy->structural(ct);
}
break;

case hxe_maturity:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  ctree_maturity_t new_maturity = ctree_maturity_t(va_arg(va, int));
  ret = proxy->maturity(cfunc, new_maturity);
}
break;

case hxe_interr:
{
  int  errcode = va_arg(va, int );
  ret = proxy->interr(errcode);
}
break;

case hxe_combine:
{
  mblock_t * blk = va_arg(va, mblock_t *);
  minsn_t * insn = va_arg(va, minsn_t *);
  ret = proxy->combine(blk, insn);
}
break;

case hxe_print_func:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  vc_printer_t * vp = va_arg(va, vc_printer_t *);
  ret = proxy->print_func(cfunc, vp);
}
break;

case hxe_func_printed:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  ret = proxy->func_printed(cfunc);
}
break;

case hxe_resolve_stkaddrs:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->resolve_stkaddrs(mba);
}
break;

case hxe_open_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->open_pseudocode(vu);
}
break;

case hxe_switch_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->switch_pseudocode(vu);
}
break;

case hxe_refresh_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->refresh_pseudocode(vu);
}
break;

case hxe_close_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->close_pseudocode(vu);
}
break;

case hxe_keyboard:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  int key_code = va_arg(va, int);
  int shift_state = va_arg(va, int);
  ret = proxy->keyboard(vu, key_code, shift_state);
}
break;

case hxe_right_click:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->right_click(vu);
}
break;

case hxe_double_click:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  int shift_state = va_arg(va, int);
  ret = proxy->double_click(vu, shift_state);
}
break;

case hxe_curpos:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->curpos(vu);
}
break;

case hxe_create_hint:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  qstring * result_hint = va_arg(va, qstring *);
  int * implines = va_arg(va, int *);
  PyObject * _tmp = proxy->create_hint(vu);
  ret = Hexrays_Hooks::handle_create_hint_output(_tmp, vu, result_hint, implines);
}
break;

case hxe_text_ready:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->text_ready(vu);
}
break;

case hxe_populating_popup:
{
  TWidget * widget = va_arg(va, TWidget *);
  TPopupMenu * popup_handle = va_arg(va, TPopupMenu *);
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->populating_popup(widget, popup_handle, vu);
}
break;

case lxe_lvar_name_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * v = va_arg(va, lvar_t *);
  const char * name = va_arg(va, const char *);
  bool is_user_name = bool(va_arg(va, int));
  ret = proxy->lvar_name_changed(vu, v, name, is_user_name);
}
break;

case lxe_lvar_type_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * v = va_arg(va, lvar_t *);
  const tinfo_t * tinfo = va_arg(va, const tinfo_t *);
  ret = proxy->lvar_type_changed(vu, v, tinfo);
}
break;

case lxe_lvar_cmt_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * v = va_arg(va, lvar_t *);
  const char * cmt = va_arg(va, const char *);
  ret = proxy->lvar_cmt_changed(vu, v, cmt);
}
break;

case lxe_lvar_mapping_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * from = va_arg(va, lvar_t *);
  lvar_t * to = va_arg(va, lvar_t *);
  ret = proxy->lvar_mapping_changed(vu, from, to);
}
break;

case hxe_cmt_changed:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  const treeloc_t * loc = va_arg(va, const treeloc_t *);
  const char * cmt = va_arg(va, const char *);
  ret = proxy->cmt_changed(cfunc, loc, cmt);
}
break;

    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in Hexrays Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
}

//-------------------------------------------------------------------------
static qvector<Hexrays_Hooks*> hexrays_hooks_instances;

//-------------------------------------------------------------------------
static void hexrays_unloading__unhook_hooks(void)
{
  for ( size_t i = 0, n = hexrays_hooks_instances.size(); i < n; ++i )
    hexrays_hooks_instances[i]->unhook();
}

//-------------------------------------------------------------------------
Hexrays_Hooks::Hexrays_Hooks()
  : hooked(false)
{
  hexrays_hooks_instances.push_back(this);
}

//-------------------------------------------------------------------------
Hexrays_Hooks::~Hexrays_Hooks()
{
  hexrays_hooks_instances.del(this);
  unhook();
}
//</code(py_hexrays_hooks)>
%}

%include "hexrays.hpp"
%exception; // Delete & restore handlers
%exception_set_default_handlers();

// These are microcode-related. Let's not expose them right now.
/* %template(ivl_t) ivl_tpl<uval_t>; */
/* %template(ivlset_t) ivlset_tpl<ivl_t, uval_t>; */
/* %template(array_of_ivlsets) qvector<ivlset_t>; */

%pythoncode %{
#<pycode(py_hexrays)>
import ida_funcs

hexrays_failure_t.__str__ = lambda self: str(self.str)

# ---------------------------------------------------------------------
class DecompilationFailure(Exception):
    """ Raised on a decompilation error.

    The associated hexrays_failure_t object is stored in the
    'info' member of this exception. """

    def __init__(self, info):
        Exception.__init__(self, 'Decompilation failed: %s' % (str(info), ))
        self.info = info
        return

# ---------------------------------------------------------------------
def decompile(ea, hf=None):
    if isinstance(ea, (int, long)):
        func = ida_funcs.get_func(ea)
        if not func: return
    elif type(ea) == ida_funcs.func_t:
        func = ea
    else:
        raise RuntimeError('arg 1 of decompile expects either ea_t or cfunc_t argument')

    if hf is None:
        hf = hexrays_failure_t()

    ptr = _decompile(func, hf)

    if ptr.__deref__() is None:
        raise DecompilationFailure(hf)

    return ptr

# ---------------------------------------------------------------------
# stringify all string types
#qtype.__str__ = qtype.c_str
#qstring.__str__ = qstring.c_str
#citem_cmt_t.__str__ = citem_cmt_t.c_str

# ---------------------------------------------------------------------
# listify all list types
import ida_idaapi
ida_idaapi._listify_types(
        cinsnptrvec_t,
        ctree_items_t,
        qvector_lvar_t,
        qvector_carg_t,
        qvector_ccase_t,
        hexwarns_t,
        history_t,
        lvar_saved_infos_t)

def citem_to_specific_type(self):
    """ cast the citem_t object to its more specific type, either cexpr_t or cinsn_t. """

    if self.op >= cot_empty and self.op <= cot_last:
        return self.cexpr
    elif self.op >= cit_empty and self.op < cit_end:
        return self.cinsn

    raise RuntimeError('unknown op type %s' % (repr(self.op), ))
citem_t.to_specific_type = property(citem_to_specific_type)

""" array used for translating cinsn_t->op type to their names. """
cinsn_t.op_to_typename = {}
for k in dir(_ida_hexrays):
    if k.startswith('cit_'):
        cinsn_t.op_to_typename[getattr(_ida_hexrays, k)] = k[4:]

""" array used for translating cexpr_t->op type to their names. """
cexpr_t.op_to_typename = {}
for k in dir(_ida_hexrays):
    if k.startswith('cot_'):
        cexpr_t.op_to_typename[getattr(_ida_hexrays, k)] = k[4:]

def property_op_to_typename(self):
    return self.op_to_typename[self.op]
cinsn_t.opname = property(property_op_to_typename)
cexpr_t.opname = property(property_op_to_typename)

def cexpr_operands(self):
    """ return a dictionary with the operands of a cexpr_t. """

    if self.op >= cot_comma and self.op <= cot_asgumod or \
        self.op >= cot_lor and self.op <= cot_fdiv or \
        self.op == cot_idx:
        return {'x': self.x, 'y': self.y}

    elif self.op == cot_tern:
        return {'x': self.x, 'y': self.y, 'z': self.z}

    elif self.op in [cot_fneg, cot_neg, cot_sizeof] or \
        self.op >= cot_lnot and self.op <= cot_predec:
        return {'x': self.x}

    elif self.op == cot_cast:
        return {'type': self.type, 'x': self.x}

    elif self.op == cot_call:
        return {'x': self.x, 'a': self.a}

    elif self.op in [cot_memref, cot_memptr]:
        return {'x': self.x, 'm': self.m}

    elif self.op == cot_num:
        return {'n': self.n}

    elif self.op == cot_fnum:
        return {'fpc': self.fpc}

    elif self.op == cot_str:
        return {'string': self.string}

    elif self.op == cot_obj:
        return {'obj_ea': self.obj_ea}

    elif self.op == cot_var:
        return {'v': self.v}

    elif self.op == cot_helper:
        return {'helper': self.helper}

    raise RuntimeError('unknown op type %s' % self.opname)
cexpr_t.operands = property(cexpr_operands)

def cinsn_details(self):
    """ return the details pointer for the cinsn_t object depending on the value of its op member. \
        this is one of the cblock_t, cif_t, etc. objects. """

    if self.op not in self.op_to_typename:
        raise RuntimeError('unknown item->op type')

    opname = self.opname
    if opname == 'empty':
        return self

    if opname in ['break', 'continue']:
        return None

    return getattr(self, 'c' + opname)
cinsn_t.details = property(cinsn_details)

def cblock_iter(self):

    iter = self.begin()
    for i in range(self.size()):
        yield iter.cur
        next(iter)

    return
cblock_t.__iter__ = cblock_iter
cblock_t.__len__ = cblock_t.size

# cblock.find(cinsn_t) -> returns the iterator positioned at the given item
def cblock_find(self, item):

    iter = self.begin()
    for i in range(self.size()):
        if iter.cur == item:
            return iter
        next(iter)

    return
cblock_t.find = cblock_find

# cblock.index(cinsn_t) -> returns the index of the given item
def cblock_index(self, item):

    iter = self.begin()
    for i in range(self.size()):
        if iter.cur == item:
            return i
        next(iter)

    return
cblock_t.index = cblock_index

# cblock.at(int) -> returns the item at the given index index
def cblock_at(self, index):

    iter = self.begin()
    for i in range(self.size()):
        if i == index:
            return iter.cur
        next(iter)

    return
cblock_t.at = cblock_at

# cblock.remove(cinsn_t)
def cblock_remove(self, item):

    iter = self.find(item)
    self.erase(iter)

    return
cblock_t.remove = cblock_remove

# cblock.insert(index, cinsn_t)
def cblock_insert(self, index, item):

    pos = self.at(index)
    iter = self.find(pos)
    self.insert(iter, item)

    return
cblock_t.insert = cblock_insert

cfuncptr_t.__str__ = lambda self: str(self.__deref__())

import ida_typeinf
def cfunc_type(self):
    """ Get the function's return type tinfo_t object. """
    tif = ida_typeinf.tinfo_t()
    result = self.get_func_type(tif)
    if not result:
        return
    return tif
cfunc_t.type = property(cfunc_type)
cfuncptr_t.type = property(lambda self: self.__deref__().type)

cfunc_t.arguments = property(lambda self: [o for o in self.lvars if o.is_arg_var])
cfuncptr_t.arguments = property(lambda self: self.__deref__().arguments)

cfunc_t.lvars = property(cfunc_t.get_lvars)
cfuncptr_t.lvars = property(lambda self: self.__deref__().lvars)
cfunc_t.warnings = property(cfunc_t.get_warnings)
cfuncptr_t.warnings = property(lambda self: self.__deref__().warnings)
cfunc_t.pseudocode = property(cfunc_t.get_pseudocode)
cfuncptr_t.pseudocode = property(lambda self: self.__deref__().get_pseudocode())
cfunc_t.eamap = property(cfunc_t.get_eamap)
cfuncptr_t.eamap = property(lambda self: self.__deref__().get_eamap())
cfunc_t.boundaries = property(cfunc_t.get_boundaries)
cfuncptr_t.boundaries = property(lambda self: self.__deref__().get_boundaries())

#pragma SWIG nowarn=+503

lvar_t.used = property(lvar_t.used)
lvar_t.typed = property(lvar_t.typed)
lvar_t.mreg_done = property(lvar_t.mreg_done)
lvar_t.has_nice_name = property(lvar_t.has_nice_name)
lvar_t.is_unknown_width = property(lvar_t.is_unknown_width)
lvar_t.has_user_info = property(lvar_t.has_user_info)
lvar_t.has_user_name = property(lvar_t.has_user_name)
lvar_t.has_user_type = property(lvar_t.has_user_type)
lvar_t.is_result_var = property(lvar_t.is_result_var)
lvar_t.is_arg_var = property(lvar_t.is_arg_var)
lvar_t.is_fake_var = property(lvar_t.is_fake_var)
lvar_t.is_overlapped_var = property(lvar_t.is_overlapped_var)
lvar_t.is_floating_var = property(lvar_t.is_floating_var)
lvar_t.is_spoiled_var = property(lvar_t.is_spoiled_var)
lvar_t.is_mapdst_var = property(lvar_t.is_mapdst_var)

# dictify all dict-like types
def _map_as_dict(maptype, name, keytype, valuetype):

    maptype.keytype = keytype
    maptype.valuetype = valuetype

    for fctname in ['begin', 'end', 'first', 'second', 'next', \
                        'find', 'insert', 'erase', 'clear', 'size']:
        fct = getattr(_ida_hexrays, name + '_' + fctname)
        setattr(maptype, '__' + fctname, fct)

    maptype.__len__ = maptype.size
    maptype.__getitem__ = maptype.at

    maptype.begin = lambda self, *args: self.__begin(self, *args)
    maptype.end = lambda self, *args: self.__end(self, *args)
    maptype.first = lambda self, *args: self.__first(*args)
    maptype.second = lambda self, *args: self.__second(*args)
    maptype.next = lambda self, *args: self.__next(*args)
    maptype.find = lambda self, *args: self.__find(self, *args)
    maptype.insert = lambda self, *args: self.__insert(self, *args)
    maptype.erase = lambda self, *args: self.__erase(self, *args)
    maptype.clear = lambda self, *args: self.__clear(self, *args)
    maptype.size = lambda self, *args: self.__size(self, *args)

    def _map___iter__(self):
        """ Iterate over dictionary keys. """
        return self.iterkeys()
    maptype.__iter__ = _map___iter__

    def _map___getitem__(self, key):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of key should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        return self.second(self.find(key))
    maptype.__getitem__ = _map___getitem__

    def _map___setitem__(self, key, value):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if not isinstance(value, self.valuetype):
            raise KeyError('type of `value` should be ' + repr(self.valuetype) + ' but got ' + type(value))
        self.insert(key, value)
        return
    maptype.__setitem__ = _map___setitem__

    def _map___delitem__(self, key):
        """ Removes the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        self.erase(self.find(key))
        return
    maptype.__delitem__ = _map___delitem__

    def _map___contains__(self, key):
        """ Returns true if the specified key exists in the . """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if self.find(key) != self.end():
            return True
        return False
    maptype.__contains__ = _map___contains__

    def _map_clear(self):
        self.clear()
        return
    maptype.clear = _map_clear

    def _map_copy(self):
        ret = {}
        for k in self.iterkeys():
            ret[k] = self[k]
        return ret
    maptype.copy = _map_copy

    def _map_get(self, key, default=None):
        if key in self:
            return self[key]
        return default
    maptype.get = _map_get

    def _map_iterkeys(self):
        iter = self.begin()
        while iter != self.end():
            yield self.first(iter)
            iter = self.next(iter)
        return
    maptype.iterkeys = _map_iterkeys

    def _map_itervalues(self):
        iter = self.begin()
        while iter != self.end():
            yield self.second(iter)
            iter = self.next(iter)
        return
    maptype.itervalues = _map_itervalues

    def _map_iteritems(self):
        iter = self.begin()
        while iter != self.end():
            yield (self.first(iter), self.second(iter))
            iter = self.next(iter)
        return
    maptype.iteritems = _map_iteritems

    def _map_keys(self):
        return list(self.iterkeys())
    maptype.keys = _map_keys

    def _map_values(self):
        return list(self.itervalues())
    maptype.values = _map_values

    def _map_items(self):
        return list(self.iteritems())
    maptype.items = _map_items

    def _map_has_key(self, key):
        return key in self
    maptype.has_key = _map_has_key

    def _map_pop(self, key):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        ret = self[key]
        del self[key]
        return ret
    maptype.pop = _map_pop

    def _map_popitem(self):
        """ Sets the value associated with the provided key. """
        if len(self) == 0:
            raise KeyError('key not found')
        key = self.keys()[0]
        return (key, self.pop(key))
    maptype.popitem = _map_popitem

    def _map_setdefault(self, key, default=None):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key in self:
            return self[key]
        self[key] = default
        return default
    maptype.setdefault = _map_setdefault

#_map_as_dict(user_labels_t, 'user_labels', (int, long), qstring)
_map_as_dict(user_cmts_t, 'user_cmts', treeloc_t, citem_cmt_t)
_map_as_dict(user_numforms_t, 'user_numforms', operand_locator_t, number_format_t)
_map_as_dict(user_iflags_t, 'user_iflags', citem_locator_t, int)
import ida_pro
_map_as_dict(user_unions_t, 'user_unions', (int, long), ida_pro.intvec_t)
_map_as_dict(eamap_t, 'eamap', long, cinsnptrvec_t)
import ida_range
_map_as_dict(boundaries_t, 'boundaries', cinsn_t, ida_range.rangeset_t)

#
# Object ownership
#
def _call_with_transferrable_ownership(fun, *args):
    e = args[0]
    was_owned = e.thisown
    res = fun(e, *args[1:])
    # ATM, 'res' doesn't own the resulting cexpr_t.
    # In case 'fun'
    #   - created a new object: we want to own that one in case 'e' was owned
    #   - didn't create a new object: we will remove & re-gain ownership on
    #                                 the same underlying cexpr_t. No biggie.
    if was_owned:
        if res:
            e._maybe_disown_and_deregister()
            res._own_and_register()
    else:
        debug_hexrays_ctree("NOTE: call_with_transferrable_ownership() called with non-IDAPython-owned object. Is this intentional?")
    return res

def lnot(e):
    return _call_with_transferrable_ownership(_ll_lnot, e)

def make_ref(e):
    return _call_with_transferrable_ownership(_ll_make_ref, e)

def dereference(e, ptrsize, is_float=False):
    return _call_with_transferrable_ownership(_ll_dereference, e, ptrsize, is_float)

def call_helper(rettype, args, *rest):
    res = _ll_call_helper(rettype, args, *rest)
    if res:
        res._own_and_register()
        if type(args) == carglist_t:
            args.thisown = False
    return res

def new_block():
    res = _ll_new_block()
    if res:
        res._own_and_register()
    return res

def make_num(*args):
    res = _ll_make_num(*args)
    if res:
        res._own_and_register()
    return res

def create_helper(*args):
    res = _ll_create_helper(*args)
    if res:
        res._own_and_register()
    return res

# ----------------

class __cbhooks_t(Hexrays_Hooks):

    instances = []

    def __init__(self, callback):
        self.callback = callback
        self.instances.append(self)
        Hexrays_Hooks.__init__(self)

    def maturity(self, *args): return self.callback(hxe_maturity, *args)
    def interr(self, *args): return self.callback(hxe_interr, **args)
    def print_func(self, *args): return self.callback(hxe_print_func, *args)
    def func_printed(self, *args): return self.callback(hxe_func_printed, *args)
    def open_pseudocode(self, *args): return self.callback(hxe_open_pseudocode, *args)
    def switch_pseudocode(self, *args): return self.callback(hxe_switch_pseudocode, *args)
    def refresh_pseudocode(self, *args): return self.callback(hxe_refresh_pseudocode, *args)
    def close_pseudocode(self, *args): return self.callback(hxe_close_pseudocode, *args)
    def keyboard(self, *args): return self.callback(hxe_keyboard, *args)
    def right_click(self, *args): return self.callback(hxe_right_click, *args)
    def double_click(self, *args): return self.callback(hxe_double_click, *args)
    def curpos(self, *args): return self.callback(hxe_curpos, *args)
    def create_hint(self, *args): return self.callback(hxe_create_hint, *args)
    def text_ready(self, *args): return self.callback(hxe_text_ready, *args)
    def populating_popup(self, *args): return self.callback(hxe_populating_popup, *args)


def install_hexrays_callback(callback):
    "Deprecated. Please use Hexrays_Hooks instead"
    h = __cbhooks_t(callback)
    h.hook()
    return True

def remove_hexrays_callback(callback):
    "Deprecated. Please use Hexrays_Hooks instead"
    for inst in __cbhooks_t.instances:
        if inst.callback == callback:
            inst.unhook()
            __cbhooks_t.instances.remove(inst)
            return 1
    return 0

#</pycode(py_hexrays)>
%}

//-------------------------------------------------------------------------
%init %{
//<init(py_hexrays)>
idapython_hook_to_notification_point(HT_UI, ida_hexrays_ui_notification, NULL);
//</init(py_hexrays)>
%}
%pythoncode %{
if _BC695:
    get_tform_vdui=get_widget_vdui
    hx_get_tform_vdui=hx_get_widget_vdui
    HEXRAYS_API_MAGIC1=(HEXRAYS_API_MAGIC>>32)
    HEXRAYS_API_MAGIC2=(HEXRAYS_API_MAGIC&0xFFFFFFFF)

%}
%init %{
{
  module_callbacks_t module_lfc;
  module_lfc.closebase = ida_hexrays_closebase;
  module_lfc.term = ida_hexrays_term;
  register_module_lifecycle_callbacks(module_lfc);
}
%}
