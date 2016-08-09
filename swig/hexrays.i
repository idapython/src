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
namespace Menus
{
  class TPopupMenu;
}
using Menus::TPopupMenu;
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
%ignore string_printer_t::vprint;
%ignore vdui_t::vdui_t;
%ignore cblock_t::find;
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
%ignore cexpr_t::contains_expr;
%ignore cexpr_t::contains_expr;
%ignore cexpr_t::cexpr_t(mbl_array_t *mba, const lvar_t &v);
%ignore cexpr_t::is_type_partial;
%ignore cexpr_t::set_type_partial;
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

%extend cfunc_t {
    %immutable argidx;

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

#if !defined(__MAC__) || (MACSDKVER >= 1060)
#define HAS_MAP_AT
#endif

// Provide trivial std::map facade so basic operations are available.
template<class key_type, class mapped_type> class std::map {
public:
#ifdef HAS_MAP_AT
    mapped_type& at(const key_type& _Keyval);
#endif
    size_t size() const;
};

#ifndef HAS_MAP_AT
#warning "std::map doesn't provide at(). Augmenting it."
%extend std::map {
    mapped_type& at(const key_type& _Keyval) { return $self->operator[](_Keyval); }
}
#endif

//---------------------------------------------------------------------
%extend citem_t {
    // define these two struct members that can be used for casting.
    cinsn_t *cinsn const { return (cinsn_t *)self; }
    cexpr_t *cexpr const { return (cexpr_t *)self; }
};

//---------------------------------------------------------------------
// swig doesn't very much like the way the union is done in this class so we need to wrap all these up.
#define CITEM_MEMBER_REF(name)                                          \
  c##name##_t *c##name const { if ( self->op == cit_##name ) { return self->c##name; } else { return NULL; } }

%extend cinsn_t {
  CITEM_MEMBER_REF(block);
  CITEM_MEMBER_REF(expr);
  CITEM_MEMBER_REF(if);
  CITEM_MEMBER_REF(for);
  CITEM_MEMBER_REF(while);
  CITEM_MEMBER_REF(do);
  CITEM_MEMBER_REF(switch);
  CITEM_MEMBER_REF(return);
  CITEM_MEMBER_REF(goto);
  CITEM_MEMBER_REF(asm);

  bool is_epilog() const { return $self == INS_EPILOG; }
};
#undef CITEM_MEMBER_REF

//-------------------------------------------------------------------------
#define CEXPR_MEMBER_REF(type, name) \
  type name const { return self->##name; }

#define CEXPR_CONDITIONAL_MEMBER_REF(type, name, condition, default_value) \
  type name const { if ( condition ) { return self->##name; } else { return default_value; } }

%extend cexpr_t {
  CEXPR_CONDITIONAL_MEMBER_REF(cnumber_t*, n, self->op == cot_num, NULL);
  CEXPR_CONDITIONAL_MEMBER_REF(fnumber_t*, fpc, self->op == cot_fnum, NULL);
  var_ref_t* v const { if ( self->op == cot_var ) { return &self->v; } else { return NULL; } }
  CEXPR_CONDITIONAL_MEMBER_REF(ea_t, obj_ea, self->op == cot_obj, BADADDR);
  CEXPR_MEMBER_REF(int, refwidth);
  CEXPR_CONDITIONAL_MEMBER_REF(cexpr_t*, x, op_uses_x(self->op), NULL);
  CEXPR_CONDITIONAL_MEMBER_REF(cexpr_t*, y, op_uses_y(self->op), NULL);
  CEXPR_CONDITIONAL_MEMBER_REF(carglist_t*, a, self->op == cot_call, NULL);
  CEXPR_CONDITIONAL_MEMBER_REF(int, m, self->op == cot_memptr || self->op == cot_memref, 0);
  CEXPR_CONDITIONAL_MEMBER_REF(cexpr_t*, z, op_uses_z(self->op), NULL);
  CEXPR_CONDITIONAL_MEMBER_REF(int, ptrsize, self->op == cot_ptr || self->op == cot_memptr, 0);
  CEXPR_MEMBER_REF(cinsn_t*, insn);
  CEXPR_CONDITIONAL_MEMBER_REF(char*, helper, self->op == cot_helper, NULL);
  CEXPR_CONDITIONAL_MEMBER_REF(char*, string, self->op == cot_str, NULL);
};

#undef CEXPR_CONDITIONAL_MEMBER_REF
#undef CEXPR_MEMBER_REF

//-------------------------------------------------------------------------
#define CTREE_ITEM_MEMBER_REF(type, name)                               \
  type name const { return self->##name; }

#define CTREE_CONDITIONAL_ITEM_MEMBER_REF(type, name, wanted_citype)     \
  type name const { if ( self->citype == wanted_citype ) { return self->##name; } else { return NULL; } }

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


//~ %template(qwstrvec_t) qvector<qwstring>; // vector of unicode strings
typedef intvec_t svalvec_t; // vector of signed values
typedef intvec_t eavec_t;// vector of addresses

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
%template(boundaries_t) std::map<cinsn_t *, areaset_t>;
// WARNING: The order here is VERY important:
//  1) The '%extend' directive. Note that
//    - the template name must be used, not the typedef (i.e., not 'cfuncptr_t')
//    - to override the destructor, the destructor must have the template parameters.
//  2) The '%ignore' directive.
//    - Again, using the template name, but this time
//    - not qualifying the destructor with template parameters
//  3) The '%template' directive, that will indeed instantiate
//     the template for swig.
%{ void hexrays_deregister_python_cfuncptr_t_instance(cfuncptr_t *fp); %}
%extend qrefcnt_t<cfunc_t> {
  // The typemap above will take care of registering newly-constructed cfuncptr_t
  // instances. However, there's no such thing as a destructor typemap.
  // Therefore, we need to do the grunt work of de-registering ourselves.
  // Note: The 'void' here is important: Without it, SWIG considers it to
  //       be a different destructor (which, of course, makes a ton of sense.)
  ~qrefcnt_t<cfunc_t>(void)
  {
    hexrays_deregister_python_cfuncptr_t_instance($self);
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
    qlist_cinsn_t_iterator &next(void) { (*self)++; return *self; }
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

%ignore add_custom_viewer_popup_item;
%rename(add_custom_viewer_popup_item) py_add_custom_viewer_popup_item;

%ignore install_hexrays_callback;
%rename(install_hexrays_callback) py_install_hexrays_callback;

%ignore remove_hexrays_callback;
%rename(remove_hexrays_callback) py_remove_hexrays_callback;

%ignore decompile_many;
%rename (decompile_many) py_decompile_many;

%ignore get_tform_vdui;
%rename (get_tform_vdui) py_get_tform_vdui;

//-------------------------------------------------------------------------
#if SWIG_VERSION == 0x20012
%typemap(out) cfuncptr_t {}
%typemap(ret) cfuncptr_t
{
  // ret cfuncptr_t
  cfuncptr_t *ni = new cfuncptr_t($1);
  hexrays_register_python_cfuncptr_t_instance(ni);
  $result = SWIG_NewPointerObj(ni, $&1_descriptor, SWIG_POINTER_OWN | 0);
}


%typemap(out) cfuncptr_t *{}
%typemap(ret) cfuncptr_t *
{
  // ret cfuncptr_t*
  cfuncptr_t *ni = new cfuncptr_t(*($1));
  hexrays_register_python_cfuncptr_t_instance(ni);
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

%python_callback_in(PyObject *hx_cblist_callback);
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

%include "hexrays.hpp"
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
