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
%ignore lvar_t::is_promoted_arg;
%ignore lvar_t::lvar_t;
%ignore strtype_info_t::find_strmem;
%ignore file_printer_t::_print;
%ignore file_printer_t;
%ignore qstring_printer_t::qstring_printer_t(const cfunc_t *, qstring &, bool);

%extend cfunc_t {
    %immutable argidx;

   qstring __str__() {
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

#define CITEM_MEMBER_REF(name) \
    name##_t *name const { return self->##name; }

//---------------------------------------------------------------------
// swig doesn't very much like the way the union is done in this class so we need to wrap all these up.
%extend cinsn_t {
    CITEM_MEMBER_REF(cblock)
    CITEM_MEMBER_REF(cexpr)
    CITEM_MEMBER_REF(cif)
    CITEM_MEMBER_REF(cfor)
    CITEM_MEMBER_REF(cwhile)
    CITEM_MEMBER_REF(cdo)
    CITEM_MEMBER_REF(cswitch)
    CITEM_MEMBER_REF(creturn)
    CITEM_MEMBER_REF(cgoto)
    CITEM_MEMBER_REF(casm)
};

#define CEXPR_MEMBER_REF(type, name) \
    type name const { return self->##name; }

%extend cexpr_t {
    CEXPR_MEMBER_REF(cnumber_t*, n)
    CEXPR_MEMBER_REF(fnumber_t*, fpc)
    const var_ref_t& v { return self->v; }
    CEXPR_MEMBER_REF(ea_t, obj_ea)
    CEXPR_MEMBER_REF(int, refwidth)
    CEXPR_MEMBER_REF(cexpr_t*, x)
    CEXPR_MEMBER_REF(cexpr_t*, y)
    CEXPR_MEMBER_REF(carglist_t*, a)
    CEXPR_MEMBER_REF(int, m)
    CEXPR_MEMBER_REF(cexpr_t*, z)
    CEXPR_MEMBER_REF(int, ptrsize)
    CEXPR_MEMBER_REF(cinsn_t*, insn)
    CEXPR_MEMBER_REF(char*, helper)
    CEXPR_MEMBER_REF(char*, string)
};

%extend ctree_item_t {
    CEXPR_MEMBER_REF(citem_t *, it)
    CEXPR_MEMBER_REF(lvar_t*, l)
    CEXPR_MEMBER_REF(cfunc_t*, f)
    const treeloc_t& loc { return self->loc; }
};

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

%extend citem_cmt_t {
    const char *c_str() const { return self->c_str(); }
};

void qswap(cinsn_t &a, cinsn_t &b);
%include "typemaps.i"

%typemap(out) void
{
  Py_INCREF(Py_None);
  $1obj = Py_None;
}

%{

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
static int hexrays_python_call(ref_t fct, ref_t args)
{
    PYW_GIL_GET;

    int result;
    int ecode1 = 0 ;

    newref_t resultobj(PyEval_CallObject(fct.o, args.o));
    if ( resultobj == NULL )
    {
        msg("IDAPython: Hex-rays python callback raised an exception.\n");

        // we can't do much else than clear the exception since this was not called from Python.
        // XXX: print stack trace?
        PyErr_Clear();
        return 0;
    }

    ecode1 = SWIG_AsVal_int(resultobj.o, &result);
    if (SWIG_IsOK(ecode1))
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
    ret = hexrays_python_call(fct, nil);
    return ret ? true : false;
}

//---------------------------------------------------------------------
static int idaapi __hexrays_python_callback(void *ud, hexrays_event_t event, va_list va)
{
    PYW_GIL_GET;

    int ret;
    borref_t fct((PyObject *)ud);
    switch(event)
    {
        case hxe_maturity:
            ///< Ctree maturity level is being changed.
            ///< cfunc_t *cfunc
            ///< ctree_maturity_t new_maturity
            {
                cfunc_t *arg0 = va_arg(va, cfunc_t *);
                ctree_maturity_t arg1 = va_argi(va, ctree_maturity_t);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_cfunc_t, 0 ));
                newref_t args(Py_BuildValue("(iOi)", event, arg0obj.o, arg1));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_interr:
            ///< Internal error has occurred.
            ///< int errcode
            {
                int arg0 = va_argi(va, int);
                newref_t args(Py_BuildValue("(ii)", event, arg0));
                ret = hexrays_python_call(fct, args);
            }
            break;

        case hxe_print_func:
            ///< Printing ctree and generating text.
            ///< cfunc_t *cfunc
            ///< vc_printer_t *vp
            ///< Returns: 1 if text has been generated by the plugin
            {
                cfunc_t *arg0 = va_arg(va, cfunc_t *);
                vc_printer_t *arg1 = va_arg(va, vc_printer_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_cfunc_t, 0 ));
                newref_t arg1obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg1), SWIGTYPE_p_vc_printer_t, 0 ));
                newref_t args(Py_BuildValue("(iOO)", event, arg0obj.o, arg1obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;

        // User interface related events:
        case hxe_open_pseudocode:
            ///< New pseudocode view has been opened.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_switch_pseudocode:
            ///< Existing pseudocode view has been reloaded
            ///< with a new function. Its text has not been
            ///< refreshed yet, only cfunc and mba pointers are ready.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_refresh_pseudocode:
            ///< Existing pseudocode text has been refreshed.
            ///< vdui_t *vu
            ///< See also hxe_text_ready, which happens earlier
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_close_pseudocode:
            ///< Pseudocode view is being closed.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_keyboard:
            ///< Keyboard has been hit.
            ///< vdui_t *vu
            ///< int key_code (VK_...)
            ///< int shift_state
            ///< Should return: 1 if the event has been handled
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                int arg1 = va_argi(va, int);
                int arg2 = va_argi(va, int);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iOii)", event, arg0obj.o, arg1, arg2));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_right_click:
            ///< Mouse right click. We can add menu items now.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_double_click:
            ///< Mouse double click.
            ///< vdui_t *vu
            ///< int shift_state
            ///< Should return: 1 if the event has been handled
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                int arg1 = va_argi(va, int);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iOi)", event, arg0obj.o, arg1));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_curpos:
            ///< Current cursor position has been changed.
            ///< (for example, by left-clicking or using keyboard)
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_create_hint:
            ///< Create a hint for the current item.
            ///< vdui_t *vu
            ///< qstring *result_hint
            ///< int *implines
            ///< Possible return values:
            ///<  0: the event has not been handled
            ///<  1: hint has been created (should set *implines to nonzero as well)
            ///<  2: hint has been created but the standard hints must be
            ///<     appended by the decompiler
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        case hxe_text_ready:
            ///< Decompiled text is ready.
            ///< vdui_t *vu
            ///< This event can be used to modify the output text (sv).
            ///< The text uses regular color codes (see lines.hpp)
            ///< COLOR_ADDR is used to store pointers to ctree elements
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
                newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
                ret = hexrays_python_call(fct, args);
            }
            break;
        default:
            //~ msg("IDAPython: Unknown event `%u' occured\n", event);
            ret = 0;
            break;
    }

    return ret;
}

%}

%ignore init_hexrays_plugin;
%rename(init_hexrays_plugin) __init_hexrays_plugin;

%ignore add_custom_viewer_popup_item;
%rename(add_custom_viewer_popup_item) __add_custom_viewer_popup_item;

%ignore install_hexrays_callback;
%rename(install_hexrays_callback) __install_hexrays_callback;

%ignore remove_hexrays_callback;
%rename(remove_hexrays_callback) __remove_hexrays_callback;

%inline %{

//---------------------------------------------------------------------
extern hexdsp_t *hexdsp;
bool __init_hexrays_plugin(int flags=0)
{
  // Only initialize one time
  if (hexdsp == NULL)
    return init_hexrays_plugin(flags);
  else
    return true;
}

//---------------------------------------------------------------------
void __add_custom_viewer_popup_item(
        TCustomControl *custom_viewer,
        const char *title,
        const char *hotkey,
        PyObject *custom_viewer_popup_item_callback)
{
  PYW_GIL_GET;
  Py_INCREF(custom_viewer_popup_item_callback);
  add_custom_viewer_popup_item(custom_viewer, title, hotkey, __python_custom_viewer_popup_item_callback, custom_viewer_popup_item_callback);
};

//---------------------------------------------------------------------
bool __install_hexrays_callback(PyObject *hx_cblist_callback)
{
  PYW_GIL_GET;
  if (install_hexrays_callback(__hexrays_python_callback, hx_cblist_callback))
  {
    Py_INCREF(hx_cblist_callback);
    return true;
  }
  return false;
}

//---------------------------------------------------------------------
int __remove_hexrays_callback(PyObject *hx_cblist_callback)
{
  PYW_GIL_GET;
  int result, i;
  result = remove_hexrays_callback(__hexrays_python_callback, hx_cblist_callback);
  for (i=0;i<result;i++)
    Py_DECREF(hx_cblist_callback);

  return result;
}

%}


%{
//-------------------------------------------------------------------------
// A set of cfuncptr_t objects that were created from IDAPython.
// This is necessary in order to delete those objects before the hexrays
// plugin is unloaded. Otherwise, IDAPython will still delete them, but
// the plugin's 'hexdsp' dispatcher function will point to dlclose()'d
// code.
static qvector<cfuncptr_t*> python_cfuncptrs;
void hexrays_clear_python_cfuncptr_t_references(void)
{
  for ( size_t i = 0, n = python_cfuncptrs.size(); i < n; ++i )
    python_cfuncptrs[i]->reset();
  // NOTE: Don't clear() the array of pointers. All the python-exposed
  // cfuncptr_t instances will be deleted through the python
  // shutdown/ref-decrementing process anyway, and the entries will be
  // properly pulled out of the vector when that happens.
}

void hexrays_register_python_cfuncptr_t_instance(cfuncptr_t *fp)
{
  QASSERT(30457, !python_cfuncptrs.has(fp));
  python_cfuncptrs.push_back(fp);
}

void hexrays_deregister_python_cfuncptr_t_instance(cfuncptr_t *fp)
{
  qvector<cfuncptr_t*>::iterator found = python_cfuncptrs.find(fp);
  if ( found != python_cfuncptrs.end() )
  {
    fp->reset();
    python_cfuncptrs.erase(found);
  }
}

%}

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

%{
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
%}

cfuncptr_t _decompile(func_t *pfn, hexrays_failure_t *hf);
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
#pragma SWIG nowarn=503
%warnfilter(514) user_lvar_visitor_t; // Director base class 'x' has no virtual destructor.
%warnfilter(514) ctree_visitor_t;     // ditto
%warnfilter(514) ctree_parentee_t;    // ditto
%warnfilter(514) cfunc_parentee_t;    // ditto
%warnfilter(473) user_lvar_visitor_t::get_info_mapping_for_saving; // Returning a pointer or reference in a director method is not recommended.
%feature("director") ctree_visitor_t;
%feature("director") ctree_parentee_t;
%feature("director") cfunc_parentee_t;
%feature("director") user_lvar_visitor_t;
%include "hexrays.hpp"

%pythoncode %{

import idaapi

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
        func = idaapi.get_func(ea)
        if not func: return
    elif type(ea) == idaapi.func_t:
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
_listify_types(cinsnptrvec_t,
               ctree_items_t,
               qvector_lvar_t,
               qvector_carg_t,
               qvector_ccase_t,
               hexwarns_t,
               history_t)

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
for k in dir(_idaapi):
    if k.startswith('cit_'):
        cinsn_t.op_to_typename[getattr(_idaapi, k)] = k[4:]

""" array used for translating cexpr_t->op type to their names. """
cexpr_t.op_to_typename = {}
for k in dir(_idaapi):
    if k.startswith('cot_'):
        cexpr_t.op_to_typename[getattr(_idaapi, k)] = k[4:]

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
        iter.next()

    return
cblock_t.__iter__ = cblock_iter
cblock_t.__len__ = cblock_t.size

# cblock.find(cinsn_t) -> returns the iterator positioned at the given item
def cblock_find(self, item):

    iter = self.begin()
    for i in range(self.size()):
        if iter.cur == item:
            return iter
        iter.next()

    return
cblock_t.find = cblock_find

# cblock.index(cinsn_t) -> returns the index of the given item
def cblock_index(self, item):

    iter = self.begin()
    for i in range(self.size()):
        if iter.cur == item:
            return i
        iter.next()

    return
cblock_t.index = cblock_index

# cblock.at(int) -> returns the item at the given index index
def cblock_at(self, index):

    iter = self.begin()
    for i in range(self.size()):
        if i == index:
            return iter.cur
        iter.next()

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

def cfunc_type(self):
    """ Get the function's return type tinfo_t object. """
    tif = tinfo_t()
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

def _map___getitem__(self, key):
    """ Returns the value associated with the provided key. """
    if not isinstance(key, self.keytype):
        raise KeyError('type of key should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if key not in self:
        raise KeyError('key not found')
    return self.second(self.find(key))

def _map___setitem__(self, key, value):
    """ Returns the value associated with the provided key. """
    if not isinstance(key, self.keytype):
        raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if not isinstance(value, self.valuetype):
        raise KeyError('type of `value` should be ' + repr(self.valuetype) + ' but got ' + type(value))
    self.insert(key, value)
    return

def _map___delitem__(self, key):
    """ Removes the value associated with the provided key. """
    if not isinstance(key, self.keytype):
        raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if key not in self:
        raise KeyError('key not found')
    self.erase(self.find(key))
    return

def _map___contains__(self, key):
    """ Returns true if the specified key exists in the . """
    if not isinstance(key, self.keytype):
        raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if self.find(key) != self.end():
        return True
    return False

def _map_clear(self):
    self.clear()
    return

def _map_copy(self):
    ret = {}
    for k in self.iterkeys():
        ret[k] = self[k]
    return ret

def _map_get(self, key, default=None):
    if key in self:
        return self[key]
    return default

def _map_iterkeys(self):
    iter = self.begin()
    while iter != self.end():
        yield self.first(iter)
        iter = self.next(iter)
    return

def _map_itervalues(self):
    iter = self.begin()
    while iter != self.end():
        yield self.second(iter)
        iter = self.next(iter)
    return

def _map_iteritems(self):
    iter = self.begin()
    while iter != self.end():
        yield (self.first(iter), self.second(iter))
        iter = self.next(iter)
    return

def _map_keys(self):
    return list(self.iterkeys())

def _map_values(self):
    return list(self.itervalues())

def _map_items(self):
    return list(self.iteritems())

def _map_has_key(self, key):
    return key in self

def _map_pop(self, key):
    """ Sets the value associated with the provided key. """
    if not isinstance(key, self.keytype):
        raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if key not in self:
        raise KeyError('key not found')
    ret = self[key]
    del self[key]
    return ret

def _map_popitem(self):
    """ Sets the value associated with the provided key. """
    if len(self) == 0:
        raise KeyError('key not found')
    key = self.keys()[0]
    return (key, self.pop(key))

def _map_setdefault(self, key, default=None):
    """ Sets the value associated with the provided key. """
    if not isinstance(key, self.keytype):
        raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if key in self:
        return self[key]
    self[key] = default
    return default

def _map_as_dict(maptype, name, keytype, valuetype):

    maptype.keytype = keytype
    maptype.valuetype = valuetype

    for fctname in ['begin', 'end', 'first', 'second', 'next', \
                        'find', 'insert', 'erase', 'clear', 'size']:
        fct = getattr(_idaapi, name + '_' + fctname)
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
    maptype.__getitem__ = _map___getitem__
    maptype.__setitem__ = _map___setitem__
    maptype.__delitem__ = _map___delitem__
    maptype.__contains__ = _map___contains__
    maptype.clear = _map_clear
    maptype.copy = _map_copy
    maptype.get = _map_get
    maptype.iterkeys = _map_iterkeys
    maptype.itervalues = _map_itervalues
    maptype.iteritems = _map_iteritems
    maptype.keys = _map_keys
    maptype.values = _map_values
    maptype.items = _map_items
    maptype.has_key = _map_has_key
    maptype.pop = _map_pop
    maptype.popitem = _map_popitem
    maptype.setdefault = _map_setdefault

#_map_as_dict(user_labels_t, 'user_labels', (int, long), qstring)
_map_as_dict(user_cmts_t, 'user_cmts', treeloc_t, citem_cmt_t)
_map_as_dict(user_numforms_t, 'user_numforms', operand_locator_t, number_format_t)
_map_as_dict(user_iflags_t, 'user_iflags', citem_locator_t, (int, long))
_map_as_dict(user_unions_t, 'user_unions', (int, long), intvec_t)
_map_as_dict(eamap_t, 'eamap', int, cinsnptrvec_t)
#_map_as_dict(boundaries_t, 'boundaries', cinsn_t, areaset_t)

%}
