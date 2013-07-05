//---------------------------------------------------------------------
// SWIG bindings for Hexray Decompiler's hexrays.hpp
//
// Author: EiNSTeiN_ <einstein@g3nius.org>
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
#define typename 

%{
#include "hexrays.hpp"
%}

//---------------------------------------------------------------------
// some defines to calm SWIG down.
#define DEFINE_MEMORY_ALLOCATION_FUNCS()
//#define DECLARE_UNCOPYABLE(f)
#define AS_PRINTF(format_idx, varg_idx)
#define idaapi
#define __fastcall

%ignore vd_printer_t::vprint;
%ignore string_printer_t::vprint;
%ignore typestring::dstr;
%ignore typestring::multiprint;
%ignore vdui_t::vdui_t;
%ignore cblock_t::find;
%ignore cfunc_t::cfunc_t;
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
%ignore typestring::resolve_func_type;
%ignore typestring::common_type;
%ignore typestring::noarray_size;
%ignore file_printer_t::_print;
%ignore file_printer_t;

%extend cfunc_t {
    %immutable rgas;
    %immutable stas;
};

%rename(dereference_uint16) operator uint16*;
%rename(dereference_const_uint16) operator const uint16*;

// this is a dummy class template to allow swig to do its thing.
template<class key_type, class mapped_type> class std::map {
public:
    mapped_type& at(const key_type& _Keyval);
    size_t size() const;
};

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

void qswap(cinsn_t &a, cinsn_t &b);
%include "typemaps.i"

%typemap(out) void
{
  Py_INCREF(Py_None);
  $1obj = Py_None;
}

%{

//---------------------------------------------------------------------
static int hexrays_cblist_py_call(PyObject *fct, PyObject *args)
{
    PyObject *resultobj;
    int result;
    int ecode1 = 0 ;

    resultobj =  PyEval_CallObject(fct, args);
    
    if (resultobj == NULL) 
    {
        msg("IDAPython: Hex-rays python callback raised an exception.\n");
        
        // we can't do much else than clear the exception since this was not called from Python.
        // XXX: print stack trace?
        PyErr_Clear();
        return 0;
    }

    ecode1 = SWIG_AsVal_int(resultobj, &result);
    Py_DECREF(resultobj);

    if (SWIG_IsOK(ecode1))
        return result;

    msg("IDAPython: Hex-rays python callback returned non-integer, value ignored.\n");
    return 0;
}

//---------------------------------------------------------------------
static bool idaapi __python_custom_viewer_popup_item_callback(void *ud)
{
    int ret;
    PyObject *fct = (PyObject *)ud;
    
    ret = hexrays_cblist_py_call(fct, NULL);
    
    return ret ? true : false;
}

//---------------------------------------------------------------------
static int idaapi __hexrays_python_callback(void *ud, hexrays_event_t event, va_list va)
{
    int ret;
    PyObject *fct = (PyObject *)ud;
    void *argp = NULL;
    PyObject *args = NULL;
    
    switch(event)
    {
        case hxe_maturity:
            ///< Ctree maturity level is being changed.
            ///< cfunc_t *cfunc
            ///< ctree_maturity_t new_maturity
            {
                cfunc_t *arg0 = va_arg(va, cfunc_t *);
                ctree_maturity_t arg1 = va_argi(va, ctree_maturity_t);
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_cfunc_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iOi)", event, arg0obj, arg1);
                ret = hexrays_cblist_py_call(fct, args);
            
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_cfunc_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 cfunc_t");
                    //PyErr_Clear();
                }
            }
            break;
        case hxe_interr:
            ///< Internal error has occurred.
            ///< int errcode
            {
                int arg0 = va_argi(va, int);
                
                args = Py_BuildValue("(ii)", event, arg0);
                ret = hexrays_cblist_py_call(fct, args);
            
                Py_DECREF(args);
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
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_cfunc_t, SWIG_POINTER_OWN |  0 );
                PyObject *arg1obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg1), SWIGTYPE_p_vc_printer_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iOO)", event, arg0obj, arg1obj);
                ret = hexrays_cblist_py_call(fct, args);
            
                //Py_XDECREF(arg0obj);
                //Py_XDECREF(arg1obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_cfunc_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 cfunc_t");
                    PyErr_Clear();
                }
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg1obj, &argp,SWIGTYPE_p_vc_printer_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #1 vc_printer_t");
                    //PyErr_Clear();
                }
            }
            break;

        // User interface related events:
        case hxe_open_pseudocode:
            ///< New pseudocode view has been opened.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
            }
            break;
        case hxe_switch_pseudocode:
            ///< Existing pseudocode view has been reloaded
            ///< with a new function. Its text has not been
            ///< refreshed yet, only cfunc and mba pointers are ready.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
            }
            break;
        case hxe_refresh_pseudocode:
            ///< Existing pseudocode text has been refreshed.
            ///< vdui_t *vu                                       
            ///< See also hxe_text_ready, which happens earlier
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
            }
            break;
        case hxe_close_pseudocode:
            ///< Pseudocode view is being closed.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
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
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iOii)", event, arg0obj, arg1, arg2);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
            }
            break;
        case hxe_right_click:
            ///< Mouse right click. We can add menu items now.
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
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
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iOi)", event, arg0obj, arg1);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
            }
            break;
        case hxe_curpos:
            ///< Current cursor position has been changed.
            ///< (for example, by left-clicking or using keyboard)
            ///< vdui_t *vu
            {
                vdui_t *arg0 = va_arg(va, vdui_t *);
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
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
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
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
                PyObject *arg0obj = SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, SWIG_POINTER_OWN |  0 );
                
                args = Py_BuildValue("(iO)", event, arg0obj);
                ret = hexrays_cblist_py_call(fct, args);
                
                //Py_XDECREF(arg0obj);
                Py_DECREF(args);
                
                if (!SWIG_IsOK(SWIG_ConvertPtr(arg0obj, &argp,SWIGTYPE_p_vdui_t, SWIG_POINTER_DISOWN |  0 ))) {
                    msg("error deleting callback argument #0 vdui_t");
                    //PyErr_Clear();
                }
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

%rename(add_custom_viewer_popup_item) __add_custom_viewer_popup_item;

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
    Py_INCREF(custom_viewer_popup_item_callback);
    add_custom_viewer_popup_item(custom_viewer, title, hotkey, __python_custom_viewer_popup_item_callback, custom_viewer_popup_item_callback);
};

//---------------------------------------------------------------------
bool __install_hexrays_callback(PyObject *hx_cblist_callback)
{
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
    int result, i;
    result = remove_hexrays_callback(__hexrays_python_callback, hx_cblist_callback);
    for (i=0;i<result;i++)
        Py_DECREF(hx_cblist_callback);

    return result;
}
%}

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
    if type(ea) == int:
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
qtype.__str__ = qtype.c_str
typestring.__str__ = typestring._print
qstring.__str__ = qstring.c_str
citem_cmt_t.__str__ = citem_cmt_t.c_str

typestring.size = property(typestring.size)
typestring.is_user_cc = property(typestring.is_user_cc)
typestring.is_vararg = property(typestring.is_vararg)
typestring.is_ptr_or_array = property(typestring.is_ptr_or_array)
typestring.is_paf = property(typestring.is_paf)
typestring.is_funcptr = property(typestring.is_funcptr)
typestring.is_ptr = property(typestring.is_ptr)
typestring.is_enum = property(typestring.is_enum)
typestring.is_func = property(typestring.is_func)
typestring.is_void = property(typestring.is_void)
typestring.is_array = property(typestring.is_array)
typestring.is_float = property(typestring.is_float)
typestring.is_union = property(typestring.is_union)
typestring.is_struct = property(typestring.is_struct)
typestring.is_struni = property(typestring.is_struni)
typestring.is_double = property(typestring.is_double)
typestring.is_ldouble = property(typestring.is_ldouble)
typestring.is_floating = property(typestring.is_floating)
typestring.is_const = property(typestring.is_const)
typestring.is_correct = property(typestring.is_correct)
typestring.is_scalar = property(typestring.is_scalar)
typestring.is_small_struni = property(typestring.is_small_struni)
typestring.is_like_scalar = property(typestring.is_like_scalar)
typestring.is_pvoid = property(typestring.is_pvoid)
typestring.is_partial_ptr = property(typestring.is_partial_ptr)
typestring.is_well_defined = property(typestring.is_well_defined)
typestring.requires_cot_ref = property(typestring.requires_cot_ref)
typestring.partial_type_num = property(typestring.partial_type_num)

# ---------------------------------------------------------------------
# listify all list types
def _vectors_iterator(self):
    for i in range(len(self)):
        yield self[i]
for cls in [cinsnptrvec_t, ctree_items_t, uvalvec_t, \
            intvec_t, boolvec_t, hexwarns_t, \
            history_t, strvec_t, qvector_lvar_t, 
            qvector_carg_t, qvector_ccase_t
        ]:
    cls.__getitem__ = cls.at
    cls.__len__ = cls.size
    cls.__iter__ = _vectors_iterator

def citem_to_specific_type(self):
    """ cast the citem_t object to its more specific type, either cexpr_t or cinsn_t. """
    
    if self.op >= cot_empty and self.op <= cot_last:
        return self.cexpr
    elif self.op >= cit_empty and self.op < cit_end:
        return self.cinsn
    
    raise RuntimeError('unknown op type')
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

def cfunc___str__(self):
    qs = qstring()
    p = qstring_printer_t(self, qs, 0)
    self.print_func(p)
    return qs.c_str()
cfunc_t.__str__ = cfunc___str__
cfuncptr_t.__str__ = lambda self: str(self.__deref__())

def cfunc_typestring(self):
    """ Get the function's return type typestring object. The full prototype \
        can be obtained via typestring._print() method. """
    
    ts = typestring()
    qt = qtype()
    
    result = self.get_func_type(ts, qt)
    if not result: return
    
    return ts
cfunc_t.typestring = property(cfunc_typestring)
cfuncptr_t.typestring = property(lambda self: self.__deref__().typestring)

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
    if type(key) != self.keytype:
        raise KeyError('type of key should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if key not in self:
        raise KeyError('key not found')
    return self.second(self.find(key))

def _map___setitem__(self, key, value):
    """ Returns the value associated with the provided key. """
    if type(key) != self.keytype:
        raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if type(value) != self.valuetype:
        raise KeyError('type of `value` should be ' + repr(self.valuetype) + ' but got ' + type(value))
    self.insert(key, value)
    return

def _map___delitem__(self, key):
    """ Removes the value associated with the provided key. """
    if type(key) != self.keytype:
        raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
    if key not in self:
        raise KeyError('key not found')
    self.erase(self.find(key))
    return

def _map___contains__(self, key):
    """ Returns true if the specified key exists in the . """
    if type(key) != self.keytype:
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
    if type(key) != self.keytype:
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
    if type(key) != self.keytype:
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

_map_as_dict(user_labels_t, 'user_labels', int, qstring)
_map_as_dict(user_cmts_t, 'user_cmts', treeloc_t, citem_cmt_t)
_map_as_dict(user_numforms_t, 'user_numforms', operand_locator_t, number_format_t)
_map_as_dict(user_iflags_t, 'user_iflags', citem_locator_t, int)
_map_as_dict(user_unions_t, 'user_unions', int, intvec_t)
_map_as_dict(eamap_t, 'eamap', int, cinsnptrvec_t)
#_map_as_dict(boundaries_t, 'boundaries', cinsn_t, areaset_t)

%}
