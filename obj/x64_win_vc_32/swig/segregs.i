%module(docstring="IDA Plugin SDK API wrapper: segregs",directors="1",threads="1") ida_segregs
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_SEGREGS
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_SEGREGS
  #define HAS_DEP_ON_INTERFACE_SEGREGS
#endif
#ifndef HAS_DEP_ON_INTERFACE_RANGE
  #define HAS_DEP_ON_INTERFACE_RANGE
#endif
%include "header.i"
%{
#include <segregs.hpp>
%}

%import "range.i"

// Ignore kernel-only symbols
%ignore delete_v660_segreg_t;
%ignore v660_segreg_t;

#define R_es 29
#define R_cs 30
#define R_ss 31
#define R_ds 32
#define R_fs 33
#define R_gs 34

%include "segregs.hpp"
%pythoncode %{
if _BC695:
    import sys
    sys.modules["ida_srarea"] = sys.modules["ida_segregs"]
    SetDefaultRegisterValue=set_default_sreg_value
    copy_srareas=copy_sreg_ranges
    def ___looks_like_ea_not_segreg(thing):
        # yay heuristics. Not sure how best to do this...
        return (type(thing) == long) or (thing > 0x200)
    def del_sreg_range(*args):
        if ___looks_like_ea_not_segreg(args[1]): # 6.95: rg, ea
            ea, rg = args[1], args[0]
        else:                                    # 7.00: ea, rg
            ea, rg = args
        return _ida_segregs.del_sreg_range(ea, rg)
    del_srarea=del_sreg_range
    getSR=get_sreg
    get_prev_srarea=get_prev_sreg_range
    get_srarea2=get_sreg_range
    def get_sreg_range_num(*args):
        if ___looks_like_ea_not_segreg(args[1]): # 6.95: rg, ea
            ea, rg = args[1], args[0]
        else:                                    # 7.00: ea, rg
            ea, rg = args
        return _ida_segregs.get_sreg_range_num(ea, rg)
    get_srarea_num=get_sreg_range_num
    get_srareas_qty2=get_sreg_ranges_qty
    getn_srarea2=getn_sreg_range
    import ida_idaapi
    is_segreg_locked=ida_idaapi._BC695.false_p
    class lock_segreg:
        def __init__():
            pass
    segreg_area_t=sreg_range_t
    splitSRarea1=split_sreg_range
    split_srarea=split_sreg_range
    get_segreg=get_sreg
    set_default_segreg_value=set_default_sreg_value

%}