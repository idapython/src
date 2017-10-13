
#<pycode_BC695(py_segregs)>
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

#</pycode_BC695(py_segregs)>
