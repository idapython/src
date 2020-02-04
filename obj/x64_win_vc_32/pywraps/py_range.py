
#<pycode_BC695(py_range)>
import sys
sys.modules["ida_area"] = sys.modules["ida_range"]
area_t = range_t
areaset_t = rangeset_t
def __set_startEA(inst, v):
    inst.start_ea = v
range_t.startEA = property(lambda self: self.start_ea, __set_startEA)
def __set_endEA(inst, v):
    inst.end_ea = v
range_t.endEA = property(lambda self: self.end_ea, __set_endEA)
#</pycode_BC695(py_range)>
