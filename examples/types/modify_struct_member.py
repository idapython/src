"""
summary: modify structure members attributes programmatically

description:
    This example shows how to access & modify certain less-obvious
    attributes of structure members (pointer size, representation, ...)

    We will first create the structure without those, and then
    show how to programmatically modify them.

level: intermediate
"""

import ida_typeinf
import ida_nalt

# For the sake of the example, we will start with an "approximation"
# of the structure we eventually want to end up with:

struct_def = """
struct RTTICompleteObjectLocator
{
  int signature;
  int offset;
  int cdOffset;
  int pTypeDescriptor;   // we will eventually want: int *__ptr32 pTypeDescriptor __offset(OFF64|RVAOFF);
  int pClassDescriptor;  // we will eventually want: int *__ptr32 pClassDescriptor __offset(OFF64|RVAOFF);
  int pSelf;             // we will eventually want: int *__ptr32 pSelf __offset(OFF64|RVAOFF);
};
"""

tif = ida_typeinf.tinfo_t(struct_def)

#
# We will want to
#  - change the _type_, from `int`, to `int *__ptr32`
#  - change the _representation_, to an RVA offset
#

new_type = ida_typeinf.tinfo_t("int *__ptr32")

new_repr = ida_typeinf.value_repr_t()
new_repr.set_vtype(ida_typeinf.FRB_OFFSET)
new_repr.ri.init(ida_nalt.REF_OFF64 | ida_nalt.REFINFO_RVAOFF)

for i in range(3, 6):
    tif.set_udm_type(i, new_type, 0, new_repr)
