"""
summary: create an array type

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we create an array using both versions of
    create_array tinfo_t method.

level: intermediate
"""

import ida_typeinf

"""
First method:
* Create the type info object of the array element.
* Create an array of 5 integers (base index set to zero)
"""
tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)
if tif.create_array(tif, 5, 0):
    print(f"{tif._print()}")

"""
Second method:
* Create an array type data object representing an array
  of 5 integers with base index 10.
* Create the array using the just constructed object.
"""
atd = ida_typeinf.array_type_data_t()
atd.base = 10
atd.nelems = 5
atd.elem_type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)
tif = ida_typeinf.tinfo_t()
if tif.create_array(atd):
    print(f"{tif._print()}")
