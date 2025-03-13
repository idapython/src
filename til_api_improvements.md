
# Additions

## udm_t(name: str, type, offset: int = -1) : udm_t

    # Create a structure/union member, with the specified name
    # and type.
    #
    # The size will be computed automatically.
    #
    # @param name a valid member name. Must not be empty.
    # @param type the member type. the type can be specified one of the following ways:
    #              - type_t if the type is simple (integral/floating/bool);
    #              - tinfo_t a more complex type, like a pointer, array, etc;
    #              - string as a C type declaration.
    # @param offset the member offset in bits. It is the caller's responsibility
    #              to specify correct offsets.
    # if an input argument is incorrect, the constructor may raise an exception

## tinfo_t.get_udm_by_name(name: str) : (idx, udm_t) | (-1, None)

    # Retrieve a structure/union member (and its index) with the
    # specified name in the specified tinfo_t object.
    #
    # @param name Member name. Must not be empty.
    # @returns a tuple (int, udm_t), or (-1, None) if member not found.

* CL#156578 - first attempt, w/o the index

## tinfo_t.get_udm_by_offset(offset: int) : (idx, udm_t) | (-1, None)

    # Retrieve a structure/union member with the specified offset
    # in the specified tinfo_t object.
    #
    # @param offset Member bit offset
    # @returns a tuple (int, udm_t), or (-1, None) if member not found.

## tinfo_t.add_udm(name: str, type: tinfo_t | type_t | str, offset: int = -1)

    # Add a new member to a structure/union type, with the specified name and type.
    #
    # The size will be computed automatically.
    # The new member must not overlap with the existing members.
    # if an input argument is incorrect, the constructor may raise an exception
    #
    # @param name Member name. Must not be empty.
    # @param type Member type. Can be specified one of the following ways:
    #              - type_t if the type is simple (integral/floating/bool);
    #              - tinfo_t a more complex type, like a pointer, array, etc;
    #              - string as a C type declaration.
    # @param offset  Member offset in bits. If specified as -1, the new member
    #                is added at the end of the structure/union.
    # @returns member object

* CL#156615

## tinfo_t.insert_udm(self, udm: udm_t, idx: int, times: int = 1, etf_flags: int = 0):

    # Insert a member in the current structure/union, at the specified index.
    #
    # The member's size will be computed automatically.
    #
    # @param udm       The member, fully initialized (but whose offset is not set)
    # @param idx       the index in the udm array where the new udm should be placed.
    # @param times     how many times to insert the new member
    # @param etf_flags an OR'ed combination of ETF_ flags

## funcarg_t(name: str, type: tinfo_t | type_t | str, argloc: argloc_t = argloc_t())

    # Create a function argument, with the specified name and type.
    #
    # The 'type' descriptor, can be one of:
    #
    # * type_t: if the type is simple (integral/floating/bool). E.g., `BTF_INT`
    # * tinfo_t: can handle more complex types (structures, pointers, arrays, ...)
    # * str: a C type declaration
    #
    # If an input argument is incorrect, the constructor may raise an exception
    #
    # @param name a valid argument name. May not be empty.
    # @param type the member type
    # @param argloc the argument location. Can be empty.

* CL#156993

## til_t.numbered_types() : generator of tinfo_t

    # Returns a generator over the numbered types contained in this
    # type library.
    #
    # Every iteration returns a fresh new tinfo_t object
    #
    # @return a tinfo_t-producing generator

* CL#156968

## til_t.named_types() : generator of tinfo_t

    # Returns a generator over the named types contained in this
    # type library.
    #
    # Every iteration returns a fresh new tinfo_t object
    #
    # @return a tinfo_t-producing generator

* CL#156968

## til_t.get_named_type(name: str) : tinfo_t | None

    # Retrieves a tinfo_t representing the named type in this type library.
    #
    # @param name a type name
    # @return a new tinfo_t object, or None if not found

* CL#156969

## til_t.get_numbered_type(ordinal: int): tinfo_t | None

    # Retrieves a tinfo_t representing the numbered type in this type library.
    #
    # @param ordinal a type ordinal
    # @return a new tinfo_t object, or None if not found

* CL#156969

## qvector.append(thing: any) : None

    # Alias of push_back()

* CL#156975

## qvector.extend(thing: qvector) : None

    # Alias of insert(end(), thing.begin(), thing.end())

* CL#156975

## func_type_data_t() should default to `CM_CC_UNKNOWN`

Otherwise, the following is not working:

    ftd = func_type_data_t()
    ftd.append(funcarg_t("myarg", BT_INT32))
    ftd.rettype = tinfo_t(BT_INT64)
    tif = tinfo_t()
    tif.create_func(ftd)
    tif._print() => features a `__bad_cc` calling convention

* CL#157005

## tinfo_t.add_edm(name: str, value: int)

    # Add an enumerator to the current enumeration.
    #
    # When creating a new enumeration from scratch, you might
    # want to first call `create_enum()`
    #
    # This method has the following signatures:
    #
    # * add_edm(edm: edm_t, bmask: int = -1, etf_flags: int = 0, idx: int = -1)
    # * add_edm(name: str, value: int, bmask: int = -1, etf_flags: int = 0, idx: int = -1)
    #
    # If an input argument is incorrect, the constructor may raise an exception
    #
    # @param edm       The member, fully initialized (first form)
    # @param name      Enumerator name - must not be empty
    # @param value     Enumerator value
    # @param bmask     A bitmask to which the enumerator belongs
    # @param etf_flags an OR'ed combination of ETF_ flags
    # @param idx       the index in the edm array where the new udm should be placed.
    #                  If the specified index cannot be honored because it would spoil

* CL#1570??

## edm_t(name: str, value: int, cmt: str = None) : edm_t

    # Create a structure/union member, with the specified name and value
    #
    # @param name  Enumerator name. Must not be empty.
    # @param value Enumerator value
    # @param cmt   Enumerator repeatable comment. May be empty.

* CL#1570??

## tinfo_t(type: type_t) : tinfo_t
## tinfo_t(decl: str, til: til_t = None, pt_flags: int = 0) : tinfo_t
## tinfo_t(**kwargs) : tinfo_t

    # Create a type object with the provided argumens.
    #
    # This constructor has the following signatures:
    #
    # * tinfo_t(decl_type: type_t)
    # * tinfo_t(decl: str, til: til_t = None, pt_flags: int = 0)
    #
    # The latter form will create the type object by parsing the type declaration
    #
    # Alternatively, you can use a form accepting the following keyword arguments:
    #
    # * ordinal: int
    # * name: str
    # * til: til_t=None # `None` means `get_idati()`
    #
    # E.g.,
    #
    # * tinfo_t(ordinal=3)
    # * tinfo_t(ordinal=10, til=get_idati())
    # * tinfo_t(name="mytype_t")
    # * tinfo_t(name="thattype_t", til=my_other_til)
    #
    # The constructor may raise an exception if data was invalid/parsing failed.
    #
    # @param decl_type A simple type
    # @param decl A valid C declaration
    # @param til A type library, or `None` to use the (`get_idati()`) default
    # @param ordinal An ordinal in the type library
    # @param name A valid type name
    # @param pt_flags Parsing flags

## tinfo_t.iter_struct() : generator of udm_t

    # Iterate on the members composing this structure.
    #
    # Example:
    #     til = ida_typeinf.get_idati()
    #     tif = til.get_named_type("my_struc")
    #     for udm in tif.iter_struct():
    #         print(f"{udm.name} at bit offset {udm.offset}")
    #
    # Will raise an exception if this type is not a structure.
    #
    # @return a udm_t-producing generator

## tinfo_t.iter_union() : generator of udm_t

    # Iterate on the members composing this union.
    #
    # Example:
    #     til = ida_typeinf.get_idati()
    #     tif = til.get_named_type("my_union")
    #     for udm in tif.iter_union():
    #         print(f"{udm.name} with type {udm.type}")
    #
    # Will raise an exception if this type is not a union.
    #
    # @return a udm_t-producing generator

## tinfo_t.iter_udt() : generator of udm_t

    # Iterate on the members composing this structure, or union.
    #
    # Example:
    #     til = ida_typeinf.get_idati()
    #     tif = til.get_named_type("my_type")
    #     for udm in tif.iter_udt():
    #         print(f"{udm.name} at bit offset {udm.offset} with type {udm.type}")
    #
    # Will raise an exception if this type is not a structure, or union
    #
    # @return a udm_t-producing generator

## tinfo_t.iter_enum() : generator of edm_t

    # Iterate on the members composing this enumeration
    #
    # Example:
    #     til = ida_typeinf.get_idati()
    #     tif = til.get_named_type("my_enum")
    #     for edm in tif.iter_enum():
    #         print(f"{edm.name} = {edm.value}")
    #
    # Will raise an exception if this type is not an enumeration
    #
    # @return a edm_t-producing generator


# Proposals


## tinfo_t repr
```
Python>idati.get_named_type("Elf32_Vernaux")
<ida_typeinf.tinfo_t object "Elf32_Vernaux">
```
Or any alternatives that show module and class names instead of
```
Python>idati.get_named_type("Elf32_Vernaux")  # it's tinfo_t object, not a string
Elf32_Vernaux
````

## All idapython default representation as `__repr__`

On typing objects Python interpreters show `__repr__`, but IDAPython shows `__str__`
Suggestion is to be synced with the interpreters and show `__repr__`

# Effectively test

    [v] pc_api_add_frame_member.elf
    [?] pc_api_apply_callee_tinfo.elf
    [ ] pc_api_change_stkvar_type.elf
    [v] pc_api_create_array.elf
    [v] pc_api_create_bfstruct.elf
    [v] pc_api_create_bmenum.elf
    [v] pc_api_create_libssh2_til.elf
    [v] pc_api_create_struct_by_parsing.elf
    [v] pc_api_create_user_shared_data.elf
    [v] pc_api_del_struct_members.elf
    [v] pc_api_func_ti_changed_listener.elf
    [v] pc_api_gap_size_align_snippet.elf
    [v] pc_api_get_best_fit_member.elf
    [v] pc_api_get_innermost_member.elf
    [v] pc_api_import_type_from_til.elf -> idapython-examples__import_type_from_til (requires UI)
    [v] pc_api_insert_gap.elf
    [v] pc_api_list_enum_member.elf
    [v] pc_api_list_frame_info.elf
    [v] pc_api_list_func_details.elf
    [v] pc_api_list_struct_accesses.elf
    [ ] pc_api_list_struct_member.elf
    [ ] pc_api_list_struct_xrefs.elf
    [ ] pc_api_list_union_member.elf
    [ ] pc_api_mark_func_spoiled.elf
    [ ] pc_api_operand_to_struct_member.elf
    [ ] pc_api_setpehdr.elf
    [ ] pc_api_visit_tinfo.elf
