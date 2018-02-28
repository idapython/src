
#<pycode(py_bytes)>
#</pycode(py_bytes)>


#<pycode_BC695(py_bytes)>
ACFOPT_ASCII=0
ACFOPT_CONVMASK=0
ACFOPT_ESCAPE=STRCONV_ESCAPE
ACFOPT_UTF16=0
ACFOPT_UTF8=0
DOUNK_DELNAMES=DELIT_DELNAMES
DOUNK_EXPAND=DELIT_EXPAND
DOUNK_NOTRUNC=DELIT_NOTRUNC
DOUNK_SIMPLE=DELIT_SIMPLE
FF_ASCI=FF_STRLIT
FF_DWRD=FF_DWORD
FF_OWRD=FF_OWORD
FF_QWRD=FF_QWORD
FF_STRU=FF_STRUCT
FF_TBYT=FF_TBYTE
FF_VAR=0
FF_YWRD=FF_YWORD
FF_ZWRD=FF_ZWORD
GFE_NOVALUE=0
add_hidden_area=add_hidden_range
asciflag=strlit_flag
delValue=del_value
del_hidden_area=del_hidden_range
do16bit=create_16bit_data
do32bit=create_32bit_data
doAlign=create_align
doByte=create_byte
doCustomData=create_custdata
doDouble=create_double
doDwrd=create_dword
doExtra=ida_idaapi._BC695.false_p
doFloat=create_float
doImmd=set_immd
doOwrd=create_oword
doPackReal=create_packed_real
doQwrd=create_qword
doStruct=create_struct
doTbyt=create_tbyte
doWord=create_word
doYwrd=create_yword
doZwrd=create_zword
do_data_ex=create_data
do_unknown=del_items
@bc695redef
def do_unknown_range(ea, size, flags):
    return del_items(ea, flags, size) # swap 2 last args
dwrdflag=dword_flag
f_hasRef=f_has_xref
f_isASCII=f_is_strlit
f_isAlign=f_is_align
f_isByte=f_is_byte
f_isCode=f_is_code
f_isCustom=f_is_custom
f_isData=f_is_data
f_isDouble=f_is_double
f_isDwrd=f_is_dword
f_isFloat=f_is_float
f_isHead=f_is_head
f_isNotTail=f_is_not_tail
f_isOwrd=f_is_oword
f_isPackReal=f_is_pack_real
f_isQwrd=f_is_qword
f_isStruct=f_is_struct
f_isTail=f_is_tail
f_isTbyt=f_is_tbyte
f_isWord=f_is_word
f_isYwrd=f_is_yword
getDefaultRadix=get_default_radix
getFlags=get_full_flags
get_long=get_dword
get_full_byte=get_wide_byte
get_full_word=get_wide_word
get_full_long=get_wide_dword
get_original_long=get_original_dword
put_long=put_dword
patch_long=patch_dword
add_long=add_dword
getRadix=get_radix
get_ascii_contents=get_strlit_contents
get_ascii_contents2=get_strlit_contents
get_flags_novalue=get_flags
get_hidden_area=get_hidden_range
get_hidden_area_num=get_hidden_range_num
get_hidden_area_qty=get_hidden_range_qty
@bc695redef
def get_many_bytes(ea, size):
    return get_bytes(ea, size)
@bc695redef
def get_many_bytes_ex(ea, size):
    return get_bytes_and_mask(ea, size)
get_max_ascii_length=get_max_strlit_length
get_next_hidden_area=get_next_hidden_range
get_prev_hidden_area=get_prev_hidden_range
get_zero_areas=get_zero_ranges
getn_hidden_area=getn_hidden_range
hasExtra=has_extra_cmts
hasRef=has_xref
hasValue=has_value
hidden_area_t=hidden_range_t
isASCII=is_strlit
isAlign=is_align
isByte=is_byte
isChar=is_char
isChar0=is_char0
isChar1=is_char1
isCode=is_code
isCustFmt=is_custfmt
isCustFmt0=is_custfmt0
isCustFmt1=is_custfmt1
isCustom=is_custom
isData=is_data
isDefArg=is_defarg
isDefArg0=is_defarg0
isDefArg1=is_defarg1
isDouble=is_double
isDwrd=is_dword
isEnabled=is_mapped
isEnum=is_enum
isEnum0=is_enum0
isEnum1=is_enum1
isFloat=is_float
isFloat0=is_float0
isFloat1=is_float1
isFlow=is_flow
isFltnum=is_fltnum
isFop=is_forced_operand
isFunc=is_func
isHead=is_head
isImmd=has_immd
isLoaded=is_loaded
isNotTail=is_not_tail
isNum=is_numop
isNum0=is_numop0
isNum1=is_numop1
isOff=is_off
isOff0=is_off0
isOff1=is_off1
isOwrd=is_oword
isPackReal=is_pack_real
isQwrd=is_qword
isSeg=is_seg
isSeg0=is_seg0
isSeg1=is_seg1
isStkvar=is_stkvar
isStkvar0=is_stkvar0
isStkvar1=is_stkvar1
isStroff=is_stroff
isStroff0=is_stroff0
isStroff1=is_stroff1
isStruct=is_struct
isTail=is_tail
isTbyt=is_tbyte
isUnknown=is_unknown
isVoid=is_suspop
isWord=is_word
isYwrd=is_yword
isZwrd=is_zword
make_ascii_string=create_strlit
noExtra=ida_idaapi._BC695.false_p
noType=clr_op_type
owrdflag=oword_flag
patch_many_bytes=patch_bytes
print_ascii_string_type=print_strlit_type
put_many_bytes=put_bytes
qwrdflag=qword_flag
tbytflag=tbyte_flag
update_hidden_area=update_hidden_range
ywrdflag=yword_flag
zwrdflag=zword_flag
def get_opinfo(*args):
    import ida_nalt
    if isinstance(args[3], ida_nalt.opinfo_t): # 6.95: ea, n, flags, buf
        ea, n, flags, buf = args
    else:                                      # 7.00: buf, ea, n, flags
        buf, ea, n, flags = args
    return _ida_bytes.get_opinfo(buf, ea, n, flags)
@bc695redef
def doASCI(ea, length):
    import ida_netnode
    return create_data(ea, FF_STRLIT, length, ida_netnode.BADNODE)
FF_3BYTE=FF_BYTE
chunksize=chunk_size
chunkstart=chunk_start
do3byte=ida_idaapi._BC695.false_p
f_is3byte=ida_idaapi._BC695.false_p
freechunk=free_chunk
get_3byte=ida_idaapi._BC695.false_p
is3byte=ida_idaapi._BC695.false_p
nextaddr=next_addr
nextchunk=next_chunk
nextthat=next_that
prevaddr=prev_addr
prevchunk=prev_chunk
prevthat=prev_that
tribyteflag=byte_flag
alignflag=align_flag
binflag=bin_flag
byteflag=byte_flag
charflag=char_flag
codeflag=code_flag
custflag=cust_flag
custfmtflag=custfmt_flag
decflag=dec_flag
doubleflag=double_flag
enumflag=enum_flag
floatflag=float_flag
fltflag=flt_flag
hexflag=hex_flag
numflag=num_flag
octflag=oct_flag
offflag=off_flag
packrealflag=packreal_flag
segflag=seg_flag
stkvarflag=stkvar_flag
stroffflag=stroff_flag
struflag=stru_flag
wordflag=word_flag
invalidate_visea_cache=ida_idaapi._BC695.false_p
@bc695redef_with_pydoc(op_stroff.__doc__)
def op_stroff(*args):
    insn, n, path, path_len, delta = args
    import ida_ua
    if not isinstance(insn, ida_ua.insn_t):
        tmp = ida_ua.insn_t()
        ida_ua.decode_insn(tmp, insn)
        insn = tmp
    return _ida_bytes.op_stroff(insn, n, path, path_len, delta)
#</pycode_BC695(py_bytes)>
