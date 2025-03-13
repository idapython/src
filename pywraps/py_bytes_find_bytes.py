#<pycode(py_bytes_find_bytes)>

import typing

import ida_idaapi
import ida_nalt
import ida_range

def find_bytes(
        bs: typing.Union[bytes, bytearray, str],
        range_start: int,
        range_size: typing.Optional[int] = None,
        range_end: typing.Optional[int] = ida_idaapi.BADADDR,
        mask: typing.Optional[typing.Union[bytes, bytearray]] = None,
        flags: typing.Optional[int] = BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW,
        radix: typing.Optional[int] = 16,
        strlit_encoding: typing.Optional[typing.Union[int, str]] = PBSENC_DEF1BPU) -> int:

    if isinstance(range_start, ida_range.range_t):
        range_start, range_end = range_start.start_ea, range_start.end_ea

    patterns = compiled_binpat_vec_t()
    if isinstance(bs, str):
        if isinstance(strlit_encoding, str):
            strlit_encoding_i = ida_nalt.add_encoding(strlit_encoding)
            if strlit_encoding_i > 0:
                strlit_encoding = strlit_encoding_i
            else:
                raise Exception("Unknown encoding: \"%s\"" % strlit_encoding)
        parse_result = parse_binpat_str(
            patterns,
            range_start,
            bs,
            radix,
            strlit_encoding)
        if parse_result is False or (isinstance(parse_result, str) and len(parse_result) > 0):
            raise Exception("Could not parse pattern: %s" % (parse_result or "unknown error",))
    else:
        p0 = patterns.push_back()
        p0.bytes = __to_bytevec(bs)
        if mask is not None:
            p0.mask = __to_bytevec(mask)

    if range_size is not None:
        range_end = range_start + range_size

    ea, _ = bin_search(range_start, range_end, patterns, flags)
    return ea


def find_string(
        _str: str,
        range_start: int,
        range_end: typing.Optional[int] = ida_idaapi.BADADDR,
        range_size: typing.Optional[int] = None,
        strlit_encoding: typing.Optional[typing.Union[int, str]] = PBSENC_DEF1BPU,
        flags: typing.Optional[int] = BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW) -> int:
    escaped = _str.replace('"', r"\22")
    return find_bytes(
        '"' + escaped + '"',
        range_start,
        range_end=range_end,
        range_size=range_size,
        flags=flags,
        strlit_encoding=strlit_encoding)


#</pycode(py_bytes_find_bytes)>
