
# Note that we DON'T define EZERO/EONE/ETWO to be fpvalue_t objects,
# because there is no way to make them read-only, which means EZERO
# could represent something entirely different from zero if the
# user mistakenly modifies it.

#<pycode(py_ieee)>
EZERO = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
EONE = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xFF\x3F"
ETWO = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x40"
#</pycode(py_ieee)>
