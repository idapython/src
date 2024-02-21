#<pycode(py_typeinf)>

import ida_idaapi
ida_idaapi._listify_types(
    reginfovec_t)

#
# When turning off BC695, 'idati' would still remain available
#
_real_cvar = cvar
_notify_idati = ida_idaapi._make_one_time_warning_message("idati", "get_idati()")

class _wrap_cvar(object):
    def __getattr__(self, attr):
        if attr == "idati":
            _notify_idati()
            return get_idati()
        return getattr(_real_cvar, attr)

    def __setattr__(self, attr, value):
        if attr != "idati":
            setattr(_real_cvar, attr, value)

cvar = _wrap_cvar()

# for compatilibity:
sc_auto   = SC_AUTO
sc_ext    = SC_EXT
sc_friend = SC_FRIEND
sc_reg    = SC_REG
sc_stat   = SC_STAT
sc_type   = SC_TYPE
sc_unk    = SC_UNK
sc_virt   = SC_VIRT

TERR_SAVE      = TERR_SAVE_ERROR
TERR_WRONGNAME = TERR_BAD_NAME
TERR_BADSYNC   = TERR_BAD_SYNC

BADORD = 0xFFFFFFFF

enum_member_vec_t = edmvec_t
enum_member_t = edm_t
udt_member_t = udm_t
tinfo_t.find_udt_member = tinfo_t.find_udm

IMPTYPE_VERBOSE  = 0x0001
IMPTYPE_OVERRIDE = 0x0002

#</pycode(py_typeinf)>
