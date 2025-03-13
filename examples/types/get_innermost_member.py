"""
summary: get information about the "innermost" member of a structure

description:
    Assuming the 2 following types:

            struct b
            {
                int low;
                int high;
            };

            struct a
            {
                int foo;
                b b_instance;
                int bar;
            };

    looking at an offset of 5 bytes inside an `a` instance, might be
    interpreted as pointing somewhere inside member `b_instance`, of type `b`.
    Alternatively, that same offset might be intprereted as pointing
    somewhere inside `low`, of type `int`.

    We refer to that latter interpretation as "innermost", and this sample
    shows how the API lets us "drill down" to retrieve that innermost member.

level: intermediate
"""
import ida_typeinf
import ida_idaapi

test_types = """

/* Taken from lighttpd headers */

struct lshpack_enc_table_entry;
struct lshpack_double_enc_head;

typedef unsigned long long unix_time64_t;

struct lshpack_enc_head { int whatever; };

struct lshpack_enc
{
    unsigned            hpe_cur_capacity;
    unsigned            hpe_max_capacity;

    /* Each new dynamic table entry gets the next number.  It is used to
     * calculate the entry's position in the decoder table without having
     * to maintain an actual array.
     */
    unsigned            hpe_next_id;

    /* Dynamic table entries (struct enc_table_entry) live in two hash
     * tables: name/value hash table and name hash table.  These tables
     * are the same size.
     */
    unsigned            hpe_nelem;
    unsigned            hpe_nbits;
    struct lshpack_enc_head
                        hpe_all_entries;
    struct lshpack_double_enc_head
                       *hpe_buckets;

    uint32_t           *hpe_hist_buf;
    unsigned            hpe_hist_size, hpe_hist_idx;
    int                 hpe_hist_wrapped;
    enum {
        LSHPACK_ENC_USE_HIST    = 1 << 0,
    }                   hpe_flags;
};

struct lshpack_arr
{
    unsigned        nalloc,
                    nelem,
                    off;
    uintptr_t      *els;
};

struct lshpack_dec
{
    struct lshpack_arr hpd_dyn_table;
    unsigned           hpd_max_capacity;       /* Maximum set by caller */
    unsigned           hpd_cur_max_capacity;   /* Adjusted at runtime */
    unsigned           hpd_cur_capacity;
    unsigned           hpd_state;
};


struct request_st;
struct h2con {
    request_st *r[8];
    uint32_t rused;

    uint32_t h2_cid;
    uint32_t h2_sid;
     int32_t sent_goaway;
    unix_time64_t sent_settings;
    uint32_t s_header_table_size;      /* SETTINGS_HEADER_TABLE_SIZE      */
    uint32_t s_enable_push;            /* SETTINGS_ENABLE_PUSH            */
    uint32_t s_max_concurrent_streams; /* SETTINGS_MAX_CONCURRENT_STREAMS */
     int32_t s_initial_window_size;    /* SETTINGS_INITIAL_WINDOW_SIZE    */
    uint32_t s_max_frame_size;         /* SETTINGS_MAX_FRAME_SIZE         */
    uint32_t s_max_header_list_size;   /* SETTINGS_MAX_HEADER_LIST_SIZE   */
    struct lshpack_dec decoder;
    struct lshpack_enc encoder;
    unix_time64_t half_closed_ts;
};
"""

def get_innermost_member(tif, byte_offset):
    if tif.is_udt():
        (found_tif, idx, _) = tif.get_innermost_udm(byte_offset * 8)
        idx, udm = found_tif.get_udm(idx)
        if udm:
            return found_tif, udm
    return None, None

def main():

    idati = ida_typeinf.get_idati()

    # get, or add parent type
    tif = idati.get_named_type("h2con")
    if not tif:
        if ida_typeinf.parse_decls(idati, test_types, True, 0) != 0:
            print("Types could not be parsed.")
            return
        tif = idati.get_named_type("h2con")

    found_tif, member_in_found_tif = get_innermost_member(tif, 0x9a) # in the middle of h2con.encoder.hpe_hist_wrapped
    if found_tif and member_in_found_tif:
        print(f"Found innermost type '{found_tif}', at member with name '{member_in_found_tif.name}' and type '{member_in_found_tif.type}'")

main()
