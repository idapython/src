{
    "op_stroff" : {
        "+example" :
"""
ins = ida_ua.insn_t()
if ida_ua.decode_insn(ins, some_address):
    path_len = 1
    path = ida_pro.tid_array(path_len)
    path[0] = ida_struct.get_struc_id("my_stucture_t")
    ida_bytes.op_stroff(ins, 0, path.cast(), path_len, 0)
"""
    }
}
