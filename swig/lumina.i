
%{
#include <lumina.hpp>
%}

%feature("nodirector") lumina_client_t;
%ignore lumina_client_t::lumina_client_t;

%ignore metadata_t;
%ignore metadata_creator_t;
%ignore md5_t;
%ignore lumina_host;
%ignore lumina_port;
%ignore lumina_tls;
%ignore lumina_min_func_size;
%ignore lumina_rpc_packet_t_descs;
%ignore lumina_client_t::send_helo;
%ignore pattern_id_t::swap;
%ignore func_info_base_t::swap;
%ignore func_info_t::swap;
%ignore func_info_and_frequency_t::swap;
%ignore func_info_pattern_and_frequency_t::swap;
%ignore input_file_t::swap;
%ignore func_info_pattern_and_frequency_t::swap;
%ignore mdkey2str;
%ignore str2mdkey;
%ignore serialize;
%ignore deserialize;
%ignore new_lumina_client;
%ignore close_server_connection;
%ignore close_server_connection2;
%ignore close_server_connections;
%ignore get_mdkey_preferred_format;
%ignore extract_type_from_metadata;
%rename (extract_type_from_metadata) py_extract_type_from_metadata;
%rename (split_metadata) py_split_metadata;
%ignore swap_md5;
%ignore print_md5;
%ignore parse_md5;
%ignore auto_apply_lumina;
%ignore eavec_to_ea64vec;
%ignore ea64vec_to_eavec;


%feature("nodirector") simple_diff_handler_t;
%ignore simple_diff_handler_t::simple_diff_handler_t;

%feature("nodirector") simple_idb_diff_handler_t;
%ignore simple_idb_diff_handler_t::simple_idb_diff_handler_t;

%ignore serialized_tinfo::empty;

%define %rpc_packet_data_t(TYPE, ENUMERATOR)
%feature("nodirector") TYPE;
%extend TYPE {
    TYPE() { return (TYPE *) new_packet(ENUMERATOR); }
};
%ignore TYPE::TYPE;
%enddef

%rpc_packet_data_t(pkt_rpc_ok_t, PKT_RPC_OK);
%rpc_packet_data_t(pkt_rpc_fail_t, PKT_RPC_FAIL);
%rpc_packet_data_t(pkt_rpc_notify_t, PKT_RPC_NOTIFY);
%rpc_packet_data_t(pkt_helo_t, PKT_HELO);
%rpc_packet_data_t(pkt_pull_md_t, PKT_PULL_MD);
%rpc_packet_data_t(pkt_pull_md_result_t, PKT_PULL_MD_RESULT);
%rpc_packet_data_t(pkt_push_md_t, PKT_PUSH_MD);
%rpc_packet_data_t(pkt_push_md_result_t, PKT_PUSH_MD_RESULT);
%rpc_packet_data_t(pkt_get_pop_t, PKT_GET_POP);
%rpc_packet_data_t(pkt_get_pop_result_t, PKT_GET_POP_RESULT);

%template(lumina_op_res_vec_t) qvector<lumina_op_res_t>;

//-------------------------------------------------------------------------
//                               metadata_t
//-------------------------------------------------------------------------
#ifdef PY3
%bytes_container_ptr_and_ref(
        metadata_t,
        begin,
        size,
        ,
        IDAPyBytes_Check,
        IDAPyBytes_AsBytes,
        IDAPyBytes_FromMemAndSize,
        _sized_binary_result,
        _maybe_sized_binary_result,
        "bytes",
        "bytes");
#else
%bytes_container_ptr_and_ref(
        metadata_t,
        begin,
        size,
        ,
        IDAPyBytes_Check,
        IDAPyBytes_AsBytes,
        IDAPyBytes_FromMemAndSize,
        _sized_binary_result,
        _maybe_sized_binary_result,
        "string",
        "str");
#endif

%make_argout_errbuf_raise_exception_when_non_empty();

%uncomparable_elements_qvector(func_info_t, func_info_vec_t);
%uncomparable_elements_qvector(func_info_and_frequency_t, func_info_and_frequency_vec_t);
%uncomparable_elements_qvector(func_info_and_pattern_t, func_info_and_pattern_vec_t);
%uncomparable_elements_qvector(func_info_pattern_and_frequency_t, func_info_pattern_and_frequency_vec_t);
%uncomparable_elements_qvector(insn_cmt_t, insn_cmts_t);
%uncomparable_elements_qvector(user_stkpnt_t, user_stkpnts_t);
%uncomparable_elements_qvector(frame_mem_t, frame_mems_t);
%uncomparable_elements_qvector(extra_cmt_t, extra_cmts_t);
%uncomparable_elements_qvector(skipped_func_t, skipped_funcs_t);
%uncomparable_elements_qvector(insn_ops_repr_t, insn_ops_reprs_t);

//-------------------------------------------------------------------------
//                            metadata_t blob
//-------------------------------------------------------------------------
%typemap(in) (const uchar *ptr, const uchar *end) // for _wrap_extract_..._from_metadata
{
  if ( !IDAPyBytes_Check($input) )
    SWIG_exception_fail(SWIG_TypeError, "Expected bytes in method '$symname', argument $argnum of type 'bytes'");
  bytevec_t bytes;
  char *buffer = nullptr;
  Py_ssize_t length = 0;
  if ( IDAPyBytes_AsMemAndSize($input, &buffer, &length) )
  {
    bytes.append(buffer, length);
    $1 = bytes.begin();
    $2 = bytes.end();
    QASSERT(30575, $2 >= $1);
  }
}

%apply metadata_t *result { metadata_t *out_md };
%typemap(argout) (metadata_t *out_md)
{
  // bytes_container typemap(argout) (metadata_t *out_md)
  PyObject *py_md = IDAPyBytes_FromMemAndSize((const char *) $1->begin(), $1->size());
  $result = SWIG_Python_AppendOutput($result, py_md);
}


//-------------------------------------------------------------------------
//                                md5_t
//-------------------------------------------------------------------------
%typemap(in) md5_t *md5 // for _wrap_input_file_t_md5_set
{
  // typemap(in) md5_t *
  qstring buf;
  IDAPyStr_AsUTF8(&buf, $input);
  $1 = new md5_t;
  memmove($1->hash, buf.c_str(), qmin(sizeof($1->hash), buf.length()));
}

%typemap(freearg) md5_t *md5 // for _wrap_input_file_t_md5_set
{
  // typemap(freearg) md5_t *
  delete $1;
}

%typemap(out) md5_t *
{ // typemap(out) md5_t *
  $result = IDAPyBytes_FromMemAndSize((const char *) $1->hash, sizeof($1->hash));
}

// suppress the output parameter as an input.
%typemap(in,numinputs=0) md5_t *out (md5_t tmp) %{
  // typemap(in,numinputs=0) md5_t *out
  $1 = &tmp;
%}

%typemap(argout) (md5_t *out)
{
  // typemap(argout) (md5_t *out)
  PyObject *py_hash = IDAPyBytes_FromMemAndSize((const char *) $1->hash, sizeof($1->hash));
  $result = SWIG_Python_AppendOutput($result, py_hash);
}

%apply md5_t *out { md5_t *out_hash };

%apply longlong *INPUT { const int64 * };
%typemap(directorin) const int64 *
{ // %typemap(directorin) const int64 *
  if ( $1 != NULL )
  {
    $input = PyLong_FromLongLong(longlong(*($1)));
  }
  else
  {
    Py_INCREF(Py_None);
    $input = Py_None;
  }
}

// We can't put that in header.i.in ATM, because it would
// inappropriately apply to the qstrvec_t/clink thing.
%typemap(out) qstrvec_t *
{ // %typemap(out) qstrvec_t *
  resultobj = qstrvec2pylist(*($1));
}

%numbers_list_to_values_vec(ea64vec_t, SWIGTYPE_p_qvectorT_unsigned_long_long_t, PyW_PyListToEa64Vec);

%include "lumina.hpp"

%inline %{
//<inline(py_lumina)>
//</inline(py_lumina)>
%}
