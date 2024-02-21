
%{
#include <lumina.hpp>
%}

%feature("nodirector") lumina_client_t;
%ignore lumina_client_t::lumina_client_t;
%ignore lumina_client_t::can_del_history;

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
%rpc_packet_data_t(pkt_helo_result_t, PKT_HELO_RESULT);
%rpc_packet_data_t(pkt_pull_md_t, PKT_PULL_MD);
%rpc_packet_data_t(pkt_pull_md_result_t, PKT_PULL_MD_RESULT);
%rpc_packet_data_t(pkt_push_md_t, PKT_PUSH_MD);
%rpc_packet_data_t(pkt_push_md_result_t, PKT_PUSH_MD_RESULT);
%rpc_packet_data_t(pkt_get_pop_t, PKT_GET_POP);
%rpc_packet_data_t(pkt_get_pop_result_t, PKT_GET_POP_RESULT);
%rpc_packet_data_t(pkt_get_lumina_info_t, PKT_GET_LUMINA_INFO);
%rpc_packet_data_t(pkt_get_lumina_info_result_t, PKT_GET_LUMINA_INFO_RESULT);

%template(lumina_op_res_vec_t) qvector<lumina_op_res_t>;

//-------------------------------------------------------------------------
//                               metadata_t
//-------------------------------------------------------------------------
%bytes_container_ptr_and_ref(
        metadata_t,
        begin,
        size,
        ,
        PyBytes_Check,
        PyBytes_as_bytevec_t,
        PyBytes_FromStringAndSize,
        _sized_binary_result,
        _maybe_sized_binary_result,
        "bytes",
        "bytes");

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
  if ( !PyBytes_Check($input) )
    SWIG_exception_fail(SWIG_TypeError, "Expected bytes in method '$symname', argument $argnum of type 'bytes'");
  bytevec_t bytes;
  char *buffer = nullptr;
  Py_ssize_t length = 0;
  if ( PyBytes_AsStringAndSize($input, &buffer, &length) )
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
  PyObject *py_md = PyBytes_FromStringAndSize((const char *) $1->begin(), $1->size());
  $result = SWIG_Python_AppendOutput($result, py_md);
}


//-------------------------------------------------------------------------
//                                md5_t
//-------------------------------------------------------------------------
%typemap(in) md5_t *md5 // for _wrap_input_file_t_md5_set
{
  // typemap(in) md5_t *
  qstring buf;
  PyUnicode_as_qstring(&buf, $input);
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
  $result = PyBytes_FromStringAndSize((const char *) $1->hash, sizeof($1->hash));
}

// suppress the output parameter as an input.
%typemap(in,numinputs=0) md5_t *out (md5_t tmp) %{
  // typemap(in,numinputs=0) md5_t *out
  $1 = &tmp;
%}

%typemap(argout) (md5_t *out)
{
  // typemap(argout) (md5_t *out)
  PyObject *py_hash = PyBytes_FromStringAndSize((const char *) $1->hash, sizeof($1->hash));
  $result = SWIG_Python_AppendOutput($result, py_hash);
}

%apply md5_t *out { md5_t *out_hash };

%apply int64 *INPUT { const int64 * };
%typemap(directorin) const int64 *
{ // %typemap(directorin) const int64 *
  if ( $1 != nullptr )
  {
    $input = PyLong_FromLongLong(int64(*($1)));
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

%numbers_list_to_values_vec(ea64vec_t, SWIGTYPE_p_qvectorT_unsigned_long_long_t, PyW_PySeqToEa64Vec);

%include "lumina.hpp"

%inline %{
//<inline(py_lumina)>
//</inline(py_lumina)>
%}

%pythoncode %{
#<pycode(py_lumina)>
#</pycode(py_lumina)>
%}
