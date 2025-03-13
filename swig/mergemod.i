
%{
#include <mergemod.hpp>
%}

%ignore create_std_modmerge_handlers;
%rename(create_std_modmerge_handlers) create_std_modmerge_handlers2;
%ignore create_std_modmerge_handlers2(merge_handler_params_t &,int,moddata_diff_helper_t &,merge_node_info2_t const *);

// Prototype of the custom function to create merge handlers
%ignore create_merge_handlers;

// idaman void ida_export create_std_modmerge_handlers2(
//         merge_handler_params_t &mhp,
//         int moddata_id,
//         moddata_diff_helper_t &helper,
//         const merge_node_info2_t *merge_node_info=nullptr,
//         size_t n_merge_node_info=0);
%define_merge_handler_typemap(merge_node_info, n_merge_node_info);

%include "mergemod.hpp"

