%{
#include <srclang.hpp>
%}

%ignore srclang_parser_t;
%ignore srclang_parsers_t;
%ignore srclang_parser_obj_t;
%ignore install_srclang_parser;
%ignore remove_srclang_parser;
%ignore select_srclang_parser;
%ignore get_srclang_parser_internal;
%ignore get_current_srclang_parser;
%ignore srclang_parser_visitor_t;
%ignore for_all_srclang_parsers;
%ignore find_parser_kind_t;
%ignore find_srclang_parser;
%ignore find_parser_by_idx;
%ignore find_parser_by_name;
%ignore find_parser_by_srclang;
%ignore init_srclang_parser;
%ignore term_srclang_parser;

%include "srclang.hpp"
