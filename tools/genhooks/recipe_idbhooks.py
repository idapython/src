
recipe = {
    "enum_const_created" : {
        "method_name" : "enum_member_created",
        "add_params" : [
            { "name" : "id", "type" : "enum_t" },
            { "name" : "cid", "type" : "const_t" },
            ],
        },
    "enum_const_deleted" : {
        "method_name" : "enum_member_deleted",
        "add_params" : [
            { "name" : "id", "type" : "enum_t" },
            { "name" : "cid", "type" : "const_t" },
            ],
        },
}

default_rtype = "void"
