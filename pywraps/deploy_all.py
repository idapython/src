# Please use the same tag for the same .i file
# That means if many insertions are going to happen in one
# given .i file then don't use more than code marking tag

print "\n-------- DEPLOY started --------------------------------------------------\n"

deploys = {
    "idaapi (common functions, notifywhen)" : {
        "tag" : "py_idaapi",
        "src" : ["py_cvt.hpp", "py_idaapi.hpp", "py_idaapi.py", "py_notifywhen.hpp", "py_notifywhen.py"],
        "tgt" : "../swig/idaapi.i"
        },

    "View (common)" : {
        "tag" : "py_view_base",
        "src" : ["py_view_base.hpp", "py_view_base.py"],
        "tgt" : "../swig/view.i"
        },

    "IDAView" : {
        "tag" : "py_idaview",
        "src" : ["py_idaview.hpp", "py_idaview.py"],
        "tgt" : "../swig/view.i"
        },

    "Graph" : {
        "tag" : "py_graph",
        "src" : ["py_graph.hpp", "py_graph.py"],
        "tgt" : "../swig/graph.i"
        },

    "custview" : {
        "tag" : "py_custviewer",
        "src" : ["py_custview.py","py_custview.hpp"],
        "tgt" : "../swig/kernwin.i"
        },

    "plgform" : {
        "tag" : "py_plgform",
        "src" : ["py_plgform.hpp","py_plgform.py"],
        "tgt" : "../swig/kernwin.i"
        },

    "expr" : {
        "tag" : "py_expr",
        "src" : ["py_expr.hpp","py_expr.py"],
        "tgt" : "../swig/expr.i"
        },

    "cli" : {
        "tag" : "py_cli",
        "src" : ["py_cli.py","py_cli.hpp"],
        "tgt" : "../swig/kernwin.i"
        },

    "Loader" : {
        "tag" : "py_loader",
        "src" : ["py_loader.hpp"],
        "tgt" : "../swig/loader.i"
        },

    "kernwin, choose2, askusingform" : {
        "tag" : "py_kernwin",
        "src" : ["py_kernwin.hpp","py_kernwin.py","py_choose.hpp","py_choose2.hpp","py_choose2.py","py_askusingform.hpp","py_askusingform.py"],
        "tgt" : "../swig/kernwin.i"
        },

    "idd" : {
        "tag" : "py_idd",
        "src" : ["py_dbg.hpp","py_appcall.py"],
        "tgt" : "../swig/idd.i"
        },

    "idd (python)" : {
        "tag" : "py_idd_2",
        "src" : ["py_dbg.py"],
        "tgt" : "../swig/idd.i"
        },

    "nalt" : {
        "tag" : "py_nalt",
        "src" : ["py_nalt.hpp","py_nalt.py"],
        "tgt" : "../swig/nalt.i"
        },

    "dbg" : {
        "tag" : "py_dbg",
        "src" : ["py_dbg.hpp"],
        "tgt" : "../swig/dbg.i"
        },

    "linput/diskio" : {
        "tag" : "py_diskio",
        "src" : ["py_linput.hpp","py_diskio.hpp","py_diskio.py"],
        "tgt" : "../swig/diskio.i"
        },

    "name" : {
        "tag" : "py_name",
        "src" : ["py_name.hpp","py_name.py"],
        "tgt" : "../swig/name.i"
        },

    "qfile" : {
        "tag" : "py_qfile",
        "src" : ["py_qfile.hpp"],
        "tgt" : "../swig/fpro.i"
        },

    "bytes" : {
        "tag" : "py_bytes",
        "src" : ["py_bytes.hpp","py_custdata.py","py_custdata.hpp"],
        "tgt" : "../swig/bytes.i"
        },

    "typeinf" : {
        "tag" : "py_typeinf",
        "src" : ["py_typeinf.hpp","py_typeinf.py"],
        "tgt" : "../swig/typeinf.i"
        },

    "gdl" : {
        "tag" : "py_gdl",
        "src" : ["py_gdl.py"],
        "tgt" : "../swig/gdl.i"
        },

    "ua" : {
        "tag" : "py_ua",
        "src" : ["py_ua.hpp","py_ua.py"],
        "tgt" : "../swig/ua.i"
        },

    "idp" : {
        "tag" : "py_idp",
        "src" : ["py_idp.hpp"],
        "tgt" : "../swig/idp.i"
        },

    "lines" : {
        "tag" : "py_lines",
        "src" : ["py_lines.hpp","py_lines.py"],
        "tgt" : "../swig/lines.i"
        },

    "pc_win32_appcall" : {
        "tag" : "appcalltest",
        "src" : ["py_appcall.py"],
        "tgt" : "../../../tests/input/pc_win32_appcall.pe.hints"
        },

    "ex_custdata example" : {
        "tag" : "ex_custdata",
        "src" : ["../examples/ex_custdata.py"],
        "tgt" : "../../../tests/input/pc_win32_custdata1.pe.hints"
        },

    "ex_formchooser" : {
        "tag" : "ex_formchooser",
        "src" : ["py_askusingform.py"],
        "tgt" : "../../formchooser/formchooser.py"
        },

    "ex_askusingform" : {
        "tag" : "ex_askusingform",
        "src" : ["py_askusingform.py"],
        "tgt" : "../examples/ex_askusingform.py"
        },

    "ex_cli example" : {
        "tag" : "ex_cli_ex1",
        "src" : ["py_cli.py"],
        "tgt" : "../examples/ex_cli.py"
        },

    "ex_expr example" : {
        "tag" : "ex_expr",
        "src" : ["py_expr.py"],
        "tgt" : "../examples/ex_expr.py"
        },

    "ex_custview.py example" : {
        "tag" : "py_custviewerex1",
        "src" : ["py_custview.py"],
        "tgt" : "../examples/ex_custview.py"
        }
    }

import deploy
for name in deploys:
    data = deploys[name]
    print "Deploying %s" % name
    deploy.deploy(data["tag"], data["src"], data["tgt"])

