# TODO:
# * auto_queue_empty must return 1 by default. How should
#   that be specified? In idp.hpp, or in a specific, 'recipe' file?

# WARNING: The code you are about to look into, is surprisingly messy and
# convoluted. Especially since it doesn't do that much. Perhaps a good
# refactoring is in order?

import sys
major, minor, micro, _, _ = sys.version_info
if major < 2 or minor < 7:
    raise Exception("Expected Python version 2.7.x, but got %s.%s.%s (from %s)" % (major, minor, micro, sys.executable))


from argparse import ArgumentParser
p = ArgumentParser()

p.add_argument("-i", "--input",         required=True,  dest="input",         help="Input file")
p.add_argument("-o", "--output",        required=True,  dest="output",        help="Output file")
p.add_argument("-x", "--xml",           required=True,  dest="xml",           help="XML structure containing enumerations information")
p.add_argument("-e", "--enum",          required=True,  dest="enum",          help="Enumeration to look for")
p.add_argument("-m", "--marker",        required=True,  dest="marker",        help="Marker to look for, to start generating callbacks")
p.add_argument("-r", "--default-rtype", required=True,  dest="def_rtype",     help="Default return type, for notifications that don't specify it")
p.add_argument("-n", "--default-rval",  required=True,  dest="def_rval",      help="Default return value, for notifications that don't specify it")
p.add_argument("-q", "--qualifier",     required=False, dest="qualifier",     help="A possible qualifier, to put in front of enumerators", default="")
p.add_argument("-R", "--recipe",        required=False, dest="recipe",        help="Special information, needed to generate valid & compatible hooks")
p.add_argument("-d", "--discard-prefix",required=False, dest="discard_prefix",help="Discard all enum entries starting with the given prefix(es) (multiple prefixes can be specified as a comma-separated list.)")
p.add_argument("-D", "--discard-doc",   required=False, dest="discard_doc",   help="Typically for kernwin.hpp: ignore enum entries whose documentation starts with the specified pattern (e.g., 'ui:', which is for 'to UI' codes, and not 'from UI' codes)")
p.add_argument("-s", "--strip-prefix",  required=False, dest="strip_prefix",  help="Strip the given prefix from the enumerator name (e.g., 'ui_', for kernwin.hpp notifications)")
args = p.parse_args()

def warn(msg):
    print "#### WARNING: %s" % msg

if args.recipe:
    execfile(args.recipe)
else:
    recipe = {}

from xml.dom import *
import xml.etree.ElementTree as ET
tree = ET.parse(args.xml)

# Find enum def
enum_el = tree.find(".//memberdef[@kind='enum']/[name='%s']" % args.enum)


def parse_return_type(desc):
    default = None
    import re
    m = re.match(r".*\(default=([^\)]*)\).*", desc)
    if m:
        default = m.group(1)
    if desc.startswith("void"):
        return "void", default
    else:
        return parse_param_type(desc), default

def parse_param_type(desc):
    if desc.startswith("("):
        import re
        m = re.match(r"\(([^\)]*)\)\s*.*", desc)
        if m:
            ptype = m.group(1)
            return ptype.lstrip(":").replace(" ::", " ")

def collect_all_text(el):
    bits = []
    for txt in el.itertext():
        bits.append(txt)
    return "".join(bits)

enumerators = []
def add_enum_value(enumval_el, name, enum_name):
    if not name.startswith("OBSOLETE"):
        params = []

        # Return type
        ret_el = enumval_el.find(".//simplesect[@kind='return']")
        rdata = {"name" : "<return>"}
        rtype = None
        rdefault = None
        rexpr = None
        recipe_data = recipe.get(name, {})

        if "ignore" in recipe_data and recipe_data["ignore"]:
            return

        return_data = recipe_data["return"] if (recipe_data and "return" in recipe_data) else {}
        if "type" in return_data:
            rtype = return_data["type"]
        elif ret_el is not None:
            rdesc = ret_el.find("para").text
            rtype, rdefault = parse_return_type(rdesc)

        if rtype is None:
            rtype = args.def_rtype

        if rtype != "void" and rdefault is None:
            rdefault = args.def_rval
            assert(rdefault is not None)

        if "default" in return_data:
            rdefault = return_data["default"]
        if "retexpr" in return_data:
            rexpr = return_data["retexpr"]

        params.append({
            "name" : "<return>",
            "type" : rtype,
            "default" : rdefault,
            "retexpr" : rexpr,
            })

        # Parameters
        plist_el = enumval_el.find(".//parameterlist")
        if plist_el is not None:
            for pitem_el in plist_el.findall("./parameteritem"):
                pname = pitem_el.find(".//parametername").text
                if pname != "none":
                    pdesc = collect_all_text(pitem_el.find(".//parameterdescription/para"))
                    ptype = parse_param_type(pdesc)
                    if ptype is None:
                        warn("Couldn't parse parameter description: \"%s\". Dropping notification \"%s\" altogether" % (pdesc, name))
                        return
                    params.append({
                        "name" : pname,
                        "type" : ptype,
                        })

        # added parameters
        if "add_params" in recipe_data:
            params.extend(recipe_data["add_params"])

        enumerators.append({"name" : name, "params" : params, "enum_name" : enum_name})


# for each enum value...
for enumval_el in enum_el.findall("./enumvalue"):
    discarded = False
    enum_name = enumval_el.find("./name").text
    name = enum_name
    if args.discard_prefix:
        for pfx in args.discard_prefix.split(","):
            if name.startswith(pfx):
                discarded = True
                break
    if not discarded and args.discard_doc:
        discarded = collect_all_text(enumval_el.find("./detaileddescription")).strip().startswith(args.discard_doc) or \
                    collect_all_text(enumval_el.find("./briefdescription")).strip().startswith(args.discard_doc)
    if not discarded:
        if args.strip_prefix:
            pfxes = args.strip_prefix.split(",")
            for pfx in pfxes:
                if name.startswith(pfx):
                    name = name[len(pfx):]
                    break
        add_enum_value(enumval_el, name, enum_name)


def dump():
    for enumerator in enumerators:
        print "%s:" % enumerator["name"]
        rdata = enumerator["params"][0]
        print "\t%s: %s (default=%s)" % (
            rdata["name"], rdata["type"], rdata["default"])
        for p in enumerator["params"][1:]:
            print "\t%s: %s" % (p["name"], p["type"])

#dump()

def gen_methods(out):
    for e in enumerators:
        ename = e["name"]
        if ename in recipe:
            recipe_data = recipe[ename]
        else:
            recipe_data = {}

        method_name = recipe_data["method_name"] if "method_name" in recipe_data else ename

        params = e["params"]
        rdata = params[0]
        # We *must* name arguments, or typemaps won't be applied properly.
        # Thus, we must 'qnotused'-them.
        qnotused_decls = ""
        if rdata["type"] == "void":
            retbody = ""
        elif rdata["retexpr"]:
            retbody = "%s;" % rdata["retexpr"]
        else:
            retbody = "return %s;" % rdata["default"]
        arg_strs = []
        for p in (recipe_data["call_params"] if "call_params" in recipe_data else params[1:]):
            if isinstance(p, basestring):
                assert(p[0] == "@")
                synth_info = recipe["synthetic_params"][p]
                ptype = synth_info["type"]
                pname = p[1:]
            else:
                pname = p["name"]
                ptype = p["type"]
            suppress_for_call = False
            final_name = pname
            defstr = ""
            if "params" in recipe_data:
                all_pdata = recipe_data["params"]
                if pname in all_pdata:
                    pdata = all_pdata[pname]
                    if "type" in pdata:
                        ptype = pdata["type"]
                    if "suppress_for_call" in pdata:
                        suppress_for_call = pdata["suppress_for_call"]
                    if "rename" in pdata:
                        final_name = pdata["rename"]
                    if "default" in pdata:
                        defstr = "=%s" % pdata["default"]
            if not suppress_for_call:
                arg_strs.append("%s %s%s" % (ptype, final_name, defstr))
                qnotused_decls += "qnotused(%s); " % final_name
        text = "virtual %s %s(%s) {%s%s}\n" % (
            rdata["type"],
            method_name,
            ", ".join(arg_strs),
            qnotused_decls,
            retbody)
        out.write(text)

def gen_notifications(out):
    for e in enumerators:
        ename = e["name"]
        out.write("case %s%s:\n" % (args.qualifier, e["enum_name"]))
        out.write("{\n")
        params = e["params"]
        rdata = params[0]

        if ename in recipe:
            recipe_data = recipe[ename]
        else:
            recipe_data = {}
        method_name = recipe_data["method_name"] if "method_name" in recipe_data else ename

        # first, the arguments to pop from the stack
        nosynth_params = []
        for p in params[1:]:
            pname = p["name"]
            ptype = p["type"]
            pick_type = ptype
            if ptype in ["bool", "char", "uchar", "uint16", "cref_t", "dref_t", "cm_t", "ui_notification_t", "dbg_notification_t", "tcc_renderer_type_t", "range_kind_t", "demreq_type_t", "ctree_maturity_t"]:
                cast = ptype
                pick_type = "int"
            else:
                cast = ""
            out.write("  %s %s = %s%sva_arg(va, %s)%s;\n" % (
                ptype,
                pname,
                cast,
                "(" if cast else "",
                pick_type,
                ")" if cast else ""));
            nosynth_params.append(pname)

        # then, let's do a second pass, this time over the arguments that need
        # to be actually passed to the method (can differ; e.g., dbg.hpp
        # notifications' "event" is typically scattered into N args)

        argstr = [] # arguments to pass to the call, minus those explicitly suppressed
        argstr_all = [] # all arguments
        for p in (recipe_data["call_params"] if "call_params" in recipe_data else params[1:]):
            if isinstance(p, basestring):
                assert(p[0] == "@")
                synth_info = recipe["synthetic_params"][p]
                ptype = synth_info["type"]
                synth = synth_info["synth"]
                pname = p[1:]
            else:
                pname = p["name"]
                ptype = p["type"]
                synth = None
            param_convertor = None
            suppress_for_call = False
            qnotused = False
            clinked = None
            cast_needed = False
            deref = None
            if "params" in recipe_data:
                all_pdata = recipe_data["params"]
                if pname in all_pdata:
                    pdata = all_pdata[pname]
                    if "convertor" in pdata:
                        param_convertor = pdata["convertor"]
                    if "deref" in pdata:
                        deref = pdata["deref"]
                    if "suppress_for_call" in pdata:
                        suppress_for_call = pdata["suppress_for_call"]
                    if "qnotused" in pdata:
                        qnotused = pdata["qnotused"]
                    if "clinked" in pdata:
                        clinked = pdata["clinked"]
                    if "cast_needed" in pdata:
                        cast_needed = pdata["cast_needed"]

            pass_expr = pname
            if deref:
                pass_expr = "%s != NULL ? *(%s) : (%s)" % (
                    pname,
                    pname,
                    deref["ifNULL"])
            if clinked:
                out.write("  ref_t clinked_%s = create_linked_class_instance(%s, %s, %s);\n" %
                          (pname, clinked["module_define"], clinked["class_define"], pname))
                out.write("  if ( clinked_%s == NULL )\n" % pname)
                out.write("    break;\n")
                pass_expr = "clinked_%s.o" % pname
            elif synth:
                pass_expr = synth
            elif cast_needed:
                pass_expr = "(%s) %s" % (cast_needed, pname)

            if not suppress_for_call:
                if param_convertor:
                    argstr.append("%s(%s)" % (param_convertor, pass_expr))
                else:
                    argstr.append("%s" % (pass_expr))
            if qnotused:
                out.write("  qnotused(%s);\n" % pname)
            argstr_all.append(pname)

        ret_convertor = None
        ret_convertor_pass_args = False
        ret_convertor_pass_args_nosynth = False
        if "return" in recipe_data:
            retdata = recipe_data["return"]
            if "convertor" in retdata:
                ret_convertor = retdata["convertor"]
            if "convertor_pass_args" in retdata:
                ret_convertor_pass_args = retdata["convertor_pass_args"]
            if "convertor_pass_args_nosynth" in retdata:
                ret_convertor_pass_args_nosynth = retdata["convertor_pass_args_nosynth"]

        if ret_convertor:
            out.write("  %s _tmp = proxy->%s(%s);\n" % (
                retdata["type"],
                ename,
                ", ".join(argstr)))
            cvtargs = ["_tmp"]
            if ret_convertor_pass_args:
                if ret_convertor_pass_args_nosynth:
                    cvtargs.extend(nosynth_params)
                else:
                    cvtargs.extend(argstr_all)
            out.write("  ret = %s(%s);\n" % (ret_convertor, ", ".join(cvtargs)))
        else:
            if rdata["type"] == "void":
                rstr = ""
            else:
                rstr = "ret = "
            out.write("  %sproxy->%s(%s);\n" % (
                rstr,
                method_name,
                ", ".join(argstr)))

        out.write("}\n")
        out.write("break;\n\n")

with open(args.input, "rt") as fin:
    with open(args.output, "wt") as fout:
        for line in fin:
            fout.write(line)
            import re
            m = re.match(r".*%s:([^\s]*).*" % args.marker, line)
            if m:
                what = m.group(1)
                if what == "methods":
                    gen_methods(fout)
                elif what == "notifications":
                    gen_notifications(fout)
                else:
                    raise Exception("Unknown marker type: %s" % what)
