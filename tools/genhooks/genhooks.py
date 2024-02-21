from __future__ import print_function
# TODO:
# * auto_queue_empty must return 1 by default. How should
#   that be specified? In idp.hpp, or in a specific, 'recipe' file?

# WARNING: The code you are about to look into, is surprisingly messy and
# convoluted. Especially since it doesn't do that much. Perhaps a good
# refactoring is in order?

import os
import sys

dirname, _ = os.path.split(__file__)
parent_dirname, _ = os.path.split(dirname)
if parent_dirname not in sys.path:
    sys.path.append(parent_dirname)

from argparse import ArgumentParser
p = ArgumentParser()

p.add_argument("-i", "--input",       required=True, help="Input file")
p.add_argument("-o", "--output",      required=True, help="Output file")
p.add_argument("-x", "--xml-dir",     required=True, help="XML structure containing enumerations information")
p.add_argument("-c", "--hooks-class", required=True, help="Name of the hooks class")
p.add_argument("-m", "--marker",      required=True, help="Marker to look for, to start generating callbacks")
p.add_argument("-q", "--qualifier",   required=False, help="A possible qualifier, to put in front of enumerators", default="")
args = p.parse_args()

def warn(msg):
    print("#### WARNING: %s" % msg)

import hooks_utils
enum_info = hooks_utils.get_hooks_enum_information(args.hooks_class)
recipe = enum_info.recipe
enumerators = hooks_utils.get_hooks_enumerators(args.xml_dir, args.hooks_class)

def dump():
    for enumerator in enumerators:
        print("%s:" % enumerator["name"])
        rdata = enumerator["params"][0]
        print("\t%s: %s (default=%s)" % (
            rdata["name"], rdata["type"], rdata["default"]))
        for p in enumerator["params"][1:]:
            print("\t%s: %s" % (p["name"], p["type"]))

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
            if isinstance(p, str):
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
            pname = recipe_data.get("params", {}).get(pname, {}).get("rename", pname)
            ptype = p["type"]
            pick_type = ptype
            # instead of va_argi() we jst promote the type to "int"
            if ptype in ["bool", "char", "uchar", "uint16", "cref_t",
              "dref_t", "cm_t", "ui_notification_t", "dbg_notification_t",
              "tcc_renderer_type_t", "range_kind_t", "demreq_type_t",
              "ctree_maturity_t", "comp_t", "local_type_change_t"]:
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
            if isinstance(p, str):
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
                    if "rename" in pdata:
                        pname = pdata["rename"]
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
                pass_expr = "%s != nullptr ? *(%s) : (%s)" % (
                    pname,
                    pname,
                    deref["ifNULL"])
            if clinked:
                out.write("  ref_t clinked_%s = create_linked_class_instance(%s, %s, %s);\n" %
                          (pname, clinked["module_define"], clinked["class_define"], pname))
                out.write("  if ( clinked_%s == nullptr )\n" % pname)
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
            out.write("  %s _tmp = %s(%s);\n" % (
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
            out.write("  %s%s(%s);\n" % (
                rstr,
                method_name,
                ", ".join(argstr)))

        out.write("}\n")
        out.write("break;\n\n")


def gen_methodsinfo_decl(out):
    out.write("    static const event_code_to_method_name_t mappings[%d];\n" % len(enumerators))
    out.write("    static const size_t mappings_size;\n")

def gen_methodsinfo_def(out):
    out.write("""
const hooks_base_t::event_code_to_method_name_t %s::mappings[%d] =
{
""" % (args.hooks_class, len(enumerators)))
    for e in enumerators:
        ename = e["name"]
        recipe_data = recipe.get(ename, {})
        method_name = recipe_data.get("method_name", ename)
        out.write("{ int(%s%s), \"%s\" },\n" % (args.qualifier, e["enum_name"], method_name))

    out.write("""
};
const size_t %s::mappings_size = %d;
""" % (args.hooks_class, len(enumerators)))

def gen_safecall(out, class_name):
    out.write("""
  %s *proxy = (%s *) ud;
  ssize_t ret = 0;
  try
  {
    if ( !proxy->has_fixed_method_set() || proxy->has_nondef[int(code)] > 0 )
    {
      // This hook gets called from the kernel. Ensure we hold the GIL.
      PYW_GIL_GET;

      if ( proxy->call_requires_new_execution() )
      {
        new_execution_t exec;
        ret = proxy->dispatch(code, va);
      }
      else
      {
        ret = proxy->dispatch(code, va);
      }
    }
  }
  catch ( Swig::DirectorException &e )
  {
    PYW_GIL_GET;
    msg("Exception in %%s dispatcher function: %%s\\n", proxy->class_name, e.getMessage());
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
""" % (class_name, class_name))


with open(args.input) as fin:
    with open(args.output, "w") as fout:
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
                elif what == "methodsinfo_decl":
                    gen_methodsinfo_decl(fout)
                elif what == "methodsinfo_def":
                    gen_methodsinfo_def(fout)
                elif what.startswith("safecall="):
                    gen_safecall(fout, what[9:])
                else:
                    raise Exception("Unknown marker type: %s" % what)
