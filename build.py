#!/usr/bin/env python
#---------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler
#
# (c) The IDAPython Team <idapython@googlegroups.com>
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#---------------------------------------------------------------------
# build.py - Custom build script
#---------------------------------------------------------------------
import os
import platform
import shutil
import sys
import types
import zipfile
import glob
from distutils import sysconfig

# Start of user configurable options
VERBOSE = True

IDA_MAJOR_VERSION = 6
IDA_MINOR_VERSION = 3

if 'IDA' in os.environ:
    IDA_SDK = os.environ['IDA']
else:
    IDA_SDK = os.path.join("..", "swigsdk-versions", ("%d.%d" % (IDA_MAJOR_VERSION, IDA_MINOR_VERSION)))

# End of user configurable options

# IDAPython version
VERSION_MAJOR  = 1
VERSION_MINOR  = 5
VERSION_PATCH  = 5

# Determine Python version
PYTHON_MAJOR_VERSION = int(platform.python_version()[0])
PYTHON_MINOR_VERSION = int(platform.python_version()[2])

# Find Python headers
PYTHON_INCLUDE_DIRECTORY = sysconfig.get_config_var('INCLUDEPY')

# Swig command-line parameters
SWIG_OPTIONS = '-modern -python -c++ -w451 -shadow -D__GNUC__ -DNO_OBSOLETE_FUNCS'

# Common macros for all compilations
COMMON_MACROS = [
    ("VER_MAJOR",  "%d" % VERSION_MAJOR),
    ("VER_MINOR",  "%d" % VERSION_MINOR),
    ("VER_PATCH",  "%d" % VERSION_PATCH),
    "__IDP__",
    ("MAXSTR", "1024"),
    "USE_DANGEROUS_FUNCTIONS",
    "USE_STANDARD_FILE_FUNCTIONS" ]

# Common includes for all compilations
COMMON_INCLUDES = [ ".", "swig" ]

# List files for the binary distribution
BINDIST_MANIFEST = [
    "README.txt",
    "COPYING.txt",
    "CHANGES.txt",
    "AUTHORS.txt",
    "STATUS.txt",
    "python.cfg",
    "docs/notes.txt",
    "examples/chooser.py",
    "examples/colours.py",
    "examples/ex_idphook_asm.py",
    "examples/ex_uirequests.py",
    "examples/debughook.py",
    "examples/ex_cli.py",
    "examples/ex1.idc",
    "examples/ex_custdata.py",
    "examples/ex1_idaapi.py",
    "examples/ex1_idautils.py",
    "examples/hotkey.py",
    "examples/structure.py",
    "examples/ex_gdl_qflow_chart.py",
    "examples/ex_strings.py",
    "examples/ex_add_menu_item.py",
    "examples/ex_func_chooser.py",
    "examples/ex_choose2.py",
    "examples/ex_debug_names.py",
    "examples/ex_graph.py",
    "examples/ex_hotkey.py",
    "examples/ex_patch.py",
    "examples/ex_expr.py",
    "examples/ex_timer.py",
    "examples/ex_dbg.py",
    "examples/ex_custview.py",
    "examples/ex_prefix_plugin.py",
    "examples/ex_pyside.py",
    "examples/ex_pyqt.py",
    "examples/ex_askusingform.py",
    "examples/ex_uihook.py",
    "examples/ex_idphook_asm.py",
    "examples/ex_imports.py"
]

# List files for the source distribution (appended to binary list)
SRCDIST_MANIFEST = [
    "BUILDING.txt",
    "python.cpp",
    "basetsd.h",
    "build.py",
    "python.cfg",
    "swig/allins.i",
    "swig/area.i",
    "swig/auto.i",
    "swig/bytes.i",
    "swig/dbg.i",
    "swig/diskio.i",
    "swig/entry.i",
    "swig/enum.i",
    "swig/expr.i",
    "swig/fixup.i",
    "swig/frame.i",
    "swig/funcs.i",
    "swig/gdl.i",
    "swig/ida.i",
    "swig/idaapi.i",
    "swig/idd.i",
    "swig/idp.i",
    "swig/ints.i",
    "swig/kernwin.i",
    "swig/lines.i",
    "swig/loader.i",
    "swig/moves.i",
    "swig/nalt.i",
    "swig/name.i",
    "swig/netnode.i",
    "swig/offset.i",
    "swig/pro.i",
    "swig/queue.i",
    "swig/search.i",
    "swig/segment.i",
    "swig/srarea.i",
    "swig/strlist.i",
    "swig/struct.i",
    "swig/typeconv.i",
    "swig/typeinf.i",
    "swig/ua.i",
    "swig/xref.i",
    "swig/graph.i",
    "swig/fpro.i",
    "tools/gendocs.py",
]

class BuilderBase:
    """ Base class for builders """
    def __init__(self):
        pass

    def compile(self, source, objectname=None, includes=[], macros=[]):
        """
        Compile the source file
        """
        allmacros = []
        allmacros.extend(COMMON_MACROS)
        allmacros.extend(self.basemacros)
        allmacros.extend(macros)
        macrostring = self._build_command_string(allmacros, self.macro_delimiter)

        allincludes = []
        allincludes.extend(COMMON_INCLUDES)
        allincludes.extend(includes)
        includestring = self._build_command_string(allincludes, self.include_delimiter)

        if not objectname:
            objectname = source + self.object_extension

        cmdstring = "%s %s %s %s %s %s" % (self.compiler,
                                           self.compiler_parameters,
                                           self.compiler_out_string(objectname),
                                           self.compiler_in_string(source + self.source_extension),
                                           includestring,
                                           macrostring)

        if VERBOSE:
            print cmdstring
        return os.system(cmdstring)

    def link(self, objects, outfile, libpaths=[], libraries=[], extra_parameters=None):
        """ Link the binary from objects and libraries """
        cmdstring = "%s %s %s" % (self.linker,
                                  self.linker_parameters,
                                  self.linker_out_string(outfile))

        for objectfile in objects:
            cmdstring = "%s %s" % (cmdstring, objectfile + self.object_extension)
        for libpath in libpaths:
            cmdstring = "%s %s%s" % (cmdstring, self.libpath_delimiter, libpath)
        for library in libraries:
            cmdstring = "%s %s" % (cmdstring, library)
        if extra_parameters:
            cmdstring = "%s %s" % (cmdstring, extra_parameters)

        if VERBOSE: print cmdstring
        return os.system(cmdstring)

    def _build_command_string(self, macros, argument_delimiter):
        macrostring = ""

        for item in macros:
            if type(item) == types.TupleType:
                macrostring += '%s%s="%s" ' % (argument_delimiter, item[0], item[1])
            else:
                macrostring += '%s%s ' % (argument_delimiter, item)

        return macrostring


class GCCBuilder(BuilderBase):
    """ Generic GCC compiler class """
    def __init__(self):
        self.include_delimiter = "-I"
        self.macro_delimiter = "-D"
        self.libpath_delimiter = "-L"
        self.compiler_parameters = "-fpermissive -Wno-write-strings"
        self.linker_parameters = "-shared"
        self.basemacros = [ ]
        self.compiler = "g++ -m32"
        self.linker = "g++ -m32"
        self.source_extension = ".cpp"
        self.object_extension = ".o"

    def compiler_in_string(self, filename):
        return "-c %s" % filename

    def compiler_out_string(self, filename):
        return "-o %s" % filename

    def linker_out_string(self, filename):
        return "-o %s" % filename


class MSVCBuilder(BuilderBase):
    """ Generic Visual C compiler class """
    def __init__(self):
        self.include_delimiter = "/I"
        self.macro_delimiter = "/D"
        self.libpath_delimiter = "/LIBPATH:"
        self.compiler_parameters = "/nologo /EHsc"
        self.linker_parameters = "/nologo /dll /export:PLUGIN"
        self.basemacros = [ "WIN32",
                            "_USRDLL",
                            "__NT__" ]
        self.compiler = "cl"
        self.linker = "link"
        self.source_extension = ".cpp"
        self.object_extension = ".obj"

    def compiler_in_string(self, filename):
        return "/c %s" % filename

    def compiler_out_string(self, filename):
        return "/Fo%s" % filename

    def linker_out_string(self, filename):
        return "/out:%s" % filename


def build_distribution(manifest, distrootdir, ea64, nukeold):
    """ Create a distibution to a directory and a ZIP file """
    # (Re)create the output directory
    if os.path.exists(distrootdir):
        if nukeold:
            shutil.rmtree(distrootdir)
            os.makedirs(distrootdir)
    else:
            os.makedirs(distrootdir)

    # Also make a ZIP archive of the build
    zippath = distrootdir + ".zip"
    zip = zipfile.ZipFile(zippath, nukeold and "w" or "a", zipfile.ZIP_DEFLATED)

    # Copy files, one by one
    for f in manifest:
        if type(f) == types.TupleType:
            srcfilepath = f[0]
            srcfilename = os.path.basename(srcfilepath)
            dstdir = os.path.join(distrootdir, f[1])
            dstfilepath = os.path.join(dstdir, srcfilename)
        else:
            srcfilepath = f
            srcfilename = os.path.basename(f)
            srcdir  = os.path.dirname(f)
            if srcdir == "":
                dstdir = distrootdir
            else:
                dstdir = os.path.join(distrootdir, srcdir)

        if not os.path.exists(dstdir):
            os.makedirs(dstdir)

        dstfilepath = os.path.join(dstdir, srcfilename)
        shutil.copyfile(srcfilepath, dstfilepath)
        zip.write(dstfilepath)

    zip.close()


def build_plugin(platform, idasdkdir, plugin_name, ea64):
    global SWIG_OPTIONS
    """ Build the plugin from the SWIG wrapper and plugin main source """
    # Path to the IDA SDK headers
    ida_include_directory = os.path.join(idasdkdir, "include")

    builder = None
    # Platform-specific settings for the Linux build
    if platform == "linux":
        builder = GCCBuilder()
        platform_macros = [ "__LINUX__" ]
        python_libpath = os.path.join(sysconfig.EXEC_PREFIX, "lib")
        python_library = "-Bdynamic -lpython%d.%d" % (PYTHON_MAJOR_VERSION, PYTHON_MINOR_VERSION)
        ida_libpath = os.path.join(idasdkdir, "lib", ea64 and "x86_linux_gcc_64" or "x86_linux_gcc_32")
        ida_lib = ""
        extra_link_parameters = " -s"
        builder.compiler_parameters += " -O2"
    # Platform-specific settings for the Windows build
    elif platform == "win32":
        builder = MSVCBuilder()
        platform_macros = [ "__NT__" ]
        python_libpath = os.path.join(sysconfig.EXEC_PREFIX, "libs")
        python_library = "python%d%d.lib" % (PYTHON_MAJOR_VERSION, PYTHON_MINOR_VERSION)
        ida_libpath = os.path.join(idasdkdir, "lib", ea64 and "x86_win_vc_64" or "x86_win_vc_32")
        ida_lib = "ida.lib"
        SWIG_OPTIONS += " -D__NT__ "
        extra_link_parameters = ""
        builder.compiler_parameters += " -Ox"
    # Platform-specific settings for the Mac OS X build
    elif platform == "macosx":
        builder = GCCBuilder()
        builder.linker_parameters = "-dynamiclib"
        platform_macros = [ "__MAC__" ]
        python_libpath = "."
        python_library = "-framework Python"
        ida_libpath = os.path.join(idasdkdir, "lib", ea64 and "x86_mac_gcc_64" or "x86_mac_gcc_32")
        ida_lib = ea64 and "-lida64" or "-lida"
        extra_link_parameters = " -s"
        builder.compiler_parameters += " -O3"

    assert builder, "Unknown platform! No idea how to build here..."

    # Enable EA64 for the compiler if necessary
    if ea64:
        platform_macros.append("__EA64__")

    platform_macros.append("NDEBUG")

    if not '--no-early-load' in sys.argv:
        platform_macros.append("PLUGINFIX")

    # Build the wrapper from the interface files
    ea64flag = ea64 and "-D__EA64__" or ""
    swigcmd = "swig %s -Iswig -o idaapi.cpp %s -I%s idaapi.i" % (SWIG_OPTIONS, ea64flag, ida_include_directory)
    if VERBOSE: print swigcmd
    res =  os.system(swigcmd)
    assert res == 0, "Failed to build the wrapper with SWIG"

    # Compile the wrapper
    res = builder.compile("idaapi",
                          includes=[ PYTHON_INCLUDE_DIRECTORY, ida_include_directory ],
                          macros=platform_macros)
    assert res == 0, "Failed to build the wrapper module"

    # Compile the main plugin source
    res =  builder.compile("python",
                           includes=[ PYTHON_INCLUDE_DIRECTORY, ida_include_directory ],
                           macros=platform_macros)
    assert res == 0, "Failed to build the main plugin object"

    # Link the final binary
    res =  builder.link( ["idaapi", "python"],
                         plugin_name,
                         [ python_libpath, ida_libpath ],
                         [ python_library, ida_lib ],
                         extra_link_parameters)
    assert res == 0, "Failed to link the plugin binary"

def detect_platform(ea64):
    # Detect the platform
    system = platform.system()

    if system == "Windows" or system == "Microsoft":
        system = "Windows"
        platform_string = "win32"
        plugin_name = ea64 and "python.p64" or "python.plw"

    elif system == "Linux":
        platform_string = "linux"
        plugin_name = ea64 and "python.plx64" or "python.plx"

    elif system == "Darwin":
        platform_string = "macosx"
        plugin_name = ea64 and "python.pmc64" or "python.pmc"
    else:
        print "Unknown platform!"
        sys.exit(-1)

    return (system, platform_string, plugin_name)

def build_binary_package(ea64, nukeold):
    system, platform_string, plugin_name = detect_platform(ea64)
    BINDISTDIR = "idapython-%d.%d.%d_ida%d.%d_py%d.%d_%s" % (VERSION_MAJOR,
                                                             VERSION_MINOR,
                                                             VERSION_PATCH,
                                                             IDA_MAJOR_VERSION,
                                                             IDA_MINOR_VERSION,
                                                             PYTHON_MAJOR_VERSION,
                                                             PYTHON_MINOR_VERSION,
                                                             platform_string)
    # Build the plugin
    build_plugin(platform_string, IDA_SDK, plugin_name, ea64)
    # Build the binary distribution
    binmanifest = []
    if nukeold:
        binmanifest.extend(BINDIST_MANIFEST)
    if not ea64 or nukeold:
      binmanifest.extend([(x, "python") for x in "python/init.py", "python/idc.py", "python/idautils.py", "idaapi.py"])
    binmanifest.append((plugin_name, "plugins"))
    build_distribution(binmanifest, BINDISTDIR, ea64, nukeold)


def build_source_package():
    """ Build a directory and a ZIP file with all the sources """
    SRCDISTDIR = "idapython-%d.%d.%d" % (VERSION_MAJOR,
                                         VERSION_MINOR,
                                         VERSION_PATCH)
    # Build the source distribution
    srcmanifest = []
    srcmanifest.extend(BINDIST_MANIFEST)
    srcmanifest.extend(SRCDIST_MANIFEST)
    srcmanifest.extend([(x, "python") for x in "python/init.py", "python/idc.py", "python/idautils.py"])
    build_distribution(srcmanifest, SRCDISTDIR, ea64=False, nukeold=True)

def gen_docs(z = False):
        print "Generating documentation....."
        old_dir = os.getcwd()
        try:
            curdir = os.getcwd() + os.sep
            docdir = 'idapython-reference-%d.%d.%d' % (VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)
            sys.path.append(curdir + 'python')
            sys.path.append(curdir + 'tools')
            sys.path.append(curdir + 'docs')
            import epydoc.cli
            import swigdocs
            os.chdir('docs')
            PYWRAPS_FN = 'pywraps'
            swigdocs.gen_docs(outfn = PYWRAPS_FN + '.py')
            epydoc.cli.optparse.sys.argv = [ 'epydoc',
                                             '--no-sourcecode',
                                             '-u', 'http://code.google.com/p/idapython/',
                                             '--navlink', '<a href="http://www.hex-rays.com/idapro/idapython_docs/">IDAPython Reference</a>',
                                             '--no-private',
                                             '--simple-term',
                                             '-o', docdir,
                                             '--html',
                                             'idc', 'idautils', PYWRAPS_FN, 'idaapi']
            # Generate the documentation
            epydoc.cli.cli()

            print "Documentation generated!"

            # Clean temp files
            for f in [PYWRAPS_FN + '.py', PYWRAPS_FN + '.pyc']:
                if os.path.exists(f):
                  os.unlink(f)

            if z:
                z = docdir + '-doc.zip'
                zip = zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED)
                for fn in glob.glob(docdir + os.sep + '*'):
                    zip.write(fn)
                zip.close()
                print "Documentation compressed to", z
        except Exception, e:
            print 'Failed to generate documentation:', e
        finally:
            os.chdir(old_dir)
        return

def usage():
    print """IDAPython build script.

Available switches:
  --doc:
    Generate documentation into the 'docs' directory
  --zip:
    Used with '--doc' switch. It will compress the generated documentation
  --ea64:
    Builds also the 64bit version of the plugin
  --no-early-load:
    The plugin will be compiled as normal plugin
    This switch disables processor, plugin and loader scripts
"""

def main():
    if '--help' in sys.argv:
        return usage()
    elif '--doc' in sys.argv:
        return gen_docs(z = '--zip' in sys.argv)

    # Do 64-bit build?
    ea64 = '--ea64' in sys.argv
    build_binary_package(ea64=False, nukeold=True)
    if ea64:
        build_binary_package(ea64=True, nukeold=False)
    build_source_package()

if __name__ == "__main__":
    main()