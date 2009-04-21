#!/usr/bin/env python
#------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler Pro
#
# Copyright (c) 2004-2008 Gergely Erdelyi <dyce@d-dome.net> 
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#------------------------------------------------------------
# build.py - Custom build script
#------------------------------------------------------------
import os
import platform
import shutil
import sys
import types
import zipfile
from distutils import sysconfig

# Start of user configurable options
VERBOSE = True
IDA_MAJOR_VERSION = 5
IDA_MINOR_VERSION = 4
IDA_SDK = ".." + os.sep + "swigsdk-versions" + os.sep + "%d.%d" % (IDA_MAJOR_VERSION, IDA_MINOR_VERSION)
#IDA_SDK = ".." + os.sep + ".."
# End of user configurable options

# IDAPython version
VERSION_MAJOR  = 1
VERSION_MINOR  = 1
VERSION_PATCH  = 90

# Determine Python version
PYTHON_MAJOR_VERSION = int(platform.python_version()[0])
PYTHON_MINOR_VERSION = int(platform.python_version()[2])

# Find Python headers
PYTHON_INCLUDE_DIRECTORY = sysconfig.get_config_var('INCLUDEPY')

# Swig command-line parameters
SWIG_OPTIONS = '-modern -python -c++ -w451 -shadow -D__GNUC__'

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
    "STATUS.txt",
    "python/init.py",
    "python/idc.py",
    "python/idautils.py",
    ("idaapi.py", "python"),
    "docs/notes.txt",
    "examples/chooser.py",
    "examples/colours.py",
    "examples/debughook.py",
    "examples/ex1.idc",
    "examples/ex1_idaapi.py",
    "examples/ex1_idautils.py",
    "examples/hotkey.py",
    "examples/structure.py",
]

# List files for the source distribution (appended to binary list)
SRCDIST_MANIFEST = [
    "BUILDING.txt",
    "python.cpp",
    "basetsd.h",
    "build.py",
    "swig/allins.i",
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
    "swig/ida.i",
    "swig/idaapi.i",
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
    "tools/gendocs.py",
]

# Temporaty build files to remove
BUILD_TEMPFILES = [
    "idaapi.cpp",
    "idaapi.obj",
    "idaapi.o",
    "idaapi.py",
    "idapython.sln",
    "idapython.ncb",
    "python.exp",
    "python.lib",
    "python.obj"
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

        if VERBOSE: print cmdstring
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
        self.compiler_parameters = "-fpermissive"
        self.linker_parameters = "-shared"
        self.basemacros = [ ]
        self.compiler = "g++"
        self.linker = "g++"
        self.source_extension = ".cpp"
        self.object_extension = ".o"

    def compiler_in_string(self, filename):
        return "-c %s" % filename

    def compiler_out_string(self, filename):
        return "-o %s" % filename

    def linker_out_string(self, filename):
        return "-o %s" % filename


class MSVCBuilder(BuilderBase):
    """ Generic GCC compiler class """
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


def build_distribution(manifest, distrootdir):
    """ Create dist tree and copy files to it """

    # Remove the previous distibution if exits
    if os.path.exists(distrootdir):
        shutil.rmtree(distrootdir)

    # Also make a ZIP archive of the build
    zippath = distrootdir + ".zip"
    zip = zipfile.ZipFile(zippath, "w", zipfile.ZIP_DEFLATED)
    
    # Create output directory
    os.makedirs(distrootdir)
    
    # Copy files, one by one
    for f in manifest:
        if type(f) == types.TupleType:
            srcfilepath = f[0]
            srcfilename = os.path.basename(srcfilepath)
            dstdir = distrootdir + os.sep + f[1]
            dstfilepath = dstdir + os.sep + srcfilename
        else:
            srcfilepath = f
            srcfilename = os.path.basename(f)
            srcdir  = os.path.dirname(f)
            
            if srcdir == "":
                dstdir = distrootdir
            else:
                dstdir = distrootdir + os.sep + srcdir 
              
        if not os.path.exists(dstdir):
            os.makedirs(dstdir)
            
        dstfilepath = dstdir + os.sep + srcfilename
        shutil.copyfile(srcfilepath, dstfilepath)
        zip.write(dstfilepath)

    zip.close()

def build_plugin(system, idasdkdir):
    """ Build the plugin from the SWIG wrapper and plugin main source """

    # Find IDA SDK headers
    ida_include_directory = idasdkdir + os.sep + "include"

    # Platform-specific settings for the Linux build
    if system == "Linux":
        builder = GCCBuilder()
        plugin_name = "python.plx"
        platform_macros = [ "__LINUX__" ]
        python_libpath = sysconfig.EXEC_PREFIX + os.sep + "lib"
        python_library = "-lpython%d.%d" % (PYTHON_MAJOR_VERSION, PYTHON_MINOR_VERSION)
        ida_libpath = idasdkdir + os.sep + "libgcc32.lnx"
        ida_lib = ""
        extra_link_parameters = "/usr/lib/python%s.%s/lib-dynload/*.so" % (PYTHON_MAJOR_VERSION, PYTHON_MINOR_VERSION)

    # Platform-specific settings for the Windows build
    if system == "Windows":
        builder = MSVCBuilder()
        plugin_name = "python.plw"
        platform_macros = [ "__NT__" ]
        python_libpath = sysconfig.EXEC_PREFIX + os.sep + "libs"
        python_library = "python%d%d.lib" % (PYTHON_MAJOR_VERSION, PYTHON_MINOR_VERSION)
        ida_libpath = idasdkdir + os.sep + "libvc.w32"
        ida_lib = "ida.lib"
        extra_link_parameters = None

    # Platform-specific settings for the Linux build
    if system == "Darwin":
        builder = GCCBuilder()
        builder.linker_parameters = "-dynamiclib"
        plugin_name = "python.pmc"
        platform_macros = [ "__MAC__" ]
        python_libpath = "."
        python_library = "-framework Python"
        ida_libpath = idasdkdir + os.sep + "libgcc32.mac"
        ida_lib = "-lida"
        extra_link_parameters = ""


    # Build the wrapper from the interface files
    swigcmd = "swig %s -Iswig -o idaapi.cpp -I%s idaapi.i" % (SWIG_OPTIONS, ida_include_directory)
    if VERBOSE: print swigcmd
    res =  os.system(swigcmd)

    if res != 0: return False

    # Compile the wrapper
    res = builder.compile("idaapi",
                          includes=[ PYTHON_INCLUDE_DIRECTORY, ida_include_directory ],
                          macros=platform_macros)

    if res != 0: return False

    # Compile the main plugin source
    res =  builder.compile("python",
                           includes=[ PYTHON_INCLUDE_DIRECTORY, ida_include_directory ],
                           macros=platform_macros)

    if res != 0: return False

    # Link the final binary
    res =  builder.link( ["idaapi", "python"],
                         plugin_name,
                         [ python_libpath, ida_libpath ],
                         [ python_library, ida_lib ],
                         extra_link_parameters)

    if res != 0: return False

    return True

    
def clean(manifest):
    """ Clean the temporary files """

    for i in manifest:
        try:
            os.unlink(i)
        except:
            pass


if __name__ == "__main__":
    # Detect the platform
    system = platform.system()

    if system == "Windows" or system == "Microsoft":
        platform_string = "win32"
        plugin_name = "python.plw"
    
    if system == "Linux":
        platform_string = "linux"
        plugin_name = "python.plx"

    if system == "Darwin":
        platform_string = "macosx"
        plugin_name = "python.pmc"
     
    BINDISTDIR = "idapython-%d.%d.%d_ida%d.%d_py%d.%d_%s" % (VERSION_MAJOR, 
                                                             VERSION_MINOR, 
                                                             VERSION_PATCH, 
                                                             IDA_MAJOR_VERSION, 
                                                             IDA_MINOR_VERSION,
                                                             PYTHON_MAJOR_VERSION,
                                                             PYTHON_MINOR_VERSION,
                                                             platform_string)
    SRCDISTDIR = "idapython-%d.%d.%d" % (VERSION_MAJOR, 
                                         VERSION_MINOR, 
                                         VERSION_PATCH) 
    
    # Build the plugin
    res = build_plugin(system, IDA_SDK)
    if not res: sys.exit(1)
    
    # Build the binary distribution
    binmanifest = []
    binmanifest.extend(BINDIST_MANIFEST)
    binmanifest.append((plugin_name, "plugins"))
    build_distribution(binmanifest, BINDISTDIR)

    # Build the binary distribution
    srcmanifest = []
    srcmanifest.extend(BINDIST_MANIFEST)
    srcmanifest.extend(SRCDIST_MANIFEST)
    build_distribution(srcmanifest, SRCDISTDIR)

    # Clean the temp files
    cleanlist = []
    cleanlist.extend(BUILD_TEMPFILES)
    cleanlist.append(plugin_name)
#    clean(cleanlist)
