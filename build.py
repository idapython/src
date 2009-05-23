#!/usr/bin/env python
#------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler Pro
#
# Copyright (c) 2004-2009 Gergely Erdelyi <dyce@d-dome.net> 
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
VERSION_PATCH  = 92

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
        # Move the python files to python64 when building a 64-bit plugin
#        if ea64:
#            dstdir = dstdir.replace(os.sep+'python', os.sep+'python64')
        if not os.path.exists(dstdir):
            os.makedirs(dstdir)
            
        dstfilepath = dstdir + os.sep + srcfilename
        shutil.copyfile(srcfilepath, dstfilepath)
        zip.write(dstfilepath)

    zip.close()


def build_plugin(platform, idasdkdir, plugin_name, ea64):
    """ Build the plugin from the SWIG wrapper and plugin main source """
    # Path to the IDA SDK headers
    ida_include_directory = idasdkdir + os.sep + "include"

    builder = None
    # Platform-specific settings for the Linux build
    if platform == "linux":
        builder = GCCBuilder()
        platform_macros = [ "__LINUX__" ]
        python_libpath = sysconfig.EXEC_PREFIX + os.sep + "lib"
        python_library = "-lpython%d.%d" % (PYTHON_MAJOR_VERSION, PYTHON_MINOR_VERSION)
        ida_libpath = os.path.join(idasdkdir, ea64 and "libgcc64.lnx" or "libgcc32.lnx")
        ida_lib = ""
        extra_link_parameters = ""
    # Platform-specific settings for the Windows build
    if platform == "win32":
        builder = MSVCBuilder()
        platform_macros = [ "__NT__" ]
        python_libpath = sysconfig.EXEC_PREFIX + os.sep + "libs"
        python_library = "python%d%d.lib" % (PYTHON_MAJOR_VERSION, PYTHON_MINOR_VERSION)
        ida_libpath = os.path.join(idasdkdir, ea64 and "libvc.w64" or "libvc.w32")
        ida_lib = "ida.lib"
        extra_link_parameters = ""
    # Platform-specific settings for the Mac OS X build
    if platform == "macosx":
        builder = GCCBuilder()
        builder.linker_parameters = "-dynamiclib"
        platform_macros = [ "__MAC__" ]
        python_libpath = "."
        python_library = "-framework Python"
        ida_libpath = os.path.join(idasdkdir, ea64 and "libgcc64.mac" or "libgcc32.mac")
        ida_lib = ea64 and "-lida64" or "-lida"
        extra_link_parameters = ""

    assert builder, "Unknown platform! No idea how to build here..."

    # Enable EA64 for the compiler if necessary
    if ea64:
        platform_macros.append("__EA64__")

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


def build_binary_package(ea64, nukeold):
    # Detect the platform
    system = platform.system()

    if system == "Windows" or system == "Microsoft":
        system = "Windows"
        platform_string = "win32"
        plugin_name = ea64 and "python.p64" or "python.plw"
    
    if system == "Linux":
        platform_string = "linux"
        plugin_name = ea64 and "python.plx64" or "python.plx"

    if system == "Darwin":
        platform_string = "macosx"
        plugin_name = ea64 and "python.pmc64" or "python.pmc"

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
    binmanifest.extend([(x, ea64 and "python64" or "python") for x in "python/init.py", "python/idc.py", "python/idautils.py", "idaapi.py"])
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


if __name__ == "__main__":
    # Do 64-bit build?
    ea64 = '--ea64' in sys.argv    
    build_binary_package(ea64=False, nukeold=True)
    build_binary_package(ea64=True, nukeold=False)
    build_source_package()
