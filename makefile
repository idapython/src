
#
# WARNING: Many rules in this file use pattern matching, where 'make'
# first considers rules as simple strings, not paths. Consequently,
# it is necessary that we don't end up with 'some_dir//some_file'.
# Thus, we have to settle for a makefile-wide policy of either:
# - terminating dir paths with '/', in which case we have to write:
#   $(SOMEDIR)somefile, or
# - not terminating dir paths with '/', in which case it becomes:
#   $(SOMEDIR)/somefile
# In other makefiles sitting in IDA's source tree, we use the first approach,
# but this one demands the second: not only is this more natural for
# non-hexrays people looking at the file, it also allows us to work in
# a more natural manner with other tools (such as the build.py wrapper, that
# uses os.path.join())
#

PROC=python
API_CONTENTS=api_contents.txt
PYDOC_INJECTIONS=pydoc_injections.txt

BC695=1
ifdef BC695
  BC695_CFLAGS=-DBC695
  BC695_SWIGFLAGS=-DBC695
  BC695_DEPLOYFLAGS=--bc695
endif

IDA_INCLUDE=../../include

DIST=$(F)dist

ifdef __NT__
  SYSNAME=win
  MSRUNTIME=/MD
  MSCLOPTS=/nologo
  MSLDOPTS=/nologo
endif

ifdef __LINUX__
  SYSNAME=linux
  DEFS=-D__LINUX__
  PYTHON32_LIBRARY_PATH?=/usr/lib
  PYTHON32_LIBRARY_INCLUDE=-L$(PYTHON32_LIBRARY_PATH)
endif

ifdef __MAC__
  SYSNAME=mac
  DEFS=-D__MAC__
endif

DONT_ERASE_LIB=1

include ../plugin.mak
include ../pyplg.mak

# allmake.unx defines 'CP' as 'qcp.sh' which is an internal tool providing
# support for the '-u' flag on OSX. However, since this makefile is part
# of the public release of IDAPython, we cannot rely on it (we do not use
# that flag in IDAPython anyway)
ifdef __MAC__
  CP=cp -f
endif

PLUGIN_SCRIPT=
ifdef __LINUX__
  OUTDLLOPTS=-Wl,-soname,$(notdir $(BINARY))
else
  ifdef __MAC__
    OUTDLLOPTS=-Wl,-install_name,@executable_path/plugins/$(notdir $(BINARY))
  endif
endif

IDA_CMD=TVHEADLESS=1 $(R)idat$(X64SUFF)$(SUFF64)
ST_SWIG=$(F)swig
ifeq ($(OUT_OF_TREE_BUILD),)
  ST_SDK=$(F)idasdk
else
  ST_SDK=$(IDA_INCLUDE)
endif
ST_PYW=$(F)pywraps
ST_WRAP=$(F)wrappers
ST_PARSED_HEADERS_NOXML=$(F)parsed_notifications
ST_PARSED_HEADERS=$(ST_PARSED_HEADERS_NOXML)/xml
ifeq ($(OUT_OF_TREE_BUILD),)
  ST_PARSED_HEADERS_CONFIG=$(ST_PARSED_HEADERS_NOXML)/doxy_gen_notifs.cfg
endif
ST_API_CONTENTS=$(F)api_contents.txt.new
ST_PYDOC_INJECTIONS=$(F)pydoc_injections.txt

# output directory for python scripts
DEPLOY_PYDIR=$(R)python
DEPLOY_INIT_PY=$(DEPLOY_PYDIR)/init.py
DEPLOY_IDC_PY=$(DEPLOY_PYDIR)/idc.py
DEPLOY_IDAUTILS_PY=$(DEPLOY_PYDIR)/idautils.py
DEPLOY_IDC_BC695_PY=$(DEPLOY_PYDIR)/idc_bc695.py
DEPLOY_IDAAPI_PY=$(DEPLOY_PYDIR)/idaapi.py
DEPLOY_IDADEX_PY=$(DEPLOY_PYDIR)/idadex.py
ifeq ($(OUT_OF_TREE_BUILD),)
  TEST_IDC=test_idc
  DBLZIP_SCRIPT:=$(abspath ../../ida/build/dblzip.py)
  PKGBIN_SCRIPT:=$(abspath ../../ida/build/pkgbin.py)
  IDC_BC695_IDC_SOURCE?=$(DEPLOY_PYDIR)/../idc/idc.idc
endif

#
SDK_SOURCES=$(wildcard $(IDA_INCLUDE)/*.h) $(wildcard $(IDA_INCLUDE)/*.hpp)
ifeq ($(OUT_OF_TREE_BUILD),)
  ST_SDK_TARGETS=$(SDK_SOURCES:$(IDA_INCLUDE)/%=$(ST_SDK)/%)
else
  ST_SDK_TARGETS=$(SDK_SOURCES)
endif

PYTHON_DYNLOAD=$(BIN_PATH)../python/lib/python2.7/lib-dynload
DEPLOY_LIBDIR=$(PYTHON_DYNLOAD)/ida_$(ADRSIZE)

$(DEPLOY_LIBDIR):
	-@if [ ! -d "$(DEPLOY_LIBDIR)" ] ; then mkdir -p 2>/dev/null $(DEPLOY_LIBDIR) ; fi

$(DEPLOY_PYDIR):
	-@if [ ! -d "$(DEPLOY_PYDIR)" ] ; then mkdir -p 2>/dev/null $(DEPLOY_PYDIR) ; fi

ifdef __NT__
  MODULE_SFX=.pyd
else
  MODULE_SFX=.so
endif

ifneq ($(OUT_OF_TREE_BUILD),)
  # envvar HAS_HEXRAYS must have been set by build.py if needed
else
  HAS_HEXRAYS=1 # force hexrays bindings
endif
ifneq ($(HAS_HEXRAYS),)
  WITH_HEXRAYS=-DWITH_HEXRAYS
  WITH_HEXRAYS_CHKAPI=--with-hexrays
  HEXRAYS_MODNAME=hexrays
endif

# We are building 'MODULES_NAMES' from subvars because it appears some versions
# of make do not deal too well with '\'s, and introduce spaces, which later is
# problematic when substituting ' ' for ',' & passing modules list to scripts
MNAMES_0=allins range auto bytes dbg diskio entry enum expr fixup
MNAMES_1=fpro frame funcs gdl graph $(HEXRAYS_MODNAME) ida idaapi idd idp
MNAMES_2=kernwin lines loader moves nalt name netnode offset pro problems
MNAMES_3=registry search segment segregs strlist struct typeinf tryblks ua xref
MNAMES_EXTRA=idc
MODULES_NAMES=$(MNAMES_0) $(MNAMES_1) $(MNAMES_2) $(MNAMES_3) $(MNAMES_EXTRA)

MODULES=$(MODULES_NAMES:%=$(F)_ida_%$(MODULE_SFX))
DEPLOYED_MODULES=$(MODULES_NAMES:%=$(DEPLOY_LIBDIR)/_ida_%$(MODULE_SFX))
MODULES_OBJECTS=$(MODULES_NAMES:%=$(F)%$(O))

ALL_ST_SWIG=$(foreach mod,$(MODULES_NAMES),$(ST_SWIG)/$(mod).i)
ALL_ST_WRAP_CPP=$(foreach mod,$(MODULES_NAMES),$(ST_WRAP)/$(mod).cpp)
ALL_ST_WRAP_PY=$(foreach mod,$(MODULES_NAMES),$(ST_WRAP)/ida_$(mod).py)

PYTHON_MODULES=$(MODULES_NAMES:%=$(DEPLOY_PYDIR)/ida_%.py)
PYTHON_BINARY_MODULES=$(MODULES_NAMES:%=$(DEPLOY_LIBDIR)/_ida_%$(MODULE_SFX))

ifdef __NT__
  MODULE_LINKIDA=
  CREATE_IMPLIB=$(RS)lib32.bat
  IDAPYTHON_IMPLIB_DEF=$(F)idapython_implib.def
  IDAPYTHON_IMPLIB_DEF_IN=tools/idapython_implib.def.in
  IDAPYTHON_IMPLIB_PATH=$(F)python.lib
  BINARY_LINKOPTS=/def:$(IDAPYTHON_IMPLIB_DEF) /IMPLIB:$(IDAPYTHON_IMPLIB_PATH)
  RESFILES=$(IDAPYTHON_IMPLIB_DEF)
else
  ifeq ($(OUT_OF_TREE_BUILD),)
    LIBIDA_DIR:=$(R)
  else
    LIBIDA_DIR:=$(L)
  endif
  MODULE_LINKIDA=-L$(LIBIDA_DIR) $(LINKIDA) $(BINARY)
endif

all: objdir pyfiles config $(DEPLOYED_MODULES) $(PYTHON_MODULES) $(ST_API_CONTENTS) $(IDAPYTHON_IMPLIB) $(ST_PYDOC_INJECTIONS) #$(TEST_IDC)

# IDAPython version
IDAPYTHON_VERSION_MAJOR=6
IDAPYTHON_VERSION_MINOR=9
IDAPYTHON_VERSION_PATCH=5
PACKAGE_NAME=idapython-$(IDAPYTHON_VERSION_MAJOR).$(IDAPYTHON_VERSION_MINOR).$(IDAPYTHON_VERSION_PATCH)-python$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR)-$(SYSNAME)


# HIJACK the $(I) variable to point to our staging SDK
I=$(ST_SDK)/

ifdef __CODE_CHECKER__
  ADDITIONAL_GOALS:=$(filter-out pyfiles config $(TEST_IDC),$(ADDITIONAL_GOALS))
  OBJS:=$(filter-out $(OBJ1),$(OBJS))
endif

ifdef __NT__                   # os and compiler specific flags
  ifneq ($(UCRT_INCLUDE),)
    I_UCRT_INCLUDE=/I$(UCRT_INCLUDE)
  endif
  IDAPYTHON_CFLAGS=$(PYTHON_CFLAGS) -w -Z7 /bigobj /I$(MSVCDIR)Include $(I_UCRT_INCLUDE)
  _SWIGFLAGS=-D__NT__ -DWIN32 -D_USRDLL -I$(PYTHON_DIR)/include
  SWIGINCLUDES?=   # nothing
  # FIXME: Cannot enable the .cfg file ATM, because there's just too many errors if I do.
  PLATFORM_CFLAGS=$(_SWIGFLAGS) -UNO_OBSOLETE_FUNCS
else # unix/mac
  ifdef __LINUX__
    PYTHON_LDFLAGS_RPATH_MAIN=-Wl,-rpath='$$ORIGIN/..'
    PYTHON_LDFLAGS_RPATH_MODULE=-Wl,-rpath='$$$$ORIGIN/../../..'
  else
    MACDEFINES=-DMACSDKVER=$(MACSDKVER)
  endif
  IDAPYTHON_CFLAGS=-w -g
  PLATFORM_CFLAGS=$(SYS) -g $(PYTHON_CFLAGS) $(ARCH_CFLAGS) $(PIC) -UNO_OBSOLETE_FUNCS # gcc flags
  _SWIGFLAGS=$(DEFS)
  SWIGINCLUDES?=-I$(SWIGDIR)share/swig/$(SWIG_VERSION)/python -I$(SWIGDIR)share/swig/$(SWIG_VERSION)
endif
# Apparently that's not needed, but I don't understand why ATM, since doc says:
#  ...Then, only modules compiled with SWIG_TYPE_TABLE set to myprojectname
#  will share type information. So if your project has three modules, all three
#  should be compiled with -DSWIG_TYPE_TABLE=myprojectname, and then these
#  three modules will share type information. But any other project's
#  types will not interfere or clash with the types in your module.
DEF_TYPE_TABLE=-DSWIG_TYPE_TABLE=idaapi
SWIGFLAGS=$(_SWIGFLAGS) -Itools/typemaps-supplement $(SWIGINCLUDES) $(DEF_TYPE_TABLE) -D__IDP__ -D__PLUGIN__ $(BC695_SWIGFLAGS)

ADDITIONAL_LIBS=$(PYTHON_LDFLAGS) $(PYTHON_LDFLAGS_RPATH_MAIN)
ifdef __LINUX__
  ADDITIONAL_LIBS_MODULE=$(PYTHON_LDFLAGS) $(PYTHON_LDFLAGS_RPATH_MODULE)
else
  ADDITIONAL_LIBS_MODULE=$(ADDITIONAL_LIBS)
endif

PUBTREE_DIR=$(F)/public_tree

.PHONY: pyfiles docs $(TEST_IDC) staging_dirs clean check_python package public_tree
config: $(C)python.cfg

clean::
	rm -rf obj/

pyfiles: $(DEPLOY_IDAUTILS_PY)  \
	 $(DEPLOY_IDC_PY)       \
	 $(DEPLOY_IDC_BC695_PY) \
	 $(DEPLOY_INIT_PY)      \
	 $(DEPLOY_IDAAPI_PY)    \
	 $(DEPLOY_IDADEX_PY)

GENHOOKS=tools/genhooks/
_SPACE := $(null) #
_COMMA := ,

$(DEPLOY_INIT_PY): python/init.py | $(DEPLOY_PYDIR)
	$(CP) $? $@

$(DEPLOY_IDC_PY): python/idc.py | $(DEPLOY_PYDIR)
	$(CP) $? $@

$(DEPLOY_IDAUTILS_PY): python/idautils.py | $(DEPLOY_PYDIR)
	$(CP) $? $@

$(DEPLOY_IDC_BC695_PY): $(IDC_BC695_IDC_SOURCE) python/idc.py tools/gen_idc_bc695.py | $(DEPLOY_PYDIR)
	$(PYTHON) tools/gen_idc_bc695.py --idc $(IDC_BC695_IDC_SOURCE) --output $@

$(DEPLOY_PYDIR)/idaapi.py: python/idaapi.py tools/genidaapi.py $(PYTHON_MODULES) | $(DEPLOY_PYDIR)
	$(PYTHON) tools/genidaapi.py -i $< -o $@ -m $(subst $(_SPACE),$(_COMMA),$(MODULES_NAMES))

$(DEPLOY_PYDIR)/idadex.py: python/idadex.py | $(DEPLOY_PYDIR)
	$(CP) $? $@

$(DEPLOY_PYDIR)/lib/%: precompiled/lib/%
	mkdir -p $(@D)
	cp $< $@
	@chmod +w $@

$(C)python.cfg: python.cfg
	$(CP) $? $@

$(R)$(LIBPYTHON_NAME): $(PRECOMPILED_DIR)/$(LIBPYTHON_NAME)
	$(CP) $? $@

# -------------------------------------------------------------------------
# Hooks generation
# http://stackoverflow.com/questions/11032280/specify-doxygen-parameters-through-command-line
$(ST_PARSED_HEADERS_CONFIG): $(GENHOOKS)doxy_gen_notifs.cfg.in $(ST_SDK_TARGETS) $(GENHOOKS)gendoxycfg.py | staging_dirs
	@$(PYTHON) $(GENHOOKS)gendoxycfg.py -i $< -o $@ --includes $(subst $(_SPACE),$(_COMMA),$(ST_SDK_TARGETS))

PARSED_HEADERS_MARKER=$(ST_PARSED_HEADERS)/headers_generated.marker
$(PARSED_HEADERS_MARKER): $(ST_SDK_TARGETS) $(ST_PARSED_HEADERS_CONFIG) $(ST_SDK_TARGETS)
ifeq ($(OUT_OF_TREE_BUILD),)
	@( cat $(ST_PARSED_HEADERS_CONFIG); echo "OUTPUT_DIRECTORY=$(ST_PARSED_HEADERS_NOXML)" ) | $(DOXYGEN_BIN) -
else
	(cd $(F) && unzip ../../out_of_tree/parsed_notifications.zip)
endif
	@touch $@

#
staging_dirs:
	-@if [ ! -d "$(ST_SDK)" ] ; then mkdir -p 2>/dev/null $(ST_SDK) ; fi
	-@if [ ! -d "$(ST_SWIG)" ] ; then mkdir -p 2>/dev/null $(ST_SWIG) ; fi
	-@if [ ! -d "$(ST_PYW)" ] ; then mkdir -p 2>/dev/null $(ST_PYW) ; fi
	-@if [ ! -d "$(ST_WRAP)" ] ; then mkdir -p 2>/dev/null $(ST_WRAP) ; fi
	-@if [ ! -d "$(ST_PARSED_HEADERS)" ] ; then mkdir -p 2>/dev/null $(ST_PARSED_HEADERS) ; fi

# -------------------------------------------------------------------------
# obj/.../idasdk/*.h[pp]
#
ifeq ($(OUT_OF_TREE_BUILD),)
$(ST_SDK)/%.h: $(IDA_INCLUDE)/%.h | staging_dirs $(PRECOMPILED_COPY)
	$(PYTHON) ../../bin/update_sdk.py $(FILTER_SDK_FLAGS) -filter-file -input $^ -output $@
$(ST_SDK)/%.hpp: $(IDA_INCLUDE)/%.hpp | staging_dirs $(PRECOMPILED_COPY)
	$(PYTHON) ../../bin/update_sdk.py $(FILTER_SDK_FLAGS) -filter-file -input $^ -output $@
endif

# -------------------------------------------------------------------------
# obj/.../pywraps/*
#
$(ST_PYW)/%.hpp: pywraps/%.hpp | staging_dirs
	@$(CP) $^ $@ && chmod +rw $@
$(ST_PYW)/%.py: pywraps/%.py | staging_dirs
	@$(CP) $^ $@ && chmod +rw $@


# These require special care, as they will have to be injected w/ hooks -- this
# only happens if we are sitting in the hexrays source tree; when published to
# the outside world, the pywraps must already contain the injected code.
$(ST_PYW)/py_idp.hpp: pywraps/py_idp.hpp \
	$(I)idp.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_idphooks.py \
	$(PARSED_HEADERS_MARKER) | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/structprocessor__t.xml -e event_t \
		-r int -n 0 -m hookgenIDP -q "processor_t::" \
		-R $(GENHOOKS)recipe_idphooks.py
$(ST_PYW)/py_idp_idbhooks.hpp: pywraps/py_idp_idbhooks.hpp \
	$(I)idp.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_idbhooks.py \
	$(PARSED_HEADERS_MARKER) | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/namespaceidb__event.xml -e event_code_t \
		-r int -n 0 -m hookgenIDB -q "idb_event::" \
		-R $(GENHOOKS)recipe_idbhooks.py
$(ST_PYW)/py_dbg.hpp: pywraps/py_dbg.hpp \
	$(I)dbg.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_dbghooks.py \
	$(PARSED_HEADERS_MARKER) | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/dbg_8hpp.xml -e dbg_notification_t \
		-r void -n 0 -m hookgenDBG \
		-R $(GENHOOKS)recipe_dbghooks.py
$(ST_PYW)/py_kernwin.hpp: pywraps/py_kernwin.hpp \
	$(I)kernwin.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_uihooks.py \
	$(PARSED_HEADERS_MARKER) | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/kernwin_8hpp.xml -e ui_notification_t \
		-r void -n 0 -m hookgenUI \
		-R $(GENHOOKS)recipe_uihooks.py \
		-d "ui_dbg_,ui_obsolete" -D "ui:" -s "ui_"
$(ST_PYW)/py_kernwin_viewhooks.hpp: pywraps/py_kernwin_viewhooks.hpp \
	$(I)kernwin.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_viewhooks.py \
	$(PARSED_HEADERS_MARKER) | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/kernwin_8hpp.xml -e view_notification_t \
		-r void -n 0 -m hookgenVIEW \
		-R $(GENHOOKS)recipe_viewhooks.py


CFLAGS= $(CCOPT) $(PLATFORM_CFLAGS) $(MSRUNTIME) -D__EXPR_SRC -I. -I$(ST_SWIG) -I$(ST_SDK) -I$(F)   \
	-DVER_MAJOR="1" -DVER_MINOR="7" -DVER_PATCH="0" -D__IDP__ -D__PLUGIN__ \
	-DUSE_STANDARD_FILE_FUNCTIONS $(IDAPYTHON_CFLAGS)           \
	$(SWITCH64) $(SWITCHX64) $(ARCH_CFLAGS) $(WITH_HEXRAYS) $(DEF_TYPE_TABLE) $(BC695_CFLAGS)
ifdef TESTABLE_BUILD
  CFLAGS+=-DTESTABLE_BUILD
  SWIGFLAGS+=-DTESTABLE_BUILD
  FILTER_SDK_FLAGS+=-testable-build
endif

ST_SWIG_HEADER=$(ST_SWIG)/header.i
$(ST_SWIG)/header.i: tools/deploy/header.i.in tools/genswigheader.py $(ST_SDK_TARGETS) | staging_dirs
	$(PYTHON) tools/genswigheader.py -i $< -o $@ -m $(subst $(_SPACE),$(_COMMA),$(MODULES_NAMES)) -s $(ST_SDK)


ifdef __NT__
PATCH_DIRECTORS_SCRIPT:=tools/patch_directors_cc.py

$(IDAPYTHON_IMPLIB_DEF): $(IDAPYTHON_IMPLIB_DEF_IN)
	sed s/%LIBNAME%/$(notdir $(BINARY))/ < $? > $@
	sed -i s/%PLUGIN_DATA_EXP%// $@
endif

PATCH_CODEGEN_X64_OPTS=--apply-valist-patches

find-pywraps-deps = $(wildcard pywraps/py_$(subst .i,,$(notdir $1))*.*)
find-pydoc-patches-deps = $(wildcard tools/inject_pydoc/$1.py)

# Some .i files depend on some other .i files in order to be parseable by SWiG
# (e.g., segregs.i imports range.i). Declare the list of such dependencies here
# so they will be picked by the auto-generated rules.
SWIG_IFACE_bytes=range
SWIG_IFACE_dbg=idd
SWIG_IFACE_frame=range
SWIG_IFACE_funcs=range
SWIG_IFACE_gdl=range
SWIG_IFACE_hexrays=typeinf
SWIG_IFACE_segment=range
SWIG_IFACE_segregs=range
SWIG_IFACE_typeinf=idp
SWIG_IFACE_tryblks=range

MODULE_LIFECYCLE_hexrays=--lifecycle-aware
MODULE_LIFECYCLE_bytes=--lifecycle-aware

define make-module-rules

    # Note: apparently make cannot work well when a given recipe generates multiple files
    # http://stackoverflow.com/questions/19822435/multiple-targets-from-one-recipe-and-parallel-execution
    # Consequently, rules such as this:
    #
    #   $(ST_WRAP)/ida_$1.py: $(ST_WRAP)/$1.cpp
    #
    # i.e., that do nothing but rely on the generation of another file,
    # will not work in // execution. Thus, we will rely exclusively on
    # the presence of the generated .cpp file, and not other generated
    # files.

    # ../../bin/x86_linux_gcc/python/ida_$1.py (note: dep. on .cpp. See note above.)
    $(DEPLOY_PYDIR)/ida_$1.py: $(ST_WRAP)/$1.cpp $(PARSED_HEADERS_MARKER) $(call find-pydoc-patches-deps,$1) | $(DEPLOY_PYDIR) tools/inject_pydoc.py
	$(PYTHON) tools/inject_pydoc.py \
                -x $(ST_PARSED_HEADERS) \
		-m $1 \
		-i $(ST_WRAP)/ida_$1.py \
		-w $(ST_SWIG)/$1.i \
		-o $$@ \
		-e $(ST_WRAP)/ida_$1.epydoc_injection \
		-v > $(ST_WRAP)/ida_$1.pydoc_injection 2>&1

    # obj/x86_linux_gcc/swig/X.i
    $(ST_SWIG)/$1.i: $(addprefix $(F),$(call find-pywraps-deps,$1)) swig/$1.i $(ST_SWIG_HEADER) $(SWIG_IFACE_$1:%=$(ST_SWIG)/%.i) $(ST_SWIG_HEADER) tools/deploy.py
	$(PYTHON) tools/deploy.py \
		--pywraps $(ST_PYW) \
		--template $$(subst $(F),,$$@) \
		--output $$@ \
		--module $$(subst .i,,$$(notdir $$@)) \
		$(MODULE_LIFECYCLE_$1) \
		$(BC695_DEPLOYFLAGS) \
		--interface-dependencies=$(subst $(_SPACE),$(_COMMA),$(SWIG_IFACE_$1))

    # obj/x86_linux_gcc/wrappers/X.cpp
    $(ST_WRAP)/$1.cpp: $(ST_SWIG)/$1.i tools/patch_codegen.py makefile $(PATCH_DIRECTORS_SCRIPT) tools/chkapi.py
	$(SWIG) -modern $(WITH_HEXRAYS) -python -threads -c++ -shadow \
	  $(MACDEFINES) -D__GNUC__ $(SWIGFLAGS) $(SWITCH64) $(SWITCHX64) -I$(ST_SWIG) \
	  -outdir $(ST_WRAP) -o $$@ -I$(ST_SDK) $$<
	@$(PYTHON) tools/patch_constants.py --file $(ST_WRAP)/$1.cpp
	$(PYTHON) tools/patch_codegen.py $(PATCH_CODEGEN_X64_OPTS) --file $(ST_WRAP)/$1.cpp --patches tools/patch_codegen/$1.py
    ifdef __NT__
	$(PYTHON) $(PATCH_DIRECTORS_SCRIPT) --file $(ST_WRAP)/$1.h
    endif
    # The copying of the .py will preserve attributes (including timestamps).
    # And, since we have patched $1.cpp, it'll be more recent than ida_$1.py,
    # and make would keep copying the .py file at each invocation.
    # To prevent that, let's make the source .py file more recent than .cpp.
	@touch $(ST_WRAP)/ida_$1.py

    # obj/x86_linux_gcc/X.o32
    $(F)$1$(O): $(ST_WRAP)/$1.cpp
    ifdef __CODE_CHECKER__
	touch $$@
    else
	$(CXX) $(CFLAGS) $(MSRUNTIME) $(MSCLOPTS) $(NORTTI) -DPLUGIN_SUBMODULE -DSWIG_DIRECTOR_NORTTI -c $(OBJSW)$$@ $(ST_WRAP)/$1.cpp
      ifndef __NT__
        ifeq ($(OUT_OF_TREE_BUILD),)
	@$(STRIPSYM_TOOL) $$@ $(STRIPSYMS) > /dev/null || ($(RM) $$@; false)
        endif
      endif
    endif

    # obj/x86_linux_gcc/_ida_X.so
    $(F)_ida_$1$(MODULE_SFX): $(F)$1$(O) $(BINARY) $(IDAPYTHON_IMPLIB_DEF)
    ifdef __NT__ # we repeat /map switch with the explicit file name because @F does not work inside macro
	$(LINKER) $(LINKOPTS) /map:$(F)_ida_$1$(MODULE_SFX).map $(MSLDOPTS) /OPT:ICF /OPT:REF /INCREMENTAL:NO /STUB:../../plugins/stub /OUT:$$@ $$< $(IDALIB) user32.lib $(ADDITIONAL_LIBS_MODULE) $(IDAPYTHON_IMPLIB_PATH)
    else
	$(CCL) $(OUTDLL) $(OUTSW)$$@ $$< $(MODULE_LINKIDA) $(PLUGIN_SCRIPT) $(ADDITIONAL_LIBS_MODULE) $(STDLIBS)
    endif

    # ../../bin/x86_linux_gcc/python/lib/lib-dynload/ida_32/_ida_X.so
    $(DEPLOY_LIBDIR)/_ida_$1$(MODULE_SFX): $(F)_ida_$1$(MODULE_SFX) | $(DEPLOY_LIBDIR)
	@$(CP) $$< $$@
endef
$(foreach mod,$(MODULES_NAMES),$(eval $(call make-module-rules,$(mod))))

$(ST_API_CONTENTS): $(ALL_ST_WRAP_CPP)
	$(PYTHON) tools/chkapi.py $(WITH_HEXRAYS_CHKAPI) -i $(subst $(_SPACE),$(_COMMA),$(ALL_ST_WRAP_CPP)) -p $(subst $(_SPACE),$(_COMMA),$(ALL_ST_WRAP_PY)) -r $(ST_API_CONTENTS)
ifeq ($(OUT_OF_TREE_BUILD),)
  ifdef BC695 # turn off comparison when bw-compat is off, or api_contents will differ
	@(diff -w $(API_CONTENTS) $(ST_API_CONTENTS)) > /dev/null || \
	  (echo "API CONTENTS CHANGED! update api_contents.txt or fix the API" && \
	   echo "(New API: $(ST_API_CONTENTS)) ***" && \
	   (diff -U 1 -w $(API_CONTENTS) $(ST_API_CONTENTS) && false))
  endif
endif

# Check that doc injection is stable
PYDOC_INJECTIONS_RESULTS=$(MODULES_NAMES:%=$(ST_WRAP)/ida_%.pydoc_injection)
$(ST_PYDOC_INJECTIONS): tools/dumpdoc.py $(PYTHON_MODULES) $(PYTHON_BINARY_MODULES)
ifdef __CODE_CHECKER__
	@touch $@
else
  ifeq ($(OUT_OF_TREE_BUILD),)
	@$(IDA_CMD) $(BATCH_SWITCH) -OIDAPython:AUTOIMPORT_COMPAT_IDA695=NO -S"$< $@ $(ST_WRAP)" -t -L$(F)dumpdoc.log >/dev/null
	@(diff -w $(PYDOC_INJECTIONS) $(ST_PYDOC_INJECTIONS)) > /dev/null || \
	  (echo "PYDOC INJECTION CHANGED! update $(PYDOC_INJECTIONS) or fix .. what needs fixing" && \
	   echo "(New API: $(ST_PYDOC_INJECTIONS)) ***" && \
	   (diff -U 1 -w $(PYDOC_INJECTIONS) $(ST_PYDOC_INJECTIONS) && false))
  else
	@touch $@
  endif
endif

# Require a strict SWiG version (other versions might generate different code.)
SWIG_VERSION_ACTUAL=$(shell $(SWIG) -version | awk "/SWIG Version [0-9.]+/ { if (match(\$$0, /([0-9.]+)/)) { print substr(\$$0, RSTART, RLENGTH); } }")

# ST_WRAP_FILES=$(MODULES_NAMES:%=$(ST_WRAP)/%.cpp) $(MODULES_NAMES:%=$(ST_WRAP)/%.h) $(MODULES_NAMES:%=$(ST_WRAP)/ida_%.py)
# .PRECIOUS: $(ST_WRAP_FILES) $(MODULES_OBJECTS)
.PRECIOUS: $(ST_API_CONTENTS) $(ST_PYDOC_INJECTIONS)

DOCS_MODULES=$(MODULES_NAMES:%=ida_%)
tools/docs/hrdoc.cfg: tools/docs/hrdoc.cfg.in
	sed s/%IDA_MODULES%/"$(DOCS_MODULES)"/ < $? > $@

# the html files are produced in docs\hr-html directory
docs:   tools/docs/hrdoc.py tools/docs/hrdoc.cfg tools/docs/hrdoc.css
ifndef __NT__
	TVHEADLESS=1 $(R)idat -Stools/docs/hrdoc.py -t > /dev/null
else
	$(R)ida -Stools/docs/hrdoc.py -t
endif

# the demo version of ida does not have the -B command line option
ifeq ($(OUT_OF_TREE_BUILD),)
  ISDEMO=$(shell grep "define DEMO$$" $(IDA_INCLUDE)/commerc.hpp)
  ifeq ($(ISDEMO),)
    BATCH_SWITCH=-B
  endif
endif

# Test that all functions that are present in ftable.cpp
# are present in idc.py (and therefore made available by
# the idapython).
$(TEST_IDC): $(F)idctest.log
$(F)idctest.log: $(RS)idc/idc.idc | $(BINARY) pyfiles $(PRECOMPILED_COPY)
ifneq ($(wildcard ../../tests),)
	@$(RM) $(F)idctest.log
	@$(IDA_CMD) $(BATCH_SWITCH) -S"test_idc.py $^" -t -L$(F)idctest.log >/dev/null || \
	  (echo "ERROR: The IDAPython IDC interface is incomplete. IDA log:" && cat $(F)idctest.log && false)
endif

package:
ifeq ($(OUT_OF_TREE_BUILD),)
	-@if [ ! -d "$(DIST)" ] ; then mkdir -p 2>/dev/null $(DIST) ; fi
	$(PYTHON) $(PKGBIN_SCRIPT) \
		--input-binary-tree $(R) \
		--output-dir $(DIST) \
		--confirmed \
		--component plugins/idapython
	(cd $(DIST) && $(PYTHON) $(DBLZIP_SCRIPT) --once --output ../../../obj/$(PACKAGE_NAME))
endif

public_tree: all
ifeq ($(OUT_OF_TREE_BUILD),)
	-@if [ ! -d "$(PUBTREE_DIR)/out_of_tree" ] ; then mkdir -p 2>/dev/null $(PUBTREE_DIR)/out_of_tree ; fi
	rsync -a --exclude=obj/ \
		--exclude=precompiled/ \
		--exclude=repl.py \
		--exclude=test_idc.py \
		--exclude=RELEASE.md \
		--exclude=docs/hr-html/ \
		--exclude=**/*~ \
		. $(PUBTREE_DIR)
	(cd $(F) && zip -r ../../$(PUBTREE_DIR)/out_of_tree/parsed_notifications.zip parsed_notifications)
endif

echo_modules:
	@echo $(MODULES_NAMES)

# MAKEDEP dependency list ------------------
$(F)python$(O)  : $(I)range.hpp $(I)bitrange.hpp $(I)bytes.hpp              \
	          $(I)diskio.hpp $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp      \
	          $(I)ida.hpp $(I)idp.hpp $(I)config.hpp $(I)kernwin.hpp    \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
                  $(I)gdl.hpp $(I)graph.hpp                                 \
	          $(I)xref.hpp python.cpp pywraps.hpp pywraps.cpp | $(ST_SDK_TARGETS)
