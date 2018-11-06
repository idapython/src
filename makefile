include ../../allmake.mak

#----------------------------------------------------------------------
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

#----------------------------------------------------------------------
# default goals
.PHONY: configs modules pyfiles deployed_modules idapython_modules api_contents pydoc_injections public_tree test_idc docs
all: configs modules pyfiles deployed_modules idapython_modules api_contents pydoc_injections # public_tree test_idc docs

#----------------------------------------------------------------------
# configurable variables for this makefile
BC695 = 1
ifdef BC695
  BC695_CC_DEF = BC695
  BC695_SWIGFLAGS = -DBC695
  BC695_DEPLOYFLAGS = --bc695
endif

#----------------------------------------------------------------------
# Build system hacks

# HACK HIJACK the $(I) variable to point to our staging SDK
#      (but don't let mkdep know about it)
IDA_INCLUDE = ../../include
ifeq ($(OUT_OF_TREE_BUILD),)
  ST_SDK = $(F)idasdk
else
  ST_SDK = $(IDA_INCLUDE)
endif
ifndef __MKDEP__
  I = $(ST_SDK)/
else
  # HACK for mkdep to add dependencies for $(F)python$(O)
  OBJS += $(F)python$(O)
endif

# allmake.mak defines 'CP' as 'qcp.sh' which is an internal tool providing
# support for the '-u' flag on OSX. However, since this makefile is part
# of the public release of IDAPython, we cannot rely on it (we do not use
# that flag in IDAPython anyway)
ifdef __MAC__
  CP = cp -f
endif

#----------------------------------------------------------------------
# the 'configs' target is in $(IDA)module.mak
CONFIGS += python.cfg

#----------------------------------------------------------------------
# the 'modules' target is in $(IDA)module.mak
MODULE = $(call module_dll,python)
MODULES += $(MODULE)

#----------------------------------------------------------------------
# we explicitly added our module targets
NO_DEFAULT_MODULE = 1
DONT_ERASE_LIB = 1

# NOTE: all MODULES must be defined before including plugin.mak.
include ../plugin.mak
include ../pyplg.mak
# NOTE: target-specific rules and dependencies that use variable
#       expansion to name the target (such as "$(MODULE): [...]") must
#       come after including plugin.mak

#----------------------------------------------------------------------
PYTHON_OBJS += $(F)python$(O)
$(MODULE): MODULE_OBJS += $(PYTHON_OBJS)
$(MODULE): $(PYTHON_OBJS)
ifdef __NT__
  $(MODULE): LDFLAGS += /DEF:$(IDAPYTHON_IMPLIB_DEF) /IMPLIB:$(IDAPYTHON_IMPLIB_PATH)
endif

# TODO these should apply only to $(MODULE)
DEFFILE = idapython.script
INSTALL_NAME = @executable_path/plugins/$(notdir $(MODULE))
ifdef __LINUX__
  LDFLAGS += -Wl,-soname,$(notdir $(MODULE))
endif

#----------------------------------------------------------------------
# TODO move this below, but it might be necessary before the defines-*
ifdef DO_IDAMAKE_SIMPLIFY
  QCHKAPI = @echo $(call qcolor,chkapi) && #
  QDEPLOY = @echo $(call qcolor,deploy) $$< && #
  QGENDOXYCFG = @echo $(call qcolor,gendoxycfg) $@ && #
  QGENHOOKS = @echo $(call qcolor,genhooks) $< && #
  QGENIDAAPI = @echo $(call qcolor,genidaapi) $< && #
  QGENSWIGHEADER = @echo $(call qcolor,genswigheader) $< && #
  QGEN_IDC_BC695 = @echo $(call qcolor,gen_idc_bc695) $< && #
  QINJECT_PLFM = @echo $(call qcolor,inject_plfm) $< && #
  QINJECT_PYDOC = @echo $(call qcolor,inject_pydoc) $$< && #
  QPATCH_CODEGEN = @echo $(call qcolor,patch_codegen) $$< && #
  QSWIG = @echo $(call qcolor,swig) $$< && #
  QUPATE_SDK = @echo $(call qcolor,update_sdk) $< && #
endif

#----------------------------------------------------------------------
IDA_CMD=TVHEADLESS=1 $(R)idat$(SUFF64)
ST_SWIG=$(F)swig
ST_PYW=$(F)pywraps
ST_WRAP=$(F)wrappers
ST_PARSED_HEADERS_NOXML=$(F)parsed_notifications
ST_PARSED_HEADERS=$(ST_PARSED_HEADERS_NOXML)/xml
ifeq ($(OUT_OF_TREE_BUILD),)
  ST_PARSED_HEADERS_CONFIG=$(ST_PARSED_HEADERS_NOXML)/doxy_gen_notifs.cfg
endif

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
  IDC_BC695_IDC_SOURCE?=$(DEPLOY_PYDIR)/../idc/idc.idc
endif

#
SDK_SOURCES=$(wildcard $(IDA_INCLUDE)/*.h) $(wildcard $(IDA_INCLUDE)/*.hpp)
ifeq ($(OUT_OF_TREE_BUILD),)
  ST_SDK_TARGETS = $(SDK_SOURCES:$(IDA_INCLUDE)/%=$(ST_SDK)/%)
else
  ST_SDK_TARGETS = $(SDK_SOURCES)
endif

PYTHON_DYNLOAD=$(BIN_PATH)../python/lib/python2.7/lib-dynload
DEPLOY_LIBDIR=$(PYTHON_DYNLOAD)/ida_$(ADRSIZE)

ifdef __NT__
  MODULE_SFX = .pyd
else
  MODULE_SFX = .so
endif

ifneq ($(OUT_OF_TREE_BUILD),)
  # envvar HAS_HEXRAYS must have been set by build.py if needed
else
  HAS_HEXRAYS=1 # force hexrays bindings
endif
ifneq ($(HAS_HEXRAYS),)
  WITH_HEXRAYS_DEF = WITH_HEXRAYS
  WITH_HEXRAYS_CHKAPI=--with-hexrays
  HEXRAYS_MODNAME=hexrays
endif

#----------------------------------------------------------------------
MODULES_NAMES += $(HEXRAYS_MODNAME)
MODULES_NAMES += allins
MODULES_NAMES += auto
MODULES_NAMES += bytes
MODULES_NAMES += dbg
MODULES_NAMES += diskio
MODULES_NAMES += entry
MODULES_NAMES += enum
MODULES_NAMES += expr
MODULES_NAMES += fixup
MODULES_NAMES += fpro
MODULES_NAMES += frame
MODULES_NAMES += funcs
MODULES_NAMES += gdl
MODULES_NAMES += graph
MODULES_NAMES += ida
MODULES_NAMES += idaapi
MODULES_NAMES += idc
MODULES_NAMES += idd
MODULES_NAMES += idp
MODULES_NAMES += kernwin
MODULES_NAMES += lines
MODULES_NAMES += loader
MODULES_NAMES += moves
MODULES_NAMES += nalt
MODULES_NAMES += name
MODULES_NAMES += netnode
MODULES_NAMES += offset
MODULES_NAMES += pro
MODULES_NAMES += problems
MODULES_NAMES += range
MODULES_NAMES += registry
MODULES_NAMES += search
MODULES_NAMES += segment
MODULES_NAMES += segregs
MODULES_NAMES += strlist
MODULES_NAMES += struct
MODULES_NAMES += tryblks
MODULES_NAMES += typeinf
MODULES_NAMES += ua
MODULES_NAMES += xref

ALL_ST_WRAP_CPP = $(foreach mod,$(MODULES_NAMES),$(ST_WRAP)/$(mod).cpp)
ALL_ST_WRAP_PY = $(foreach mod,$(MODULES_NAMES),$(ST_WRAP)/ida_$(mod).py)
DEPLOYED_MODULES = $(foreach mod,$(MODULES_NAMES),$(DEPLOY_LIBDIR)/_ida_$(mod)$(MODULE_SFX))
IDAPYTHON_MODULES = $(foreach mod,$(MODULES_NAMES),$(DEPLOY_PYDIR)/ida_$(mod).py)
PYTHON_BINARY_MODULES = $(foreach mod,$(MODULES_NAMES),$(DEPLOY_LIBDIR)/_ida_$(mod)$(MODULE_SFX))

#----------------------------------------------------------------------
idapython_modules: $(IDAPYTHON_MODULES)
deployed_modules: $(DEPLOYED_MODULES)

ifdef __NT__
  IDAPYTHON_IMPLIB_DEF=idapython_implib.def
  IDAPYTHON_IMPLIB_PATH=$(F)python.lib
  LINKIDAPYTHON = $(IDAPYTHON_IMPLIB_PATH)
else
  LINKIDAPYTHON = $(MODULE)
endif

ifdef __NT__                   # os and compiler specific flags
  _SWIGFLAGS = -D__NT__ -DWIN32 -D_USRDLL -I$(PYTHON_DIR)/include
  CFLAGS += /bigobj $(_SWIGFLAGS) -I$(ST_SDK) /U_DEBUG
  # override runtime libs in CFLAGS
  RUNTIME_LIBSW = /MD
else # unix/mac
  ifdef __LINUX__
    PYTHON_LDFLAGS_RPATH_MAIN=-Wl,-rpath='$$ORIGIN/..'
    PYTHON_LDFLAGS_RPATH_MODULE=-Wl,-rpath='$$ORIGIN/../../..'
    _SWIGFLAGS = -D__LINUX__
  else ifdef __MAC__
    _SWIGFLAGS = -D__MAC__
  endif
endif
# Apparently that's not needed, but I don't understand why ATM, since doc says:
#  ...Then, only modules compiled with SWIG_TYPE_TABLE set to myprojectname
#  will share type information. So if your project has three modules, all three
#  should be compiled with -DSWIG_TYPE_TABLE=myprojectname, and then these
#  three modules will share type information. But any other project's
#  types will not interfere or clash with the types in your module.
DEF_TYPE_TABLE = SWIG_TYPE_TABLE=idaapi
SWIGFLAGS=$(_SWIGFLAGS) -Itools/typemaps-supplement $(SWIG_INCLUDES) $(addprefix -D,$(DEF_TYPE_TABLE)) $(BC695_SWIGFLAGS)

LDFLAGS += $(PYTHON_LDFLAGS) $(PYTHON_LDFLAGS_RPATH_MAIN)

pyfiles: $(DEPLOY_IDAUTILS_PY)  \
         $(DEPLOY_IDC_PY)       \
         $(DEPLOY_IDC_BC695_PY) \
         $(DEPLOY_INIT_PY)      \
         $(DEPLOY_IDAAPI_PY)    \
         $(DEPLOY_IDADEX_PY)

GENHOOKS=tools/genhooks/

$(DEPLOY_INIT_PY): python/init.py
	$(CP) $? $@

$(DEPLOY_IDC_PY): python/idc.py
	$(CP) $? $@

$(DEPLOY_IDAUTILS_PY): python/idautils.py
	$(CP) $? $@

$(DEPLOY_IDC_BC695_PY): $(IDC_BC695_IDC_SOURCE) python/idc.py tools/gen_idc_bc695.py
	$(QGEN_IDC_BC695)$(PYTHON) tools/gen_idc_bc695.py --idc $(IDC_BC695_IDC_SOURCE) --output $@

$(DEPLOY_IDAAPI_PY): python/idaapi.py tools/genidaapi.py $(IDAPYTHON_MODULES)
	$(QGENIDAAPI)$(PYTHON) tools/genidaapi.py -i $< -o $@ -m $(subst $(space),$(comma),$(MODULES_NAMES))

$(DEPLOY_IDADEX_PY): python/idadex.py
	$(CP) $? $@

$(DEPLOY_PYDIR)/lib/%: precompiled/lib/%
	cp $< $@
	$(Q)chmod +w $@

#----------------------------------------------------------------------
# Hooks generation
# http://stackoverflow.com/questions/11032280/specify-doxygen-parameters-through-command-line
$(ST_PARSED_HEADERS_CONFIG): $(GENHOOKS)doxy_gen_notifs.cfg.in $(ST_SDK_TARGETS) $(GENHOOKS)gendoxycfg.py
	$(QGENDOXYCFG)$(PYTHON) $(GENHOOKS)gendoxycfg.py -i $< -o $@ --includes $(subst $(space),$(comma),$(ST_SDK_TARGETS))

PARSED_HEADERS_MARKER=$(ST_PARSED_HEADERS)/headers_generated.marker
$(PARSED_HEADERS_MARKER): $(ST_SDK_TARGETS) $(ST_PARSED_HEADERS_CONFIG) $(ST_SDK_TARGETS)
ifeq ($(OUT_OF_TREE_BUILD),)
	$(Q)( cat $(ST_PARSED_HEADERS_CONFIG); echo "OUTPUT_DIRECTORY=$(ST_PARSED_HEADERS_NOXML)" ) | $(DOXYGEN_BIN) - >/dev/null
else
	(cd $(F) && unzip ../../out_of_tree/parsed_notifications.zip)
endif
	$(Q)touch $@

#----------------------------------------------------------------------
# Create directories in the first phase of makefile parsing.
DIRLIST += $(DEPLOY_LIBDIR)
DIRLIST += $(DEPLOY_PYDIR)
DIRLIST += $(DEPLOY_PYDIR)/lib
DIRLIST += $(ST_PARSED_HEADERS)
DIRLIST += $(ST_PYW)
DIRLIST += $(ST_SDK)
DIRLIST += $(ST_SWIG)
DIRLIST += $(ST_WRAP)
$(foreach d,$(sort $(DIRLIST)),$(if $(wildcard $(d)),,$(shell mkdir -p $(d))))

#----------------------------------------------------------------------
# obj/.../idasdk/*.h[pp]
ifeq ($(OUT_OF_TREE_BUILD),)
$(ST_SDK)/%.h: $(IDA_INCLUDE)/%.h
	$(QUPATE_SDK)$(PYTHON) ../../bin/update_sdk.py $(FILTER_SDK_FLAGS) -filter-file -input $^ -output $@
$(ST_SDK)/%.hpp: $(IDA_INCLUDE)/%.hpp
	$(QUPATE_SDK)$(PYTHON) ../../bin/update_sdk.py $(FILTER_SDK_FLAGS) -filter-file -input $^ -output $@
endif

#----------------------------------------------------------------------
# obj/.../pywraps/*
$(ST_PYW)/%.hpp: pywraps/%.hpp
	$(Q)$(CP) $^ $@ && chmod +rw $@
$(ST_PYW)/%.py: pywraps/%.py
	$(Q)$(CP) $^ $@ && chmod +rw $@

# These require special care, as they will have to be injected w/ hooks -- this
# only happens if we are sitting in the hexrays source tree; when published to
# the outside world, the pywraps must already contain the injected code.
$(ST_PYW)/py_idp.hpp: pywraps/py_idp.hpp \
        $(I)idp.hpp \
        $(GENHOOKS)genhooks.py \
        $(GENHOOKS)recipe_idphooks.py \
        $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -x $(ST_PARSED_HEADERS)/structprocessor__t.xml -e event_t \
                -r int -n 0 -m hookgenIDP -q "processor_t::" \
                -R $(GENHOOKS)recipe_idphooks.py
$(ST_PYW)/py_idp_idbhooks.hpp: pywraps/py_idp_idbhooks.hpp \
        $(I)idp.hpp \
        $(GENHOOKS)recipe_idbhooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -x $(ST_PARSED_HEADERS)/namespaceidb__event.xml -e event_code_t \
                -r int -n 0 -m hookgenIDB -q "idb_event::" \
                -R $(GENHOOKS)recipe_idbhooks.py
$(ST_PYW)/py_dbg.hpp: pywraps/py_dbg.hpp \
        $(I)dbg.hpp \
        $(GENHOOKS)recipe_dbghooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -x $(ST_PARSED_HEADERS)/dbg_8hpp.xml -e dbg_notification_t \
                -r void -n 0 -m hookgenDBG \
                -R $(GENHOOKS)recipe_dbghooks.py
$(ST_PYW)/py_kernwin.hpp: pywraps/py_kernwin.hpp \
        $(I)kernwin.hpp \
        $(GENHOOKS)recipe_uihooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -x $(ST_PARSED_HEADERS)/kernwin_8hpp.xml -e ui_notification_t \
                -r void -n 0 -m hookgenUI \
                -R $(GENHOOKS)recipe_uihooks.py \
                -d "ui_dbg_,ui_obsolete" -D "ui:" -s "ui_"
$(ST_PYW)/py_kernwin_viewhooks.hpp: pywraps/py_kernwin_viewhooks.hpp \
        $(I)kernwin.hpp \
        $(GENHOOKS)recipe_viewhooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -x $(ST_PARSED_HEADERS)/kernwin_8hpp.xml -e view_notification_t \
                -r void -n 0 -m hookgenVIEW \
                -R $(GENHOOKS)recipe_viewhooks.py
$(ST_PYW)/py_hexrays_hooks.hpp: pywraps/py_hexrays_hooks.hpp \
        $(I)hexrays.hpp \
        $(GENHOOKS)recipe_hexrays.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -x $(ST_PARSED_HEADERS)/hexrays_8hpp.xml -e hexrays_event_t \
                -r int -n 0 -m hookgenHEXRAYS \
                -R $(GENHOOKS)recipe_hexrays.py \
                -s "hxe_,lxe_"


#----------------------------------------------------------------------
CFLAGS += $(PYTHON_CFLAGS)
CC_DEFS += $(BC695_CC_DEF)
CC_DEFS += $(DEF_TYPE_TABLE)
CC_DEFS += $(WITH_HEXRAYS_DEF)
CC_DEFS += USE_STANDARD_FILE_FUNCTIONS
CC_DEFS += VER_MAJOR="1"
CC_DEFS += VER_MINOR="7"
CC_DEFS += VER_PATCH="0"
CC_DEFS += __EXPR_SRC
CC_INCP += $(F)
CC_INCP += $(IDA_INCLUDE)
CC_INCP += $(ST_SWIG)
CC_INCP += .

# suppress warnings
WARNS = $(NOWARNS)

# disable -pthread in CFLAGS
PTHR_SWITCH =

# disable -DNO_OBSOLETE_FUNCS in CFLAGS
NO_OBSOLETE_FUNCS =

#----------------------------------------------------------------------
ifdef TESTABLE_BUILD
  SWIGFLAGS+=-DTESTABLE_BUILD
  FILTER_SDK_FLAGS+=-testable-build
endif

ST_SWIG_HEADER = $(ST_SWIG)/header.i
$(ST_SWIG)/header.i: tools/deploy/header.i.in tools/genswigheader.py $(ST_SDK_TARGETS)
	$(QGENSWIGHEADER)$(PYTHON) tools/genswigheader.py -i $< -o $@ -m $(subst $(space),$(comma),$(MODULES_NAMES)) -s $(ST_SDK)

ifdef __NT__
  PATCH_DIRECTORS_SCRIPT = tools/patch_directors_cc.py
endif

find-pywraps-deps = $(wildcard pywraps/py_$(subst .i,,$(notdir $(1)))*.hpp) $(wildcard pywraps/py_$(subst .i,,$(notdir $(1)))*.py)
find-pydoc-patches-deps = $(wildcard tools/inject_pydoc/$(1).py)


ADDITIONAL_PYWRAP_DEP_idp=$(ST_PYW)/py_idp.py
$(ST_PYW)/py_idp.py: pywraps/py_idp.py.in tools/inject_plfm.py $(ST_SDK)/idp.hpp
	$(QINJECT_PLFM)$(PYTHON) tools/inject_plfm.py -i $< -o $@ -d $(ST_SDK)/idp.hpp

# Some .i files depend on some other .i files in order to be parseable by SWiG
# (e.g., segregs.i imports range.i). Declare the list of such dependencies here
# so they will be picked by the auto-generated rules.
SWIG_IFACE_bytes=range
SWIG_IFACE_dbg=idd
SWIG_IFACE_frame=range
SWIG_IFACE_funcs=range
SWIG_IFACE_gdl=range
SWIG_IFACE_hexrays=typeinf
SWIG_IFACE_idd=range
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
    #   $(ST_WRAP)/ida_$(1).py: $(ST_WRAP)/$(1).cpp
    #
    # i.e., that do nothing but rely on the generation of another file,
    # will not work in // execution. Thus, we will rely exclusively on
    # the presence of the generated .cpp file, and not other generated
    # files.

    # ../../bin/x86_linux_gcc/python/ida_$(1).py (note: dep. on .cpp. See note above.)
    $(DEPLOY_PYDIR)/ida_$(1).py: $(ST_WRAP)/$(1).cpp $(PARSED_HEADERS_MARKER) $(call find-pydoc-patches-deps,$(1)) | tools/inject_pydoc.py
	$(QINJECT_PYDOC)$(PYTHON) tools/inject_pydoc.py \
                -x $(ST_PARSED_HEADERS) \
                -m $(1) \
                -i $(ST_WRAP)/ida_$(1).py \
                -w $(ST_SWIG)/$(1).i \
                -o $$@ \
                -e $(ST_WRAP)/ida_$(1).epydoc_injection \
                -v > $(ST_WRAP)/ida_$(1).pydoc_injection 2>&1

    # obj/x86_linux_gcc/swig/X.i
    $(ST_SWIG)/$(1).i: $(addprefix $(F),$(call find-pywraps-deps,$(1))) $(ADDITIONAL_PYWRAP_DEP_$(1)) swig/$(1).i $(ST_SWIG_HEADER) $(SWIG_IFACE_$(1):%=$(ST_SWIG)/%.i) $(ST_SWIG_HEADER) tools/deploy.py $(PARSED_HEADERS_MARKER)
	$(QDEPLOY)$(PYTHON) tools/deploy.py \
                --pywraps $(ST_PYW) \
                --template $$(subst $(F),,$$@) \
                --output $$@ \
                --module $$(subst .i,,$$(notdir $$@)) \
                $(MODULE_LIFECYCLE_$(1)) \
                $(BC695_DEPLOYFLAGS) \
                --interface-dependencies=$(subst $(space),$(comma),$(SWIG_IFACE_$(1))) \
		--xml-doc-directory $(ST_PARSED_HEADERS)

    # obj/x86_linux_gcc/wrappers/X.cpp
    $(ST_WRAP)/$(1).cpp: $(ST_SWIG)/$(1).i tools/patch_codegen.py $(PATCH_DIRECTORS_SCRIPT) $(PARSED_HEADERS_MARKER) tools/chkapi.py
	$(QSWIG)$(SWIG) -modern $(addprefix -D,$(WITH_HEXRAYS_DEF)) -python -threads -c++ -shadow \
          -D__GNUC__ $(SWIGFLAGS) $(addprefix -D,$(DEF64)) -I$(ST_SWIG) \
          -outdir $(ST_WRAP) -o $$@ -I$(ST_SDK) $$<
	$(Q)$(PYTHON) tools/patch_constants.py --file $(ST_WRAP)/$(1).cpp
	$(QPATCH_CODEGEN)$(PYTHON) tools/patch_codegen.py \
                --apply-valist-patches \
                --file $(ST_WRAP)/$(1).cpp \
                --module $(1) \
                --xml-doc-directory $(ST_PARSED_HEADERS) \
                --patches tools/patch_codegen/$(1).py
    ifdef __NT__
	$(PYTHON) $(PATCH_DIRECTORS_SCRIPT) --file $(ST_WRAP)/$(1).h
    endif
    # The copying of the .py will preserve attributes (including timestamps).
    # And, since we have patched $(1).cpp, it'll be more recent than ida_$(1).py,
    # and make would keep copying the .py file at each invocation.
    # To prevent that, let's make the source .py file more recent than .cpp.
	$(Q)touch $(ST_WRAP)/ida_$(1).py
endef
$(foreach mod,$(MODULES_NAMES),$(eval $(call make-module-rules,$(mod))))

# obj/x86_linux_gcc/X.o
X_O = $(call objs,$(MODULES_NAMES))
vpath %.cpp $(ST_WRAP)
ifdef __NT__
  # remove warnings from generated code:
  # error C4296: '<': expression is always false
  # warning C4700: uninitialized local variable 'c_result' used
  # warning C4706: assignment within conditional expression
  $(X_O): CFLAGS += /wd4296 /wd4700 /wd4706
endif
# disable -fno-rtti
$(X_O): NORTTI =
$(X_O): CC_DEFS += PLUGIN_SUBMODULE
$(X_O): CC_DEFS += SWIG_DIRECTOR_NORTTI
ifdef __CODE_CHECKER__
$(X_O):
	$(Q)touch $@
endif

# obj/x86_linux_gcc/_ida_X.so
_IDA_X_SO = $(addprefix $(F)_ida_,$(addsuffix $(MODULE_SFX),$(MODULES_NAMES)))
ifdef __NT__
  $(_IDA_X_SO): STDLIBS += user32.lib
endif
# Note: On Windows, IDAPython's python.lib must come *after* python27.lib
#       in the linking command line, otherwise Python will misdetect
#       IDAPython's python.dll as the main "python" DLL, and IDAPython
#       will fail to load with the following error:
#         "Module use of python.dll conflicts with this version of Python."
#       To achieve this, we add IDAPython's python.lib to STDLIBS, which
#       is at the end of the link command.
#       See Python's dynload_win.c:GetPythonImport() for more details.
$(_IDA_X_SO): STDLIBS += $(LINKIDAPYTHON)
$(_IDA_X_SO): LDFLAGS += $(PYTHON_LDFLAGS_RPATH_MODULE) $(OUTMAP)$(F)$(@F).map
$(F)_ida_%$(MODULE_SFX): $(F)%$(O) $(MODULE) $(IDAPYTHON_IMPLIB_DEF)
	$(call link_dll, $<, $(LINKIDA))
ifdef __NT__
	$(Q)$(RM) $(@:$(MODULE_SFX)=.exp) $(@:$(MODULE_SFX)=.lib)
endif

# ../../bin/x86_linux_gcc/python/lib/lib-dynload/ida_32/_ida_X.so
$(DEPLOY_LIBDIR)/_ida_%$(MODULE_SFX): $(F)_ida_%$(MODULE_SFX)
	$(Q)$(CP) $< $@

#----------------------------------------------------------------------
API_CONTENTS = api_contents.txt
ST_API_CONTENTS = $(F)$(API_CONTENTS)
.PRECIOUS: $(ST_API_CONTENTS)

api_contents: $(ST_API_CONTENTS)
$(ST_API_CONTENTS): $(ALL_ST_WRAP_CPP)
	$(QCHKAPI)$(PYTHON) tools/chkapi.py $(WITH_HEXRAYS_CHKAPI) -i $(subst $(space),$(comma),$(ALL_ST_WRAP_CPP)) -p $(subst $(space),$(comma),$(ALL_ST_WRAP_PY)) -r $(ST_API_CONTENTS)
ifeq ($(OUT_OF_TREE_BUILD),)
  ifdef BC695 # turn off comparison when bw-compat is off, or api_contents will differ
	$(Q)(diff -w $(API_CONTENTS) $(ST_API_CONTENTS)) > /dev/null || \
          (echo "API CONTENTS CHANGED! update $(API_CONTENTS) or fix the API" && \
           echo "(New API: $(ST_API_CONTENTS)) ***" && \
           (diff -U 1 -w $(API_CONTENTS) $(ST_API_CONTENTS) && false))
  endif
endif

#----------------------------------------------------------------------
# Check that doc injection is stable
PYDOC_INJECTIONS = pydoc_injections.txt
ST_PYDOC_INJECTIONS = $(F)$(PYDOC_INJECTIONS)
.PRECIOUS: $(ST_PYDOC_INJECTIONS)

pydoc_injections: $(ST_PYDOC_INJECTIONS)
$(ST_PYDOC_INJECTIONS): tools/dumpdoc.py $(IDAPYTHON_MODULES) $(PYTHON_BINARY_MODULES)
ifdef __CODE_CHECKER__
	$(Q)touch $@
else
  ifeq ($(OUT_OF_TREE_BUILD),)
	$(Q)$(IDA_CMD) $(BATCH_SWITCH) -OIDAPython:AUTOIMPORT_COMPAT_IDA695=NO -S"$< $@ $(ST_WRAP)" -t -L$(F)dumpdoc.log >/dev/null
	$(Q)(diff -w $(PYDOC_INJECTIONS) $(ST_PYDOC_INJECTIONS)) > /dev/null || \
          (echo "PYDOC INJECTION CHANGED! update $(PYDOC_INJECTIONS) or fix .. what needs fixing" && \
           echo "(New API: $(ST_PYDOC_INJECTIONS)) ***" && \
           (diff -U 1 -w $(PYDOC_INJECTIONS) $(ST_PYDOC_INJECTIONS) && false))
  else
	$(Q)touch $@
  endif
endif

#----------------------------------------------------------------------
DOCS_MODULES=$(foreach mod,$(MODULES_NAMES),ida_$(mod))
tools/docs/hrdoc.cfg: tools/docs/hrdoc.cfg.in
	sed s/%IDA_MODULES%/"$(DOCS_MODULES)"/ < $^ > $@

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

#----------------------------------------------------------------------
# Test that all functions that are present in ftable.cpp
# are present in idc.py (and therefore made available by
# the idapython).
test_idc: $(TEST_IDC)
$(TEST_IDC): $(F)idctest.log
$(F)idctest.log: $(RS)idc/idc.idc | $(MODULE) pyfiles
ifneq ($(wildcard ../../tests),)
	$(Q)$(RM) $(F)idctest.log
	$(Q)$(IDA_CMD) $(BATCH_SWITCH) -S"test_idc.py $^" -t -L$(F)idctest.log >/dev/null || \
          (echo "ERROR: The IDAPython IDC interface is incomplete. IDA log:" && cat $(F)idctest.log && false)
endif

#----------------------------------------------------------------------
PUBTREE_DIR=$(F)/public_tree
public_tree: all
ifeq ($(OUT_OF_TREE_BUILD),)
	-$(Q)if [ ! -d "$(PUBTREE_DIR)/out_of_tree" ] ; then mkdir -p 2>/dev/null $(PUBTREE_DIR)/out_of_tree ; fi
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

#----------------------------------------------------------------------
# the 'echo_modules' target must be called explicitly
# Note: used by ida/build/pkgbin.py
echo_modules:
	@echo $(MODULES_NAMES)

#----------------------------------------------------------------------
clean::
	rm -rf obj/

# MAKEDEP dependency list ------------------
$(F)python$(O)  : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)diskio.hpp $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp      \
                  $(I)gdl.hpp $(I)graph.hpp $(I)ida.hpp                     \
                  $(I)ida_highlighter.hpp $(I)idd.hpp $(I)idp.hpp           \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
                  $(I)pro.h $(I)range.hpp $(I)segment.hpp $(I)typeinf.hpp   \
                  $(I)ua.hpp $(I)xref.hpp python.cpp pywraps.cpp            \
                  pywraps.hpp
