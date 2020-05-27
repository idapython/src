
ifeq ($(PYTHON_VERSION_MAJOR),2)
  OBJDIR=obj/$(SYSDIR)/2
else
  OBJDIR=obj/$(SYSDIR)/3
endif

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
.PHONY: configs modules pyfiles deployed_modules idapython_modules api_contents pydoc_injections pyqt sip bins public_tree test_idc docs
all: configs modules pyfiles deployed_modules idapython_modules api_contents pydoc_injections pyqt sip bins # public_tree test_idc docs

ifeq ($(OUT_OF_TREE_BUILD),)
  BINS += $(IDAPYSWITCH)
else
  # when out-of-tree (i.e., from github), we only build idapyswitch64,
  # and rely on it even for the __EA32__ build
  ifdef __EA64__
    BINS += $(IDAPYSWITCH)
  else
    IDAPYSWITCH_64_HACK := 64
  endif
endif

IDAPYSWITCH:=$(R)idapyswitch$(IDAPYSWITCH_64_HACK)$(B)

BINS += $(IDAPYSWITCH)
bins: $(BINS)

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
ST_SDK = $(F)idasdk
ifndef __MKDEP__
  I = $(ST_SDK)/
endif

# HACK HIJACK the $(LIBDIR) variable to point to our staging SDK
ifneq ($(OUT_OF_TREE_BUILD),)
  LIBDIR = $(IDA)lib/$(TARGET_PROCESSOR_NAME)_$(SYSNAME)_$(COMPILER_NAME)_$(ADRSIZE)$(EXTRASUF)
endif

# HACK for mkdep to add dependencies for $(F)idapython$(O)
ifdef __MKDEP__
  OBJS += $(F)idapython$(O)
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
CONFIGS += idapython.cfg

#----------------------------------------------------------------------
# the 'modules' target is in $(IDA)module.mak
ifeq ($(PYTHON_VERSION_MAJOR),3)
  ifdef __EA64__
    MODULE_NAME_STEM:=idapython3_
  else
    MODULE_NAME_STEM:=idapython3
  endif
else
  ifdef __EA64__
    MODULE_NAME_STEM:=idapython2_
  else
    MODULE_NAME_STEM:=idapython2
  endif
endif
MODULE = $(call module_dll,$(MODULE_NAME_STEM))
MODULES += $(MODULE)

#----------------------------------------------------------------------
ifdef __MAC__
  # it is important that we guarantee some available space in the header,
  # we might want to patch the libpython load commands later.
  LDFLAGS += -Wl,-headerpad,0x400
else
  ifdef __LINUX__
    # We want the 'DT_NEEDED' of idapython.so to be sufficiently large
    # to hold any libpython3.Y<modifiers>.so<suffix>. Therefore, at
    # build-time, let's use our tool (which will in turn use patchelf)
    # to expand the DT_NEEDED 'slot' size.
    ifeq ($(PYTHON_VERSION_MAJOR),3)
      IDAPYSWITCH_MODULE_DEP := $(IDAPYSWITCH)
      ifndef __CODE_CHECKER__
        # this is for idapython[64].so
        POSTACTION=$(Q)$(IDAPYSWITCH) --split-debug-and-expand-libpython3-dtneeded-room $(MODULE)
        # and this for _ida_*.so
        POSTACTION_IDA_X_SO=$(Q)$(IDAPYSWITCH) --split-debug-and-expand-libpython3-dtneeded-room
      endif
    endif
  endif
endif


#----------------------------------------------------------------------
# we explicitly added our module targets
NO_DEFAULT_TARGETS = 1
DONT_ERASE_LIB = 1

# NOTE: all MODULES must be defined before including plugin.mak.
include ../plugin.mak
include ../pyplg.mak
# NOTE: target-specific rules and dependencies that use variable
#       expansion to name the target (such as "$(MODULE): [...]") must
#       come after including plugin.mak

#----------------------------------------------------------------------
PYTHON_OBJS += $(F)idapython$(O)
$(MODULE): MODULE_OBJS += $(PYTHON_OBJS)
$(MODULE): $(PYTHON_OBJS) $(IDAPYSWITCH_MODULE_DEP)
ifdef __NT__
  $(MODULE): LDFLAGS += /DEF:$(IDAPYTHON_IMPLIB_DEF) /IMPLIB:$(IDAPYTHON_IMPLIB_PATH)
endif

# TODO these should apply only to $(MODULE)
DEFFILE = idapython.script
INSTALL_NAME = @executable_path/plugins/$(notdir $(MODULE))
ifdef __LINUX__
  LDFLAGS += -Wl,-soname,$(notdir $(MODULE))
endif

PATCH_CONST=$(Q)$(PYTHON) tools/patch_constants.py -i $(1) -o $(2)

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
  QINJECT_BASE_HOOKS_FLAGS = @echo $(call qcolor,inject_base_hooks_flags) $< && #
  QPATCH_CODEGEN = @echo $(call qcolor,patch_codegen) $$< && #
  QPATCH_H_CODEGEN = @echo $(call qcolor,patch_h_codegen) $$< && #
  QPATCH_PYTHON_CODEGEN = @echo $(call qcolor,patch_python_codegen) $$< && #
  QSWIG = @echo $(call qcolor,swig) $$< && #
  QUPDATE_SDK = @echo $(call qcolor,update_sdk) $< && #
  QSPLIT_HEXRAYS_TEMPLATES = @echo $(call qcolor,split_hexrays_templates) $< && #
  QPYDOC_INJECTIONS = @echo $(call qcolor,check_injections) $@ && #
endif

#----------------------------------------------------------------------
ST_SWIG=$(F)swig
ST_PYW=$(F)pywraps
ST_WRAP=$(F)wrappers
ST_PARSED_HEADERS_NOXML=$(F)parsed_notifications
ST_PARSED_HEADERS=$(ST_PARSED_HEADERS_NOXML)/xml
ifeq ($(OUT_OF_TREE_BUILD),)
  ST_PARSED_HEADERS_CONFIG=$(ST_PARSED_HEADERS_NOXML)/doxy_gen_notifs.cfg
endif

# output directory for python scripts
DEPLOY_PYDIR=$(R)python/$(PYTHON_VERSION_MAJOR)
DEPLOY_INIT_PY=$(DEPLOY_PYDIR)/init.py
DEPLOY_IDC_PY=$(DEPLOY_PYDIR)/idc.py
DEPLOY_IDAUTILS_PY=$(DEPLOY_PYDIR)/idautils.py
DEPLOY_IDC_BC695_PY=$(DEPLOY_PYDIR)/idc_bc695.py
DEPLOY_IDAAPI_PY=$(DEPLOY_PYDIR)/idaapi.py
DEPLOY_IDADEX_PY=$(DEPLOY_PYDIR)/idadex.py
ifdef TESTABLE_BUILD
  DEPLOY_LUMINA_MODEL_PY=$(DEPLOY_PYDIR)/lumina_model.py
endif
ifeq ($(OUT_OF_TREE_BUILD),)
  TEST_IDC=test_idc
  IDC_BC695_IDC_SOURCE?=$(DEPLOY_PYDIR)/../../idc/idc.idc
  IDAT_PATH?=$(R)/idat
else
  IDC_BC695_IDC_SOURCE?=$(IDA_INSTALL)/idc/idc.idc
  IDAT_PATH?=$(IDA_INSTALL)/idat
endif

IDAT_CMD=TVHEADLESS=1 $(IDAT_PATH)$(SUFF64)

ifneq ($(OUT_OF_TREE_BUILD),)
  # envvar HAS_HEXRAYS must have been set by build.py if needed
else
  ifeq ($(BUILD_VD),1)
    HAS_HEXRAYS=1 # force hexrays bindings
  endif
endif
#
ifeq ($(OUT_OF_TREE_BUILD),)
  include ../../etc/sdk/sdk_files.mak
  SDK_SOURCES=$(sort $(foreach v,$(SDK_FILES),$(if $(findstring include/,$(v)),$(addprefix $(IDA_INCLUDE)/,$(notdir $(v))))))
  ifneq ($(HAS_HEXRAYS),)
    SDK_SOURCES+=$(IDA_INCLUDE)/hexrays.hpp
  endif
  SDK_SOURCES+=$(IDA_INCLUDE)/lumina.hpp
  SDK_SOURCES+=$(IDA_INCLUDE)/dirtree.hpp
else
  SDK_SOURCES=$(wildcard $(IDA_INCLUDE)/*.h) $(wildcard $(IDA_INCLUDE)/*.hpp)
endif
ST_SDK_TARGETS = $(SDK_SOURCES:$(IDA_INCLUDE)/%=$(ST_SDK)/%)

# Python 2-3
ifeq ($(PYTHON_VERSION_MAJOR),3)
  _SWIGPY3FLAG := -py3 -py3-stable-abi -DPY3=1
  CC_DEFS += PY3=1
  CC_DEFS += Py_LIMITED_API=0x03040000 # we should make sure we use the same version as SWiG
else
  USE_PYTHON2_ENVVAR := USE_PYTHON2=1
endif
DYNLOAD_SUBDIR := python$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR)

DEPLOY_LIBDIR=$(DEPLOY_PYDIR)/ida_$(ADRSIZE)

ifdef __NT__
  PYDLL_EXT = .pyd
else
  PYDLL_EXT = .so
endif

ifneq ($(HAS_HEXRAYS),)
  WITH_HEXRAYS_DEF = WITH_HEXRAYS
  WITH_HEXRAYS_CHKAPI=--with-hexrays
  HEXRAYS_MODNAME=hexrays
  ifdef BC695
    CMP_API = 1
  endif
  # Warning: adding an empty HEXRAYS_MODNAME will lead to idaapy trying to load
  # a module called ida_.
  MODULES_NAMES += $(HEXRAYS_MODNAME)
endif

ifeq ($(CMP_API),)
  NO_CMP_API := 1
endif

#----------------------------------------------------------------------
MODULES_NAMES += allins
MODULES_NAMES += auto
MODULES_NAMES += bitrange
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
ifdef TESTABLE_BUILD
  MODULES_NAMES += lumina
  # when dirtree.hpp makes it into the SDK, add all relevant scripts
  # that are currently in tests/ui/, into plugins/idapython/examples/.
  # Grep for 'dirtree' and 'dirspec' to spot those.
  MODULES_NAMES += dirtree
endif
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
DEPLOYED_MODULES = $(foreach mod,$(MODULES_NAMES),$(DEPLOY_LIBDIR)/_ida_$(mod)$(PYDLL_EXT))
IDAPYTHON_MODULES = $(foreach mod,$(MODULES_NAMES),$(DEPLOY_PYDIR)/ida_$(mod).py)
PYTHON_BINARY_MODULES = $(foreach mod,$(MODULES_NAMES),$(DEPLOY_LIBDIR)/_ida_$(mod)$(PYDLL_EXT))

#----------------------------------------------------------------------
idapython_modules: $(IDAPYTHON_MODULES)
deployed_modules: $(DEPLOYED_MODULES)

ifdef __NT__
  IDAPYTHON_IMPLIB_DEF=idapython_implib.def
  IDAPYTHON_IMPLIB_PATH=$(F)idapython.lib
  LINKIDAPYTHON = $(IDAPYTHON_IMPLIB_PATH)
else
  LINKIDAPYTHON = $(MODULE)
endif

ifdef __NT__                   # os and compiler specific flags
  _SWIGFLAGS = -D__NT__ -DWIN32 -D_USRDLL -I"$(PYTHON_ROOT)/include"
  CFLAGS += /bigobj $(_SWIGFLAGS) -I$(ST_SDK) /U_DEBUG
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

pyfiles: $(DEPLOY_IDAUTILS_PY)  \
         $(DEPLOY_IDC_PY)       \
         $(DEPLOY_IDC_BC695_PY) \
         $(DEPLOY_INIT_PY)      \
         $(DEPLOY_IDAAPI_PY)    \
         $(DEPLOY_IDADEX_PY)    \
         $(DEPLOY_LUMINA_MODEL_PY)

ifeq ($(OUT_OF_TREE_BUILD),)
  ifndef NDEBUG
    SRC_PYQT_BUNDLE:=$(PYQT5_DEBUG)
  else
    SRC_PYQT_BUNDLE:=$(PYQT5_RELEASE)
  endif
  DEST_PYQT_DIR:=$(R)python/$(PYTHON_VERSION_MAJOR)/PyQt5
  $(DEST_PYQT_DIR):
	-$(Q)if [ ! -d "$(DEST_PYQT_DIR)" ] ; then mkdir -p 2>/dev/null $(DEST_PYQT_DIR) ; fi

  # PyQt5
  DEST_PYQT_QTCORE:=$(DEST_PYQT_DIR)/QtCore$(PYDLL_EXT)
  $(DEST_PYQT_QTCORE): $(SRC_PYQT_BUNDLE) | $(DEST_PYQT_DIR)
	$(Q)tar -xf $(SRC_PYQT_BUNDLE) -C $(dir $(DEST_PYQT_DIR)) --strip 1
	$(Q)touch $@
  DEST_PYQT += $(DEST_PYQT_QTCORE)

  SIP_PYDLL_FNAME:=sip$(PYDLL_EXT)
  SIP_PYI_FNAME:=sip.pyi

  ifeq ($(PYTHON_VERSION_MAJOR),3)
    # sip for Python < 3.8
    DEST_SIP34_DIR:=$(DEST_PYQT_DIR)/python_3.4
    $(DEST_SIP34_DIR):
	-$(Q)if [ ! -d "$(DEST_SIP34_DIR)" ] ; then mkdir -p 2>/dev/null $(DEST_SIP34_DIR) ; fi
    DEST_SIP34_PYDLL:=$(DEST_SIP34_DIR)/$(SIP_PYDLL_FNAME)
    DEST_SIP34_PYI:=$(DEST_SIP34_DIR)/$(SIP_PYI_FNAME)
    $(DEST_SIP34_PYDLL): $(wildcard $(SIP34_TREE)/lib/python*/PyQt5/$(SIP_PYDLL_FNAME)) | $(DEST_SIP34_DIR)
	$(Q)$(CP) $? $@
    $(DEST_SIP34_PYI): $(wildcard $(SIP34_TREE)/lib/python*/PyQt5/$(SIP_PYI_FNAME)) | $(DEST_SIP34_DIR)
	$(Q)$(CP) $? $@
    DEST_SIP += $(DEST_SIP34_PYDLL) $(DEST_SIP34_PYI)

    # sip for Python >= 3.8
    DEST_SIP38_DIR:=$(DEST_PYQT_DIR)/python_3.8
    $(DEST_SIP38_DIR):
	-$(Q)if [ ! -d "$(DEST_SIP38_DIR)" ] ; then mkdir -p 2>/dev/null $(DEST_SIP38_DIR) ; fi
    DEST_SIP38_PYDLL:=$(DEST_SIP38_DIR)/$(SIP_PYDLL_FNAME)
    DEST_SIP38_PYI:=$(DEST_SIP38_DIR)/$(SIP_PYI_FNAME)
    $(DEST_SIP38_PYDLL): $(wildcard $(SIP38_TREE)/lib/python*/PyQt5/$(SIP_PYDLL_FNAME)) | $(DEST_SIP38_DIR)
	$(Q)$(CP) $? $@
    $(DEST_SIP38_PYI): $(wildcard $(SIP38_TREE)/lib/python*/PyQt5/$(SIP_PYI_FNAME)) | $(DEST_SIP38_DIR)
	$(Q)$(CP) $? $@
    DEST_SIP += $(DEST_SIP38_PYDLL) $(DEST_SIP38_PYI)
  else
    # sip for Python 2.7
    DEST_SIP27_DIR:=$(DEST_PYQT_DIR)
    DEST_SIP27_PYDLL:=$(DEST_SIP27_DIR)/$(SIP_PYDLL_FNAME)
    DEST_SIP27_PYI:=$(DEST_SIP27_DIR)/$(SIP_PYI_FNAME)
    $(DEST_SIP27_PYDLL): $(wildcard $(SIP27_TREE)/lib/python*/PyQt5/$(SIP_PYDLL_FNAME)) | $(DEST_SIP27_DIR)
	$(Q)$(CP) $? $@
    $(DEST_SIP27_PYI): $(wildcard $(SIP27_TREE)/lib/python*/PyQt5/$(SIP_PYI_FNAME)) | $(DEST_SIP27_DIR)
	$(Q)$(CP) $? $@
    DEST_SIP += $(DEST_SIP27_PYDLL) $(DEST_SIP27_PYI)
  endif

  # And pick the right sip.so now (Python3 only; for Python2, we already put it in the right place)
  ifeq ($(PYTHON_VERSION_MAJOR),3)
    ifeq ($(shell test $(PYTHON_VERSION_MINOR) -gt 7; echo $$?),0) # ugh
      DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP38_PYDLL)
    else
      DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP34_PYDLL)
    endif
    $(DEST_PYQT_DIR)/$(SIP_PYDLL_FNAME): $(DEST_INSTALL_SIP_PYDLL)
	$(Q)$(CP) $? $@
	$(Q)chmod +w $@
    DEST_SIP += $(DEST_PYQT_DIR)/$(SIP_PYDLL_FNAME)
  endif
endif

pyqt: $(DEST_PYQT)
sip: $(DEST_SIP)

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

$(DEPLOY_LUMINA_MODEL_PY): python/lumina_model.py
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
	(cd $(F) && unzip ../../../out_of_tree/parsed_notifications.zip)
endif
	$(Q)touch $@

#----------------------------------------------------------------------
# Create directories in the first phase of makefile parsing.
DIRLIST += $(DEPLOY_LIBDIR)
DIRLIST += $(DEPLOY_PYDIR)
DIRLIST += $(ST_PARSED_HEADERS)
DIRLIST += $(ST_PYW)
DIRLIST += $(ST_SDK)
DIRLIST += $(ST_SWIG)
DIRLIST += $(ST_WRAP)
$(foreach d,$(sort $(DIRLIST)),$(if $(wildcard $(d)),,$(shell mkdir -p $(d))))

#----------------------------------------------------------------------
# obj/.../idasdk/*.h[pp]
# NOTE: Because we have the following sequence in hexrays.hpp:
#  - definition of template "template <class T> struct ivl_tpl"
#  - instantiation of template into "typedef ivl_tpl<uval_t> uval_ivl_t;"
#  - subclassing of "uval_ivl_t": "struct ivl_t : public uval_ivl_t",
# we are in trouble in our hexrays.i file, because by the time SWiG
# processes "struct ivl_t", it won't have properly instantiated the
# template, leading to the IDAPython proxy class "ivl_t" not subclassing
# "uval_ivl_t". Therefore, we have to split the hexrays.hpp header file
# into two: one that defines the template, and one that instantiates it.
# This way, we can '%import "hexrays_templates.hpp"', then do the SWiG
# template incantation, and finally '%include "hexrays_notemplates.hpp"'
# to actually generate wrappers.
ifeq ($(OUT_OF_TREE_BUILD),)
$(ST_SDK)/%.h: $(IDA_INCLUDE)/%.h ../../etc/sdk/filter_src.pl tools/preprocess_sdk_header.py
	$(QUPDATE_SDK) perl ../../etc/sdk/filter_src.pl $< - | $(PYTHON) tools/preprocess_sdk_header.py --input - --output $@ --metadata $@.metadata
$(ST_SDK)/%.hpp: $(IDA_INCLUDE)/%.hpp ../../etc/sdk/filter_src.pl tools/preprocess_sdk_header.py
	$(QUPDATE_SDK) perl ../../etc/sdk/filter_src.pl $< - | $(PYTHON) tools/preprocess_sdk_header.py --input - --output $@ --metadata $@.metadata
else
$(ST_SDK)/%.h: $(IDA_INCLUDE)/%.h tools/preprocess_sdk_header.py
	$(QUPDATE_SDK) $(PYTHON) tools/preprocess_sdk_header.py --input $< --output $@ --metadata $@.metadata
$(ST_SDK)/%.hpp: $(IDA_INCLUDE)/%.hpp tools/preprocess_sdk_header.py
	$(QUPDATE_SDK) $(PYTHON) tools/preprocess_sdk_header.py --input $< --output $@ --metadata $@.metadata
endif
HEXRAYS_HPP_SPLIT_DIR:=$(ST_SDK)

$(HEXRAYS_HPP_SPLIT_DIR)/hexrays_notemplates.hpp: $(ST_SDK)/hexrays.hpp tools/split_hexrays_templates.py
	$(QSPLIT_HEXRAYS_TEMPLATES)$(PYTHON) tools/split_hexrays_templates.py \
	--input $< \
	--out-templates $(HEXRAYS_HPP_SPLIT_DIR)/hexrays_templates.hpp \
	--out-body=$(HEXRAYS_HPP_SPLIT_DIR)/hexrays_notemplates.hpp
SWIGFLAGS += -I$(HEXRAYS_HPP_SPLIT_DIR)

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
                -c IDP_Hooks \
                -x $(ST_PARSED_HEADERS) \
                -m hookgenIDP \
                -q "processor_t::"
$(ST_PYW)/py_idp_idbhooks.hpp: pywraps/py_idp_idbhooks.hpp \
        $(I)idp.hpp \
        $(GENHOOKS)recipe_idbhooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -c IDB_Hooks \
                -x $(ST_PARSED_HEADERS) \
                -m hookgenIDB \
                -q "idb_event::"
$(ST_PYW)/py_dbg.hpp: pywraps/py_dbg.hpp \
        $(I)dbg.hpp \
        $(GENHOOKS)recipe_dbghooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -c DBG_Hooks \
                -x $(ST_PARSED_HEADERS) \
                -m hookgenDBG \
                -q "dbg_notification_t::"
$(ST_PYW)/py_kernwin.hpp: pywraps/py_kernwin.hpp \
        $(I)kernwin.hpp \
        $(GENHOOKS)recipe_uihooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -c UI_Hooks \
                -x $(ST_PARSED_HEADERS) \
	        -q "ui_notification_t::" \
                -m hookgenUI
$(ST_PYW)/py_kernwin_viewhooks.hpp: pywraps/py_kernwin_viewhooks.hpp \
        $(I)kernwin.hpp \
        $(GENHOOKS)recipe_viewhooks.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -c View_Hooks \
                -x $(ST_PARSED_HEADERS) \
                -q "view_notification_t::" \
                -m hookgenVIEW
$(ST_PYW)/py_hexrays_hooks.hpp: pywraps/py_hexrays_hooks.hpp \
        $(HEXRAYS_HPP_SPLIT_DIR)/hexrays_notemplates.hpp \
        $(GENHOOKS)recipe_hexrays.py \
        $(GENHOOKS)genhooks.py $(PARSED_HEADERS_MARKER) $(MAKEFILE_DEP) | $(SDK_SOURCES)
	$(QGENHOOKS)$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
                -c Hexrays_Hooks \
                -x $(ST_PARSED_HEADERS) \
                -q "hexrays_event_t::" \
                -m hookgenHEXRAYS


#----------------------------------------------------------------------
CFLAGS += $(PYTHON_CFLAGS)
CC_DEFS += $(BC695_CC_DEF)
CC_DEFS += $(DEF_TYPE_TABLE)
CC_DEFS += $(WITH_HEXRAYS_DEF)
CC_DEFS += USE_STANDARD_FILE_FUNCTIONS
CC_DEFS += VER_MAJOR="7"
CC_DEFS += VER_MINOR="4"
CC_DEFS += VER_PATCH="0"
CC_DEFS += __EXPR_SRC
CC_INCP += $(F)
CC_INCP += $(ST_SWIG)
CC_INCP += ../../ldr/mach-o/h
CC_INCP += .

ifdef __UNIX__
  # suppress some warnings
  # see https://github.com/swig/swig/pull/801
  # FIXME: remove these once swig is fixed
  CC_WNO += -Wno-shadow
  CC_WNO += -Wno-unused-parameter
  # FIXME: these should be fixed and removed
  CC_WNO += -Wno-attributes
  CC_WNO += -Wno-delete-non-virtual-dtor
  CC_WNO += -Wno-deprecated-declarations
  CC_WNO += -Wno-format-nonliteral
  CC_WNO += -Wno-write-strings
  ifdef __MAC__
    # additional switches for clang
    CC_WNO += -Wno-deprecated-register
  endif
endif

# disable -pthread in CFLAGS
PTHR_SWITCH =

# disable -DNO_OBSOLETE_FUNCS in CFLAGS
NO_OBSOLETE_FUNCS =

#----------------------------------------------------------------------
ifdef TESTABLE_BUILD
  SWIGFLAGS+=-DTESTABLE_BUILD
endif

ST_SWIG_HEADER = $(ST_SWIG)/header.i
$(ST_SWIG)/header.i: tools/deploy/header.i.in tools/genswigheader.py $(ST_SDK_TARGETS)
	$(QGENSWIGHEADER)$(PYTHON) tools/genswigheader.py -i $< -o $@ -m $(subst $(space),$(comma),$(MODULES_NAMES)) -s $(ST_SDK)

ifdef __NT__
  PATCH_DIRECTORS_SCRIPT = tools/patch_directors_cc.py
endif

find-pywraps-deps = $(wildcard pywraps/py_$(subst .i,,$(notdir $(1)))*.hpp) $(wildcard pywraps/py_$(subst .i,,$(notdir $(1)))*.py)
find-pydoc-patches-deps = $(wildcard tools/inject_pydoc/$(1).py)
find-patch-codegen-deps = $(wildcard tools/patch_codegen/*$(1)*.py)

ADDITIONAL_PYWRAP_DEP_idp=$(ST_PYW)/py_idp.py
$(ST_PYW)/py_idp.py: pywraps/py_idp.py.in tools/inject_plfm.py $(ST_SDK)/idp.hpp
	$(QINJECT_PLFM)$(PYTHON) tools/inject_plfm.py -i $< -o $@ -d $(ST_SDK)/idp.hpp

ADDITIONAL_PYWRAP_DEP_idaapi=$(ST_PYW)/py_idaapi.hpp
$(ST_PYW)/py_idaapi.hpp: pywraps/py_idaapi.hpp.in tools/inject_base_hooks_flags.py pywraps.hpp
	$(QINJECT_BASE_HOOKS_FLAGS)$(PYTHON) tools/inject_base_hooks_flags.py -i $< -o $@ -f pywraps.hpp


# Some .i files depend on some other .i files in order to be parseable by SWiG
# (e.g., segregs.i imports range.i). Declare the list of such dependencies here
# so they will be picked by the auto-generated rules.
SWIG_IFACE_bytes=range
SWIG_IFACE_dbg=idd
SWIG_IFACE_frame=range
SWIG_IFACE_funcs=range
SWIG_IFACE_gdl=range
SWIG_IFACE_hexrays=pro typeinf xref
SWIG_IFACE_idd=range
SWIG_IFACE_idp=bitrange
SWIG_IFACE_segment=range
SWIG_IFACE_segregs=range
SWIG_IFACE_typeinf=idp
SWIG_IFACE_tryblks=range
# ifdef TESTABLE_BUILD
# SWIG_IFACE_kernwin=dirtree
# endif

MODULE_LIFECYCLE_hexrays=--lifecycle-aware
MODULE_LIFECYCLE_bytes=--lifecycle-aware
MODULE_LIFECYCLE_idaapi=--lifecycle-aware

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
    $(DEPLOY_PYDIR)/ida_$(1).py: $(ST_WRAP)/$(1).cpp $(PARSED_HEADERS_MARKER) $(call find-pydoc-patches-deps,$(1)) $(call find-patch-codegen-deps,$(1)) | tools/inject_pydoc.py tools/wrapper_utils.py
	$(QINJECT_PYDOC)$(PYTHON) tools/inject_pydoc.py \
                --xml-doc-directory $(ST_PARSED_HEADERS) \
                --module $(1) \
                --input $(ST_WRAP)/ida_$(1).py \
                --interface $(ST_SWIG)/$(1).i \
                --cpp-wrapper $(ST_WRAP)/$(1).cpp \
                --output $$@ \
                --epydoc-injections $(ST_WRAP)/ida_$(1).epydoc_injection \
                --verbose > $(ST_WRAP)/ida_$(1).pydoc_injection 2>&1

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

    # creating obj/x86_linux_gcc/wrappers/X.cpp and friends
    # 1. SWIG generates x.cpp.in1, x.h and x.py from swig/x.i
    # 2. patch_const.py generates x.cpp.in2 from x.cpp.in1
    # 3. patch_codegen.py generates x.cpp from x.cpp.in2
    # 4. patch_h_codegen.py patches x.h in place
    # 5. patch_python_codegen.py patches ida_x.py in place using helpers in tools/patch_codegen
    # 6. on windows, patch_directors_cc.py patches x.h in place again
    $(ST_WRAP)/$(1).cpp: $(ST_SWIG)/$(1).i tools/patch_codegen.py tools/patch_python_codegen.py $(PATCH_DIRECTORS_SCRIPT) $(PARSED_HEADERS_MARKER) tools/chkapi.py tools/wrapper_utils.py
	$(QSWIG)$(SWIG) $(addprefix -D,$(WITH_HEXRAYS_DEF)) -python $(_SWIGPY3FLAG) -threads -c++ -shadow \
          -D__GNUC__ -DSWIG_PYTHON_LEGACY_BOOL=1 $(SWIGFLAGS) $(addprefix -D,$(DEF64)) -I$(ST_SWIG) \
          -outdir $(ST_WRAP) -o $$@.in1 -oh $(ST_WRAP)/$(1).h -I$(ST_SDK) -DIDAPYTHON_MODULE_$(1)=1 $$<
	$(call PATCH_CONST,$(ST_WRAP)/$(1).cpp.in1,$(ST_WRAP)/$(1).cpp.in2)
	$(QPATCH_CODEGEN)$(PYTHON) tools/patch_codegen.py \
                --input $(ST_WRAP)/$(1).cpp.in2 \
	        --output $(ST_WRAP)/$(1).cpp \
                --module $(1) \
                --xml-doc-directory $(ST_PARSED_HEADERS) \
                --patches tools/patch_codegen/$(1).py \
		--batch-patches tools/patch_codegen/$(1)_batch.py
	$(QPATCH_H_CODEGEN)$(PYTHON) tools/patch_h_codegen.py \
                --file $(ST_WRAP)/$(1).h \
                --module $(1) \
                --patches tools/patch_codegen/$(1)_h.py
	$(QPATCH_PYTHON_CODEGEN)$(PYTHON) tools/patch_python_codegen.py \
                --file $(ST_WRAP)/ida_$(1).py \
                --module $(1) \
                --patches tools/patch_codegen/ida_$(1).py
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
  # warning C4647: behavior change: __is_pod(type) has different value in previous versions
  # warning C4700: uninitialized local variable 'c_result' used
  # warning C4706: assignment within conditional expression
  $(X_O): CFLAGS += /wd4296 /wd4647 /wd4700 /wd4706
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
_IDA_X_SO = $(addprefix $(F)_ida_,$(addsuffix $(PYDLL_EXT),$(MODULES_NAMES)))
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
$(_IDA_X_SO): LDFLAGS += $(PYTHON_LDFLAGS) $(PYTHON_LDFLAGS_RPATH_MODULE) $(OUTMAP)$(F)$(@F).map
$(F)_ida_%$(PYDLL_EXT): $(F)%$(O) $(MODULE) $(IDAPYTHON_IMPLIB_DEF) $(IDAPYSWITCH_MODULE_DEP)
	$(call link_dll, $<, $(LINKIDA))
ifdef __NT__
	$(Q)$(RM) $(@:$(PYDLL_EXT)=.exp) $(@:$(PYDLL_EXT)=.lib)
endif

# ../../bin/x64_linux_gcc/python/2/ida_32/_ida_X.so
$(DEPLOY_LIBDIR)/_ida_%$(PYDLL_EXT): $(F)_ida_%$(PYDLL_EXT)
	$(Q)$(CP) $< $@
ifdef __LINUX__
  ifndef __CODE_CHECKER__
    ifeq ($(PYTHON_VERSION_MAJOR),3)
	$(Q)$(POSTACTION_IDA_X_SO) $@
    endif
  endif
endif

#----------------------------------------------------------------------
ifdef TESTABLE_BUILD
API_CONTENTS = api_contents$(PYTHON_VERSION_MAJOR).txt
else
API_CONTENTS = release_api_contents$(PYTHON_VERSION_MAJOR).txt
endif
ST_API_CONTENTS = $(F)$(API_CONTENTS)
.PRECIOUS: $(ST_API_CONTENTS)

api_contents: $(ST_API_CONTENTS)
$(ST_API_CONTENTS): $(ALL_ST_WRAP_CPP)
	$(QCHKAPI)$(PYTHON) tools/chkapi.py $(WITH_HEXRAYS_CHKAPI) -i $(subst $(space),$(comma),$(ALL_ST_WRAP_CPP)) -p $(subst $(space),$(comma),$(ALL_ST_WRAP_PY)) -r $(ST_API_CONTENTS)
ifeq ($(OUT_OF_TREE_BUILD),)
  ifdef CMP_API # turn off comparison when bw-compat is off, or api_contents will differ
	$(Q)(diff -w $(API_CONTENTS) $(ST_API_CONTENTS)) > /dev/null || \
          (echo "API CONTENTS CHANGED! update $(API_CONTENTS) or fix the API" && \
           echo "(New API: $(ST_API_CONTENTS)) ***" && \
           (diff -U 1 -w $(API_CONTENTS) $(ST_API_CONTENTS) && false))
  endif
endif

#----------------------------------------------------------------------
# Check that doc injection is stable
ifdef TESTABLE_BUILD
PYDOC_INJECTIONS = pydoc_injections$(PYTHON_VERSION_MAJOR).txt
else
PYDOC_INJECTIONS = release_pydoc_injections$(PYTHON_VERSION_MAJOR).txt
endif
ST_PYDOC_INJECTIONS = $(F)$(PYDOC_INJECTIONS)
.PRECIOUS: $(ST_PYDOC_INJECTIONS)

ifdef __EA64__
  DUMPDOC_IS_64:=True
else
  DUMPDOC_IS_64:=False
endif

PYDOC_INJECTIONS_IDAT_CMD=$(USE_PYTHON2_ENVVAR) $(IDAT_CMD) $(BATCH_SWITCH) "-OIDAPython:AUTOIMPORT_COMPAT_IDA695=NO" -S"$< $@ $(ST_WRAP) $(DUMPDOC_IS_64)" -t -L$(F)dumpdoc.log >/dev/null
pydoc_injections: $(ST_PYDOC_INJECTIONS)
$(ST_PYDOC_INJECTIONS): tools/dumpdoc.py $(IDAPYTHON_MODULES) $(PYTHON_BINARY_MODULES)
ifeq ($(or $(__CODE_CHECKER__),$(NO_CMP_API),$(__ASAN__)),)
	$(QPYDOC_INJECTIONS)$(PYDOC_INJECTIONS_IDAT_CMD) || \
	 (echo "Command \"$(PYDOC_INJECTIONS_IDAT_CMD)\" failed. Check \"$(F)dumpdoc.log\" for details." && false)
	$(Q)(diff -w $(PYDOC_INJECTIONS) $(ST_PYDOC_INJECTIONS)) > /dev/null || \
          (echo "PYDOC INJECTION CHANGED! update $(PYDOC_INJECTIONS) or fix .. what needs fixing" && \
           echo "(New API: $(ST_PYDOC_INJECTIONS)) ***" && \
           (diff -U 1 -w $(PYDOC_INJECTIONS) $(ST_PYDOC_INJECTIONS) && false))
else
	$(Q)touch $@
endif

#----------------------------------------------------------------------
DOCS_MODULES=$(foreach mod,$(MODULES_NAMES),ida_$(mod))
tools/docs/hrdoc.cfg: tools/docs/hrdoc.cfg.in
	sed s/%IDA_MODULES%/"$(DOCS_MODULES)"/ < $^ > $@

# the html files are produced in docs\hr-html directory
docs:   tools/docs/hrdoc.py tools/docs/hrdoc.cfg tools/docs/hrdoc.css
ifndef __NT__
	$(IDAT_CMD) -Stools/docs/hrdoc.py -t > /dev/null
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
	$(Q)$(IDAT_CMD) $(BATCH_SWITCH) -S"test_idc.py $^" -t -L$(F)idctest.log >/dev/null || \
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
	(cd $(F) && zip -r ../../../$(PUBTREE_DIR)/out_of_tree/parsed_notifications.zip parsed_notifications)
endif

#----------------------------------------------------------------------
IDAPYSWITCH_OBJS += $(F)idapyswitch$(O)
ifdef __NT__
  ifneq ($(OUT_OF_TREE_BUILD),)
     # SDK provides only MT libraries
     $(F)idapyswitch$(O): RUNTIME_LIBSW=/MT
  else
    ifndef NDEBUG
      $(F)idapyswitch$(O): CFLAGS := $(filter-out /U_DEBUG,$(CFLAGS))
    endif
  endif
endif
$(R)idapyswitch$(B): $(call dumb_target, pro, $(IDAPYSWITCH_OBJS))

#----------------------------------------------------------------------
# the 'echo_modules' target must be called explicitly
# Note: used by ida/build/pkgbin.py
echo_modules:
	@echo $(MODULES_NAMES)

#----------------------------------------------------------------------
clean::
	rm -rf obj/

$(MODULE): LDFLAGS += $(PYTHON_LDFLAGS) $(PYTHON_LDFLAGS_RPATH_MAIN)

# MAKEDEP dependency list ------------------
$(F)idapyswitch$(O): $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp            \
                  $(I)config.hpp $(I)diskio.hpp $(I)entry.hpp $(I)err.h     \
                  $(I)exehdr.h $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp       \
                  $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
                  $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
                  $(I)netnode.hpp $(I)network.hpp $(I)offset.hpp $(I)pro.h  \
                  $(I)prodir.h $(I)range.hpp $(I)segment.hpp                \
                  $(I)segregs.hpp $(I)ua.hpp $(I)xref.hpp                   \
                  ../../ldr/ar/aixar.hpp ../../ldr/ar/ar.hpp                \
                  ../../ldr/ar/arcmn.cpp ../../ldr/elf/../idaldr.h          \
                  ../../ldr/elf/elf.h ../../ldr/elf/elfbase.h               \
                  ../../ldr/elf/elfr_arm.h ../../ldr/elf/elfr_ia64.h        \
                  ../../ldr/elf/elfr_mips.h ../../ldr/elf/elfr_ppc.h        \
                  ../../ldr/elf/reader.cpp ../../ldr/mach-o/../ar/ar.hpp    \
                  ../../ldr/mach-o/../idaldr.h ../../ldr/mach-o/base.cpp    \
                  ../../ldr/mach-o/common.cpp ../../ldr/mach-o/common.h     \
                  ../../ldr/mach-o/h/architecture/byte_order.h              \
                  ../../ldr/mach-o/h/arm/_types.h                           \
                  ../../ldr/mach-o/h/i386/_types.h                          \
                  ../../ldr/mach-o/h/i386/eflags.h                          \
                  ../../ldr/mach-o/h/libkern/OSByteOrder.h                  \
                  ../../ldr/mach-o/h/libkern/i386/OSByteOrder.h             \
                  ../../ldr/mach-o/h/libkern/i386/_OSByteOrder.h            \
                  ../../ldr/mach-o/h/libkern/machine/OSByteOrder.h          \
                  ../../ldr/mach-o/h/mach-o/arm/reloc.h                     \
                  ../../ldr/mach-o/h/mach-o/arm64/reloc.h                   \
                  ../../ldr/mach-o/h/mach-o/fat.h                           \
                  ../../ldr/mach-o/h/mach-o/hppa/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/i860/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/loader.h                        \
                  ../../ldr/mach-o/h/mach-o/m88k/reloc.h                    \
                  ../../ldr/mach-o/h/mach-o/nlist.h                         \
                  ../../ldr/mach-o/h/mach-o/ppc/reloc.h                     \
                  ../../ldr/mach-o/h/mach-o/reloc.h                         \
                  ../../ldr/mach-o/h/mach-o/sparc/reloc.h                   \
                  ../../ldr/mach-o/h/mach-o/stab.h                          \
                  ../../ldr/mach-o/h/mach-o/x86_64/reloc.h                  \
                  ../../ldr/mach-o/h/mach/arm/_structs.h                    \
                  ../../ldr/mach-o/h/mach/arm/boolean.h                     \
                  ../../ldr/mach-o/h/mach/arm/thread_state.h                \
                  ../../ldr/mach-o/h/mach/arm/thread_status.h               \
                  ../../ldr/mach-o/h/mach/arm/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/boolean.h                         \
                  ../../ldr/mach-o/h/mach/i386/_structs.h                   \
                  ../../ldr/mach-o/h/mach/i386/boolean.h                    \
                  ../../ldr/mach-o/h/mach/i386/fp_reg.h                     \
                  ../../ldr/mach-o/h/mach/i386/kern_return.h                \
                  ../../ldr/mach-o/h/mach/i386/thread_state.h               \
                  ../../ldr/mach-o/h/mach/i386/thread_status.h              \
                  ../../ldr/mach-o/h/mach/i386/vm_param.h                   \
                  ../../ldr/mach-o/h/mach/i386/vm_types.h                   \
                  ../../ldr/mach-o/h/mach/kern_return.h                     \
                  ../../ldr/mach-o/h/mach/kmod.h                            \
                  ../../ldr/mach-o/h/mach/machine.h                         \
                  ../../ldr/mach-o/h/mach/machine/boolean.h                 \
                  ../../ldr/mach-o/h/mach/machine/kern_return.h             \
                  ../../ldr/mach-o/h/mach/machine/thread_status.h           \
                  ../../ldr/mach-o/h/mach/machine/vm_types.h                \
                  ../../ldr/mach-o/h/mach/message.h                         \
                  ../../ldr/mach-o/h/mach/port.h                            \
                  ../../ldr/mach-o/h/mach/ppc/_structs.h                    \
                  ../../ldr/mach-o/h/mach/ppc/boolean.h                     \
                  ../../ldr/mach-o/h/mach/ppc/kern_return.h                 \
                  ../../ldr/mach-o/h/mach/ppc/thread_status.h               \
                  ../../ldr/mach-o/h/mach/ppc/vm_param.h                    \
                  ../../ldr/mach-o/h/mach/ppc/vm_types.h                    \
                  ../../ldr/mach-o/h/mach/vm_prot.h                         \
                  ../../ldr/mach-o/h/mach/vm_types.h                        \
                  ../../ldr/mach-o/h/ppc/_types.h                           \
                  ../../ldr/mach-o/h/sys/_posix_availability.h              \
                  ../../ldr/mach-o/h/sys/_symbol_aliasing.h                 \
                  ../../ldr/mach-o/h/sys/cdefs.h                            \
                  ../../ldr/mach-o/macho_node.h ../../ldr/pe/../idaldr.h    \
                  ../../ldr/pe/common.cpp ../../ldr/pe/common.h             \
                  ../../ldr/pe/pe.h idapyswitch.cpp idapyswitch_linux.cpp   \
                  idapyswitch_mac.cpp idapyswitch_win.cpp
$(F)idapython$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp            \
                  $(I)diskio.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h          \
                  $(I)funcs.hpp $(I)gdl.hpp $(I)graph.hpp $(I)ida.hpp       \
                  $(I)ida_highlighter.hpp $(I)idd.hpp $(I)idp.hpp           \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
                  $(I)pro.h $(I)range.hpp $(I)segment.hpp $(I)typeinf.hpp   \
                  $(I)ua.hpp $(I)xref.hpp extapi.cpp extapi.hpp idapy.hpp   \
                  idapython.cpp pywraps.cpp pywraps.hpp
