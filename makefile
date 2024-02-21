
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
.PHONY: configs modules pyfiles deployed_modules idapython_modules api_check api_contents pyqt sip bins public_tree test_idc docs tbd examples_index test_pywraps
all: configs modules pyfiles deployed_modules idapython_modules api_check api_contents pyqt sip bins examples_index test_pywraps # public_tree test_idc docs

ifeq ($(OUT_OF_TREE_BUILD),)
  IDAPYSWITCH:=$(R)idapyswitch$(B)
  IDAPYSWITCH_DEP:=$(IDAPYSWITCH)
  IDAPYSWITCH_PATH:=$(IDAPYSWITCH)
  TEST_PYWRAPS_RESULT_FNAME:=test_pywraps$(ADRSIZE).txt
  ifdef __NT__
    # On Windows, we cannot afford to use `test_pywraps` during a
    # debug build: since `test_pywraps.exe` relies on `python3.dll`
    # (and corresponding headers), Python will force optimized
    # iterators resulting in errors such as:
    #    dumb.obj : error LNK2038: mismatch detected for '_ITERATOR_DEBUG_LEVEL': value '2' doesn't match value '0' in test_pywraps.obj

    # And as it turns out, doing it during an optimized build
    # is problematic as well, because it'll typically not find
    # `python3.dll`. I tried to support it by patching `PATH`,
    # but now we're dealing with cygwin confusion...
    ifdef NDEBUG
      HAS_TEST_PYWRAPS:=1
      PYTHON_ROOT_CYGPATH:=$(shell cygpath $(PYTHON_ROOT))
      TEST_PYWRAPS_ENV:=PATH="$$PATH:$(PYTHON_ROOT_CYGPATH)"
    endif
  else
    HAS_TEST_PYWRAPS:=1
  endif
  ifeq ($(HAS_TEST_PYWRAPS),1)
    TEST_PYWRAPS:=$(F)$(TEST_PYWRAPS_RESULT_FNAME).marker
  endif
  BINS += $(IDAPYSWITCH)
else
  ifdef __NT__
    IDAPYSWITCH_PATH:=$(IDA_INSTALL)/idapyswitch.exe
  else
    IDAPYSWITCH_PATH:=$(IDA_INSTALL)/idapyswitch
  endif
endif

BINS += $(IDAPYSWITCH_DEP)
bins: $(BINS)

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
ifdef __EA64__
  MODULE_NAME_STEM:=idapython3_
else
  MODULE_NAME_STEM:=idapython3
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
    IDAPYSWITCH_MODULE_DEP := $(IDAPYSWITCH_DEP)
    ifndef __CODE_CHECKER__
      # this is for idapython[64].so
      POSTACTION=$(Q)$(IDAPYSWITCH_PATH) --split-debug-and-expand-libpython3-dtneeded-room $(MODULE)
      # and this for _ida_*.so
      POSTACTION_IDA_X_SO=$(Q)$(IDAPYSWITCH_PATH) --split-debug-and-expand-libpython3-dtneeded-room
    endif
  endif
endif

#----------------------------------------------------------------------
ifdef __MAC__
  # use  a stub .tbd library to link against, see tbd.md
  TBD_FILE = libpython$(PYTHON_VERSION_MAJOR).tbd
  # note: this path must be compatible with -L$(R) -lpython3 in pyplg.mak
  TBD_MODULE_DEP = $(R)$(TBD_FILE)
  # idapyswitch must be told that we're working with Python2
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
$(MODULE): $(PYTHON_OBJS) $(IDAPYSWITCH_MODULE_DEP) $(TBD_MODULE_DEP)
ifdef __NT__
  $(MODULE): OUTDLL = /DLL /NOEXP
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
  QDUMPAPI = @echo $(call qcolor,dumpapi) && #
  QDEPLOY = @echo $(call qcolor,deploy) $$< && #
  QGENDOXYCFG = @echo $(call qcolor,gendoxycfg) $@ && #
  QGENHOOKS = @echo $(call qcolor,genhooks) $< && #
  QGENIDAAPI = @echo $(call qcolor,genidaapi) $< && #
  QGENSWIGHEADER = @echo $(call qcolor,genswigheader) $< && #
  QINJECT_PYDOC = @echo $(call qcolor,inject_pydoc) $$< && #
  QPATCH_CODEGEN = @echo $(call qcolor,patch_codegen) $$< && #
  QPATCH_H_CODEGEN = @echo $(call qcolor,patch_h_codegen) $$< && #
  QPATCH_PYTHON_CODEGEN = @echo $(call qcolor,patch_python_codegen) $$< && #
  QSWIG = @echo $(call qcolor,swig) $$< && #
  QUPDATE_SDK = @echo $(call qcolor,update_sdk) $< && #
  QSPLIT_HEXRAYS_TEMPLATES = @echo $(call qcolor,split_hexrays_templates) $< && #
  QGEN_EXAMPLES_INDEX = @echo $(call qcolor,gen_examples_index) $@ && #
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
DEPLOY_IDAAPI_PY=$(DEPLOY_PYDIR)/idaapi.py
DEPLOY_IDADEX_PY=$(DEPLOY_PYDIR)/idadex.py
ifdef TESTABLE_BUILD
  DEPLOY_LUMINA_MODEL_PY=$(DEPLOY_PYDIR)/lumina_model.py
endif
ifeq ($(OUT_OF_TREE_BUILD),)
  TEST_IDC=test_idc
  IDAT_PATH?=$(R)/idat
else
  IDAT_PATH?=$(IDA_INSTALL)/idat
endif

ifeq ($(OUT_OF_TREE_BUILD),)
  IDAT_CMD=TVHEADLESS=1 "$(IDAT_PATH)$(SUFF64)"
else
  IDAT_CMD=TVHEADLESS=1 IDAPYTHON_DYNLOAD_BASE=$(R) "$(IDAT_PATH)$(SUFF64)"
endif

# envvar HAS_HEXRAYS must have been set by build.py if needed
ifeq ($(OUT_OF_TREE_BUILD),)
  HAS_HEXRAYS=1 # force hexrays bindings
endif

# determine SDK_SOURCES
ifeq ($(OUT_OF_TREE_BUILD),)
  include ../../etc/sdk/sdk_files.mak
  SDK_SOURCES=$(sort $(foreach v,$(SDK_FILES),$(if $(findstring include/,$(v)),$(addprefix $(IDA_INCLUDE)/,$(notdir $(v))))))
  ifneq ($(HAS_HEXRAYS),)
    SDK_SOURCES+=$(IDA_INCLUDE)/hexrays.hpp
  endif
  SDK_SOURCES+=$(IDA_INCLUDE)/lumina.hpp
else
  SDK_SOURCES=$(wildcard $(IDA_INCLUDE)/*.h) $(wildcard $(IDA_INCLUDE)/*.hpp)
endif
ST_SDK_TARGETS = $(SDK_SOURCES:$(IDA_INCLUDE)/%=$(ST_SDK)/%)

_SWIGPY3FLAG := -py3 -py3-stable-abi -DPY3=1
CC_DEFS += PY3=1
CC_DEFS += Py_LIMITED_API=0x03040000 # we should make sure we use the same version as SWiG
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
  # Warning: adding an empty HEXRAYS_MODNAME will lead to idaapy trying to load
  # a module called ida_.
  MODULES_NAMES += $(HEXRAYS_MODNAME)
endif

ifeq ($(HAS_HEXRAYS),)
  NO_CMP_API := 1
endif

#----------------------------------------------------------------------
MODULES_NAMES += allins
MODULES_NAMES += auto
MODULES_NAMES += bitrange
MODULES_NAMES += bytes
MODULES_NAMES += dbg
MODULES_NAMES += diskio
MODULES_NAMES += dirtree
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
MODULES_NAMES += ieee
MODULES_NAMES += kernwin
MODULES_NAMES += lines
MODULES_NAMES += loader
ifdef TESTABLE_BUILD
  MODULES_NAMES += lumina
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
MODULES_NAMES += regfinder
MODULES_NAMES += search
MODULES_NAMES += segment
MODULES_NAMES += segregs
MODULES_NAMES += srclang
MODULES_NAMES += strlist
MODULES_NAMES += struct
MODULES_NAMES += tryblks
MODULES_NAMES += typeinf
MODULES_NAMES += ua
MODULES_NAMES += xref
ifndef NOTEAMS
  MODULES_NAMES += mergemod
  MODULES_NAMES += merge
endif

ALL_ST_WRAP_CPP = $(foreach mod,$(MODULES_NAMES),$(ST_WRAP)/$(mod).cpp)
ALL_ST_WRAP_PY = $(foreach mod,$(MODULES_NAMES),$(ST_WRAP)/ida_$(mod).py)
ALL_ST_WRAP_PY_FINAL = $(foreach mod,$(MODULES_NAMES),$(ST_WRAP)/ida_$(mod).py.final)
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
SWIGFLAGS=$(_SWIGFLAGS) -Itools/typemaps-supplement $(SWIG_INCLUDES) $(addprefix -D,$(DEF_TYPE_TABLE)) -DMISSED_BC695
ifdef NOTEAMS
  SWIGFLAGS += -DNOTEAMS
endif

pyfiles: $(DEPLOY_IDAUTILS_PY)  \
         $(DEPLOY_IDC_PY)       \
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

  # sip for Python [3.8, 3.9)
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

  # sip for Python [3.9, 3.10)
  DEST_SIP39_DIR:=$(DEST_PYQT_DIR)/python_3.9
  $(DEST_SIP39_DIR):
	-$(Q)if [ ! -d "$(DEST_SIP39_DIR)" ] ; then mkdir -p 2>/dev/null $(DEST_SIP39_DIR) ; fi
  DEST_SIP39_PYDLL:=$(DEST_SIP39_DIR)/$(SIP_PYDLL_FNAME)
  DEST_SIP39_PYI:=$(DEST_SIP39_DIR)/$(SIP_PYI_FNAME)
  $(DEST_SIP39_PYDLL): $(wildcard $(SIP39_TREE)/lib/python*/PyQt5/$(SIP_PYDLL_FNAME)) | $(DEST_SIP39_DIR)
	$(Q)$(CP) $? $@
  $(DEST_SIP39_PYI): $(wildcard $(SIP39_TREE)/lib/python*/PyQt5/$(SIP_PYI_FNAME)) | $(DEST_SIP39_DIR)
	$(Q)$(CP) $? $@
  DEST_SIP += $(DEST_SIP39_PYDLL) $(DEST_SIP39_PYI)

  # sip for Python [3.10, 3.11)
  DEST_SIP310_DIR:=$(DEST_PYQT_DIR)/python_3.10
  $(DEST_SIP310_DIR):
	-$(Q)if [ ! -d "$(DEST_SIP310_DIR)" ] ; then mkdir -p 2>/dev/null $(DEST_SIP310_DIR) ; fi
  DEST_SIP310_PYDLL:=$(DEST_SIP310_DIR)/$(SIP_PYDLL_FNAME)
  DEST_SIP310_PYI:=$(DEST_SIP310_DIR)/$(SIP_PYI_FNAME)
  $(DEST_SIP310_PYDLL): $(wildcard $(SIP310_TREE)/lib/python*/PyQt5/$(SIP_PYDLL_FNAME)) | $(DEST_SIP310_DIR)
	$(Q)$(CP) $? $@
  $(DEST_SIP310_PYI): $(wildcard $(SIP310_TREE)/lib/python*/PyQt5/$(SIP_PYI_FNAME)) | $(DEST_SIP310_DIR)
	$(Q)$(CP) $? $@
  DEST_SIP += $(DEST_SIP310_PYDLL) $(DEST_SIP310_PYI)

  # sip for Python [3.11, 3.12)
  DEST_SIP311_DIR:=$(DEST_PYQT_DIR)/python_3.11
  $(DEST_SIP311_DIR):
	-$(Q)if [ ! -d "$(DEST_SIP311_DIR)" ] ; then mkdir -p 2>/dev/null $(DEST_SIP311_DIR) ; fi
  DEST_SIP311_PYDLL:=$(DEST_SIP311_DIR)/$(SIP_PYDLL_FNAME)
  DEST_SIP311_PYI:=$(DEST_SIP311_DIR)/$(SIP_PYI_FNAME)
  $(DEST_SIP311_PYDLL): $(wildcard $(SIP311_TREE)/lib/python*/PyQt5/$(SIP_PYDLL_FNAME)) | $(DEST_SIP311_DIR)
	$(Q)$(CP) $? $@
  $(DEST_SIP311_PYI): $(wildcard $(SIP311_TREE)/lib/python*/PyQt5/$(SIP_PYI_FNAME)) | $(DEST_SIP311_DIR)
	$(Q)$(CP) $? $@
  DEST_SIP += $(DEST_SIP311_PYDLL) $(DEST_SIP311_PYI)

  # sip for Python [3.12, ...
  DEST_SIP312_DIR:=$(DEST_PYQT_DIR)/python_3.12
  $(DEST_SIP312_DIR):
	-$(Q)if [ ! -d "$(DEST_SIP312_DIR)" ] ; then mkdir -p 2>/dev/null $(DEST_SIP312_DIR) ; fi
  DEST_SIP312_PYDLL:=$(DEST_SIP312_DIR)/$(SIP_PYDLL_FNAME)
  DEST_SIP312_PYI:=$(DEST_SIP312_DIR)/$(SIP_PYI_FNAME)
  $(DEST_SIP312_PYDLL): $(wildcard $(SIP312_TREE)/lib/python*/PyQt5/$(SIP_PYDLL_FNAME)) | $(DEST_SIP312_DIR)
	$(Q)$(CP) $? $@
  $(DEST_SIP312_PYI): $(wildcard $(SIP312_TREE)/lib/python*/PyQt5/$(SIP_PYI_FNAME)) | $(DEST_SIP312_DIR)
	$(Q)$(CP) $? $@
  DEST_SIP += $(DEST_SIP312_PYDLL) $(DEST_SIP312_PYI)

  # And pick the right sip.so now (Python3 only; for Python2, we already put it in the right place)
  ifeq ($(shell test $(PYTHON_VERSION_MINOR) -gt 11; echo $$?),0) # ugh
    DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP312_PYDLL)
  else
    ifeq ($(shell test $(PYTHON_VERSION_MINOR) -gt 10; echo $$?),0) # ugh
      DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP311_PYDLL)
    else
      ifeq ($(shell test $(PYTHON_VERSION_MINOR) -gt 9; echo $$?),0) # ugh
        DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP310_PYDLL)
      else
        ifeq ($(shell test $(PYTHON_VERSION_MINOR) -gt 8; echo $$?),0) # ugh
          DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP39_PYDLL)
        else
          ifeq ($(shell test $(PYTHON_VERSION_MINOR) -gt 7; echo $$?),0) # ugh
            DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP38_PYDLL)
          else
            DEST_INSTALL_SIP_PYDLL:=$(DEST_SIP34_PYDLL)
          endif
        endif
      endif
    endif
  endif
  $(DEST_PYQT_DIR)/$(SIP_PYDLL_FNAME): $(DEST_INSTALL_SIP_PYDLL)
	$(Q)$(CP) $? $@
	$(Q)chmod +w $@
  DEST_SIP += $(DEST_PYQT_DIR)/$(SIP_PYDLL_FNAME)
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
	(cd $(F) && unzip ../../out_of_tree/parsed_notifications.zip)
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
CC_DEFS += MISSED_BC695
CC_DEFS += $(DEF_TYPE_TABLE)
CC_DEFS += $(WITH_HEXRAYS_DEF)
CC_DEFS += USE_STANDARD_FILE_FUNCTIONS
CC_DEFS += VER_MAJOR=$(IDAVER_MAJOR)
CC_DEFS += VER_MINOR=$(IDAVER_MINOR)
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

# Some .i files depend on some other .i files in order to be parseable by SWiG
# (e.g., segregs.i imports range.i). Declare the list of such dependencies here
# so they will be picked by the auto-generated rules.
SWIG_IFACE_bytes=range
SWIG_IFACE_dbg=idd
SWIG_IFACE_frame=range
SWIG_IFACE_funcs=range
SWIG_IFACE_gdl=range
SWIG_IFACE_graph=gdl
SWIG_IFACE_hexrays=pro typeinf xref gdl
SWIG_IFACE_idd=range
SWIG_IFACE_idp=bitrange
SWIG_IFACE_segment=range
SWIG_IFACE_segregs=range
SWIG_IFACE_typeinf=idp
SWIG_IFACE_tryblks=range

MODULE_LIFECYCLE_bytes=--lifecycle-aware
MODULE_LIFECYCLE_hexrays=--lifecycle-aware
MODULE_LIFECYCLE_idaapi=--lifecycle-aware
MODULE_LIFECYCLE_kernwin=--lifecycle-aware

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

    # ../../bin/x86_linux_gcc/python/ida_$(1).py
    $(DEPLOY_PYDIR)/ida_$(1).py: $(ST_WRAP)/ida_$(1).py.final
	$(Q)$(CP) $$< $$@

    # obj/x86_linux_gcc/wrappers/ida_X.py.final (note: dep. on .cpp. See note above.)
    $(ST_WRAP)/ida_$(1).py.final: $(ST_WRAP)/$(1).cpp tools/inject_pydoc.py $(PARSED_HEADERS_MARKER) $(call find-pydoc-patches-deps,$(1)) $(call find-patch-codegen-deps,$(1))
	$(QINJECT_PYDOC)$(PYTHON) tools/inject_pydoc.py \
                --xml-doc-directory $(ST_PARSED_HEADERS) \
                --module $(1) \
                --input $(ST_WRAP)/ida_$(1).py \
                --interface $(ST_SWIG)/$(1).i \
                --cpp-wrapper $(ST_WRAP)/$(1).cpp \
                --traces tools/collected_traces.txt \
                --cases tools/inject_pydoc_cases.txt \
                --output $$@ \
                --verbose > $(ST_WRAP)/ida_$(1).pydoc_injection

    # obj/x86_linux_gcc/swig/X.i
    $(ST_SWIG)/$(1).i: $(addprefix $(F),$(call find-pywraps-deps,$(1))) swig/$(1).i $(ST_SWIG_HEADER) $(SWIG_IFACE_$(1):%=$(ST_SWIG)/%.i) $(ST_SWIG_HEADER) tools/deploy.py $(PARSED_HEADERS_MARKER)
	$(QDEPLOY)$(PYTHON) tools/deploy.py \
                --pywraps $(ST_PYW) \
                --template $$(subst $(F),,$$@) \
                --output $$@ \
                --module $$(subst .i,,$$(notdir $$@)) \
                $(MODULE_LIFECYCLE_$(1)) \
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
$(X_O): pywraps.hpp
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
# Note: On Windows, IDAPython's python.lib must come *after* python3x.lib
#       in the linking command line, otherwise Python will misdetect
#       IDAPython's python.dll as the main "python" DLL, and IDAPython
#       will fail to load with the following error:
#         "Module use of python.dll conflicts with this version of Python."
#       To achieve this, we add IDAPython's python.lib to STDLIBS, which
#       is at the end of the link command.
#       See Python's dynload_win.c:GetPythonImport() for more details.
$(_IDA_X_SO): STDLIBS += $(LINKIDAPYTHON)
$(_IDA_X_SO): LDFLAGS += $(PYTHON_LDFLAGS) $(PYTHON_LDFLAGS_RPATH_MODULE) $(OUTMAP)$(F)$(@F).map
$(F)_ida_%$(PYDLL_EXT): $(F)%$(O) $(MODULE) $(IDAPYTHON_IMPLIB_DEF) $(IDAPYSWITCH_MODULE_DEP) $(TBD_MODULE_DEP)
	$(call link_dll, $<, $(LINKIDA))
ifdef __NT__
	$(Q)$(RM) $(@:$(PYDLL_EXT)=.exp) $(@:$(PYDLL_EXT)=.lib)
endif

# ../../bin/x64_linux_gcc/python/ida_32/_ida_X.so
$(DEPLOY_LIBDIR)/_ida_%$(PYDLL_EXT): $(F)_ida_%$(PYDLL_EXT)
	$(Q)$(CP) $< $@
ifdef __LINUX__
  ifndef __CODE_CHECKER__
	$(Q)$(POSTACTION_IDA_X_SO) $@
  endif
endif

#----------------------------------------------------------------------
ifdef TESTABLE_BUILD
  API_CONTENTS = api_contents$(EXTRASUF1).brief
else
  API_CONTENTS = api_contents$(EXTRASUF1).full
  API_CONTENTS_OPTS := --dump-doc
endif
ST_API_CONTENTS = $(F)$(API_CONTENTS)
ST_API_CONTENTS_SUCCESS = $(ST_API_CONTENTS).success
.PRECIOUS: $(ST_API_CONTENTS)

api_contents: $(ST_API_CONTENTS_SUCCESS)
ifeq ($(or $(__CODE_CHECKER__),$(NO_CMP_API),$(__ASAN__),$(IDAHOME),$(DEMO_OR_FREE)),)
$(ST_API_CONTENTS_SUCCESS): $(ALL_ST_WRAP_PY_FINAL) $(API_CONTENTS) tools/py_scanner.py
	$(QDUMPAPI)$(PYTHON) tools/py_scanner.py --dump-kind $(API_CONTENTS_OPTS) --paths $(subst $(space),$(comma),$(ALL_ST_WRAP_PY_FINAL)) > $(ST_API_CONTENTS)
  ifeq ($(OUT_OF_TREE_BUILD),)
	$(Q)((diff -w $(API_CONTENTS) $(ST_API_CONTENTS)) > /dev/null && touch $@) || \
          (echo "API CONTENTS CHANGED! update $(API_CONTENTS) or fix the API" && \
           echo "(New API: $(ST_API_CONTENTS)) ***" && \
           (diff -U 1 -w $(API_CONTENTS) $(ST_API_CONTENTS); true))
  else
	$(Q)touch $@
  endif
else
$(ST_API_CONTENTS_SUCCESS): $(ALL_ST_WRAP_PY_FINAL) tools/py_scanner.py
	$(Q)touch $@
endif

#-------------------------------------------------------------------------
ST_API_CHECK_SUCCESS := $(F)api_check.success
api_check: $(ST_API_CHECK_SUCCESS)
$(ST_API_CHECK_SUCCESS): $(ALL_ST_WRAP_CPP)
ifeq ($(or $(__CODE_CHECKER__),$(NO_CMP_API),$(__ASAN__),$(IDAHOME),$(DEMO_OR_FREE)),)
	$(QCHKAPI)$(PYTHON) tools/chkapi.py $(WITH_HEXRAYS_CHKAPI) -i $(subst $(space),$(comma),$(ALL_ST_WRAP_CPP)) -p $(subst $(space),$(comma),$(ALL_ST_WRAP_PY))
endif
	$(Q)touch $@

ifdef __EA64__
  DUMPDOC_IS_64:=True
else
  DUMPDOC_IS_64:=False
endif

#----------------------------------------------------------------------
DOCS_MODULES=$(foreach mod,$(MODULES_NAMES),ida_$(mod))
SORTED_DOCS_MODULES=$(sort $(DOCS_MODULES))
docs:   tools/docs/hrdoc.py tools/docs/hrdoc.css
ifndef __NT__
	$(IDAT_CMD) $(BATCH_SWITCH) -S"tools/docs/hrdoc.py -o docs/hr-html -m $(subst $(space),$(comma),$(SORTED_DOCS_MODULES)),idc,idautils -s idc,idautils -x ida_allins" -t > /dev/null
#	$(IDAT_CMD) $(BATCH_SWITCH) -S"tools/docs/hrdoc.py -o docs/hr-html -m ida_pro,ida_kernwin -s idc,idautils -x ida_allins" -t > /dev/null  # use this one for testing (faster)
else
	$(R)ida -Stools/docs/hrdoc.py -t
endif

# the demo version of ida does not have the -B command line option
ifeq ($(OUT_OF_TREE_BUILD),)
  ifndef DEMO_OR_FREE
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
PUBTREE_DIR=$(F)public_tree
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
TEST_PYWRAPS_OBJS += $(F)test_pywraps$(O)
TEST_PYWRAPS_DEPS := pywraps.cpp pywraps.hpp extapi.cpp extapi.hpp
$(F)test_pywraps$(O): $(PARSED_HEADERS_MARKER) $(TEST_PYWRAPS_DEPS)
ifdef __NT__
  ifneq ($(OUT_OF_TREE_BUILD),)
     # SDK provides only MT libraries
     $(F)test_pywraps$(O): RUNTIME_LIBSW=/MT
  endif
endif
$(R)test_pywraps$(B): $(call dumb_target, json idc unicode pro, $(TEST_PYWRAPS_OBJS)) $(PYTHON_LDFLAGS)

$(F)$(TEST_PYWRAPS_RESULT_FNAME).marker: $(R)test_pywraps$(B)
	$(Q)$(TEST_PYWRAPS_ENV) $(R)test_pywraps$(B) > $(F)$(TEST_PYWRAPS_RESULT_FNAME)
  ifeq ($(OUT_OF_TREE_BUILD),)
	$(Q)((diff -w $(TEST_PYWRAPS_RESULT_FNAME) $(F)$(TEST_PYWRAPS_RESULT_FNAME)) > /dev/null && touch $@) || \
          (echo "$(TEST_PYWRAPS_RESULT_FNAME) changed" && \
           (diff -U 1 -w $(TEST_PYWRAPS_RESULT_FNAME) $(F)$(TEST_PYWRAPS_RESULT_FNAME); true))
  else
	$(Q)touch $@
  endif

ifdef __CODE_CHECKER__
  test_pywraps: ;
else
test_pywraps: $(TEST_PYWRAPS)
endif

#----------------------------------------------------------------------
ifdef __MAC__
tbd: $(TBD_MODULE_DEP)
# copy the tbd library to idabin, and instruct idapyswitch to create the symlink to libpython
$(TBD_MODULE_DEP): $(TBD_FILE) $(IDAPYSWITCH_DEP)
	$(Q)$(CP) $< $@
	cd $(R) && $(IDAPYSWITCH_PATH) $(TBD_IDAPYSWITCH_ARGS) --force-path $(shell $(PYTHON)-config --prefix)/Python
else
tbd: ;
endif

#----------------------------------------------------------------------
# the 'echo_modules' target must be called explicitly
# Note: used by ida/build/pkgbin.py
echo_modules:
	@echo $(MODULES_NAMES)

#----------------------------------------------------------------------
clean::
	rm -rf obj/

ifdef __CODE_CHECKER__
  examples_index: ;
else
  EXAMPLES          := $(wildcard examples/**/*.py)
  GEN_EXAMPLES_TOOL := tools/gen_examples_index.py
  GEN_EXAMPLES_CFG  := tools/gen_examples_index.cfg

  ST_EXAMPLES_INDEX_HTML := $(F)examples/index.html
  ST_EXAMPLES_INDEX_MD   := $(F)examples/index.md

  define make-examples-index-rules

    $(eval EXAMPLES_INDEX    := examples/index.$(1))
    $(eval ST_EXAMPLES_INDEX := $(2))
    $(eval EXAMPLES_TEMPLATE := tools/examples_index_template.$(1))

    .PRECIOUS: $(ST_EXAMPLES_INDEX)

    $(eval EXAMPLES_INDEX_CMD := $(PYTHON) $(GEN_EXAMPLES_TOOL) write \
	-t $(EXAMPLES_TEMPLATE) \
	-e examples \
	-o $(ST_EXAMPLES_INDEX) \
	   )

    $(ST_EXAMPLES_INDEX): $(GEN_EXAMPLES_TOOL) $(GEN_EXAMPLES_CFG) \
                          $(EXAMPLES_TEMPLATE) $(EXAMPLES)
	-$(Q)if [ ! -d "$(F)examples" ] ; then mkdir -p 2>/dev/null $(F)examples ; fi
	$(QGEN_EXAMPLES_INDEX)$(EXAMPLES_INDEX_CMD) \
	  || echo FAILED: $(EXAMPLES_INDEX_CMD)
	$(Q)diff -w $(EXAMPLES_INDEX) $(ST_EXAMPLES_INDEX) > /dev/null \
	  || (echo "EXAMPLES INDEX CHANGED! update $(EXAMPLES_INDEX)" \
	   && echo "(New examples: $(ST_EXAMPLES_INDEX)) ***" \
	   && diff -U 1 -w $(EXAMPLES_INDEX) $(ST_EXAMPLES_INDEX) \
	   && false)
  endef

  $(eval $(call make-examples-index-rules,html,$(ST_EXAMPLES_INDEX_HTML)))
  $(eval $(call make-examples-index-rules,md,$(ST_EXAMPLES_INDEX_MD)))

  examples_index: $(ST_EXAMPLES_INDEX_HTML) $(ST_EXAMPLES_INDEX_MD)

endif

$(MODULE): LDFLAGS += $(PYTHON_LDFLAGS)

# MAKEDEP dependency list ------------------
$(F)idapyswitch$(O): $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp            \
                  $(I)config.hpp $(I)diskio.hpp $(I)entry.hpp $(I)err.h     \
                  $(I)exehdr.h $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp       \
                  $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)lzfse.h    \
                  $(I)lzvn_decode_base.h $(I)md5.h $(I)nalt.hpp             \
                  $(I)name.hpp $(I)netnode.hpp $(I)network.hpp              \
                  $(I)offset.hpp $(I)pro.h $(I)prodir.h $(I)range.hpp       \
                  $(I)segment.hpp $(I)segregs.hpp $(I)ua.hpp $(I)xref.hpp   \
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
                  ../../ldr/mach-o/h/libkern/arm/OSByteOrder.h              \
                  ../../ldr/mach-o/h/libkern/i386/OSByteOrder.h             \
                  ../../ldr/mach-o/h/libkern/i386/_OSByteOrder.h            \
                  ../../ldr/mach-o/h/libkern/machine/OSByteOrder.h          \
                  ../../ldr/mach-o/h/mach-o/arm/reloc.h                     \
                  ../../ldr/mach-o/h/mach-o/arm64/reloc.h                   \
                  ../../ldr/mach-o/h/mach-o/fat.h                           \
                  ../../ldr/mach-o/h/mach-o/fixup-chains.h                  \
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
                  ../../ldr/mach-o/h/mach/vm_prot.h                         \
                  ../../ldr/mach-o/h/mach/vm_types.h                        \
                  ../../ldr/mach-o/h/sys/_posix_availability.h              \
                  ../../ldr/mach-o/h/sys/_symbol_aliasing.h                 \
                  ../../ldr/mach-o/h/sys/cdefs.h                            \
                  ../../ldr/mach-o/macho_node.h                             \
                  ../../ldr/mach-o/strtab_reader_t.h                        \
                  ../../ldr/mach-o/uncompress.cpp ../../ldr/pe/../idaldr.h  \
                  ../../ldr/pe/common.cpp ../../ldr/pe/common.h             \
                  ../../ldr/pe/pe.h idapyswitch.cpp idapyswitch_linux.cpp   \
                  idapyswitch_mac.cpp idapyswitch_win.cpp
$(F)idapython$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp            \
                  $(I)diskio.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h          \
                  $(I)funcs.hpp $(I)gdl.hpp $(I)graph.hpp $(I)ida.hpp       \
                  $(I)ida_highlighter.hpp $(I)idd.hpp $(I)idp.hpp           \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lex.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
                  $(I)netnode.hpp $(I)parsejson.hpp $(I)pro.h               \
                  $(I)range.hpp $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp  \
                  $(I)xref.hpp extapi.hpp idapython.cpp pywraps.cpp         \
                  pywraps.hpp
$(F)test_pywraps$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp         \
                  $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
                  $(I)gdl.hpp $(I)graph.hpp $(I)ida.hpp $(I)idd.hpp         \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lex.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)name.hpp $(I)netnode.hpp $(I)parsejson.hpp $(I)pro.h  \
                  $(I)range.hpp $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp  \
                  $(I)xref.hpp extapi.cpp extapi.hpp pywraps.cpp            \
                  pywraps.hpp test_pywraps.cpp
