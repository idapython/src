
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

ifdef __X64__
  ifdef __LINUX__
    LINUX64=1
  endif
endif

ifdef LINUX64
all:
	@echo "Not building Python for Linux x64"
else

PROC=python
STRIPOBJS=idaapi.cpp
API_CONTENTS=api_contents.txt
CFGFILE=python.cfg

IDA_INCLUDE=../../include

STAGING=./staging
ST_SWIG=$(STAGING)/swig
ST_SDK=$(STAGING)/idasdk
ST_PYW=$(STAGING)/pywraps
ST_PARSED_HEADERS=$(STAGING)/parsed_notifications/xml

ifdef __NT__
  SYSNAME=win
else
.NOTPARALLEL:
endif
ifdef __LINUX__
  SYSNAME=linux
  DEFS=-D__LINUX__
  PYTHON32_LIBRARY_PATH?=/usr/lib
  PYTHON32_LIBRARY_INCLUDE=-L$(PYTHON32_LIBRARY_PATH)
endif
ifdef __BSD__
  SYSNAME=bsd
  DEFS=-D__BSD__
endif
ifdef __MAC__
  SYSNAME=mac
  DEFS=-D__MAC__
endif

O1=idaapi
ADDITIONAL_GOALS=pyfiles config $(TEST_IDC)

__USE_RTTI__=1
include ../plugin.mak

# HIJACK the $(I) variable to point to our staging SDK
I=$(ST_SDK)/

ifdef __CODE_CHECKER__
  ADDITIONAL_GOALS:=$(filter-out pyfiles config $(TEST_IDC),$(ADDITIONAL_GOALS))
  OBJS:=$(filter-out $(OBJ1),$(OBJS))
endif

# used python version
PYTHON_VERSION_MAJOR?=2
PYTHON_VERSION_MINOR?=7

# output directory for python scripts

ifeq ($(OUT_OF_TREE_BUILD),)
  SCRIPTDIR=$(R)python
  DEPLOY_INIT_PY=$(SCRIPTDIR)/init.py
  DEPLOY_IDC_PY=$(SCRIPTDIR)/idc.py
  DEPLOY_IDAUTILS_PY=$(SCRIPTDIR)/idautils.py
  TEST_IDC=test_idc
else
  SCRIPTDIR=python
endif

ifdef __NT__                   # os and compiler specific flags
ifneq ($(UCRT_INCLUDE),)
  I_UCRT_INCLUDE=/I$(UCRT_INCLUDE)
endif
  PYTHON_ROOT?=c:
  PYTHON_DIR=$(PYTHON_ROOT)/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)
  IDAPYTHON_CFLAGS=-w -Z7 /EHsc /bigobj /I$(MSVCDIR)Include $(I_UCRT_INCLUDE)
  ifdef __X64__
    PYTHONLIB=vcx64_python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR).lib -nodefaultlib:python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR).lib
  else
    PYTHONLIB=$(PYTHON_DIR)/libs/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR).lib
  endif
  _SWIGFLAGS=-D__NT__ -DWIN32 -D_USRDLL -I$(PYTHON_DIR)/include
  SWIGINCLUDES?=   # nothing
  OSFLAGS=$(_SWIGFLAGS) -UNO_OBSOLETE_FUNCS
else # unix/mac
  ifdef __LINUX__
    # use the precompiled 2.7
    ifeq ($(OUT_OF_TREE_BUILD),)
      PYDIR=$(shell pwd)/precompiled
      PYLIBDIR=$(PYDIR)
      # copy these files to IDA's directory
      PYLIBFILES=$(shell find precompiled/lib -type f)
      PRECOMPILED_COPY=$(R)$(PYTHONLIBNAME) $(patsubst precompiled/%,$(SCRIPTDIR)/%,$(PYLIBFILES))
    else
      PYDIR=$(IDAPYTHON_PYTHONHOME)
      PYLIBDIR=$(PYDIR)/lib
    endif
    PYTHON32_INCLUDE:=-I$(PYDIR)/include/python$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR)
    PYTHONLIBNAME=libpython$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR).so.1.0
    PYTHONLIB=$(PYLIBDIR)/$(PYTHONLIBNAME) -ldl
  else
    PYVER=$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR)
    PYTHON32_INCLUDE:=$(shell python$(PYVER)-config --includes)
    PYTHONLIB:=$(shell python$(PYVER)-config --ldflags)
    MACDEFINES=-DMACSDKVER=$(MACSDKVER)
  endif
  IDAPYTHON_CFLAGS=-w -g
  OSFLAGS=$(SYS) -g $(PYTHON32_INCLUDE) $(ARCH_CFLAGS) $(PIC) -UNO_OBSOLETE_FUNCS # gcc flags
  _SWIGFLAGS=$(DEFS)
  SWIGINCLUDES?=-I$(SWIGDIR)share/swig/$(SWIG_VERSION)/python -I$(SWIGDIR)share/swig/$(SWIG_VERSION)
endif
SWIGFLAGS=$(_SWIGFLAGS) $(SWIGINCLUDES)

ADDITIONAL_LIBS=$(PYTHONLIB)

.PHONY: pyfiles docs $(TEST_IDC) staging_dirs clean check_python
config: $(C)python.cfg

clean:
	rm -rf $(STAGING)/ obj/

pyfiles: $(SCRIPTDIR)/idautils.py \
	 $(SCRIPTDIR)/idc.py      \
	 $(SCRIPTDIR)/init.py     \
	 $(SCRIPTDIR)/idaapi.py

GENHOOKS=tools/genhooks/

$(DEPLOY_INIT_PY): python/init.py
	$(CP) $? $@

$(DEPLOY_IDC_PY): python/idc.py
	$(CP) $? $@

$(DEPLOY_IDAUTILS_PY): python/idautils.py
	$(CP) $? $@

$(SCRIPTDIR)/idaapi.py: $(F)idaapi.py
	$(PYTHON) inject_pydoc.py swig/  $? $@

$(SCRIPTDIR)/lib/%: precompiled/lib/%
	mkdir -p $(@D)
	cp $< $@
	@chmod +w $@

$(C)python.cfg: $(CFGFILE)
	$(CP) $? $@

$(R)$(PYTHONLIBNAME): $(PYDIR)/$(PYTHONLIBNAME)
	$(CP) $? $@

# -------------------------------------------------------------------------
# Hooks generation
$(ST_PARSED_HEADERS)/structprocessor__t.xml: $(I)idp.hpp $(GENHOOKS)doxy_gen_notifs.cfg | $(ST_SDK_TARGETS)
	@$(DOXYGEN_BIN) $(GENHOOKS)doxy_gen_notifs.cfg

$(ST_PARSED_HEADERS)/dbg_8hpp.xml: $(I)dbg.hpp $(GENHOOKS)doxy_gen_notifs.cfg | $(ST_SDK_TARGETS)
	@$(DOXYGEN_BIN) $(GENHOOKS)doxy_gen_notifs.cfg

$(ST_PARSED_HEADERS)/kernwin_8hpp.xml: $(I)kernwin.hpp $(GENHOOKS)doxy_gen_notifs.cfg | $(ST_SDK_TARGETS)
	@$(DOXYGEN_BIN) $(GENHOOKS)doxy_gen_notifs.cfg

$(ST_PARSED_HEADERS)/namespaceidb__event.xml: $(I)kernwin.hpp $(GENHOOKS)doxy_gen_notifs.cfg | $(ST_SDK_TARGETS)
	@$(DOXYGEN_BIN) $(GENHOOKS)doxy_gen_notifs.cfg

#
staging_dirs:
	-@if [ ! -d "$(ST_SDK)" ] ; then mkdir -p 2>/dev/null $(ST_SDK) ; fi
	-@if [ ! -d "$(ST_SWIG)" ] ; then mkdir -p 2>/dev/null $(ST_SWIG) ; fi
	-@if [ ! -d "$(ST_PYW)" ] ; then mkdir -p 2>/dev/null $(ST_PYW) ; fi
	-@if [ ! -d "$(ST_PARSED_HEADERS)" ] ; then mkdir -p 2>/dev/null $(ST_PARSED_HEADERS) ; fi

# -------------------------------------------------------------------------
# Rules for preparing 'staging/idasdk/*.h[pp]'
#
SDK_SOURCES=$(wildcard $(IDA_INCLUDE)/*.h) $(wildcard $(IDA_INCLUDE)/*.hpp)
ST_SDK_TARGETS=$(SDK_SOURCES:$(IDA_INCLUDE)/%=$(ST_SDK)/%)
$(ST_SDK)/%.h: $(IDA_INCLUDE)/%.h | staging_dirs
	@$(CP) $^ $@ && chmod +rw $@
$(ST_SDK)/%.hpp: $(IDA_INCLUDE)/%.hpp | staging_dirs
	@$(CP) $^ $@ && chmod +rw $@


# -------------------------------------------------------------------------
# Rules for preparing 'staging/pywraps/*'
#
PYW_SOURCES=$(wildcard pywraps/*.hpp) $(wildcard pywraps/*.py)
ST_PYW_TARGETS=$(PYW_SOURCES:pywraps/%=$(ST_PYW)/%)
$(ST_PYW)/%.hpp: pywraps/%.hpp | staging_dirs
	@$(CP) $^ $@ && chmod +rw $@
$(ST_PYW)/%.py: pywraps/%.py | staging_dirs
	@$(CP) $^ $@ && chmod +rw $@


ifneq ($(OUT_OF_TREE_BUILD),)
  # envvar HAS_HEXRAYS must have been set by build.py if needed
else

  # force hexrays bindings
  HAS_HEXRAYS=1

  # These require special care, as they will have to be injected w/ hooks -- this
  # only happens if we are sitting in the hexrays source tree; when published to
  # the outside world, the pywraps must already contain the injected code.
  $(ST_PYW)/py_idp.hpp: pywraps/py_idp.hpp \
	$(I)idp.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_idphooks.py \
	$(ST_PARSED_HEADERS)/structprocessor__t.xml | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/structprocessor__t.xml -e idp_notify \
		-r int -n 0 -m hookgenIDP -q "processor_t::" \
		-R $(GENHOOKS)recipe_idphooks.py
  $(ST_PYW)/py_idbhooks.hpp: pywraps/py_idbhooks.hpp \
	$(I)idp.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_idbhooks.py \
	$(ST_PARSED_HEADERS)/namespaceidb__event.xml | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/namespaceidb__event.xml -e event_code_t \
		-r int -n 0 -m hookgenIDB -q "idb_event::" \
		-R $(GENHOOKS)recipe_idbhooks.py
  $(ST_PYW)/py_dbg.hpp: pywraps/py_dbg.hpp \
	$(I)dbg.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_dbghooks.py \
	$(ST_PARSED_HEADERS)/dbg_8hpp.xml | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/dbg_8hpp.xml -e dbg_notification_t \
		-r void -n 0 -m hookgenDBG \
		-R $(GENHOOKS)recipe_dbghooks.py
  $(ST_PYW)/py_kernwin.hpp: pywraps/py_kernwin.hpp \
	$(I)kernwin.hpp \
	$(GENHOOKS)genhooks.py \
	$(GENHOOKS)recipe_uihooks.py \
	$(ST_PARSED_HEADERS)/kernwin_8hpp.xml | staging_dirs $(SDK_SOURCES)
	@$(PYTHON) $(GENHOOKS)genhooks.py -i $< -o $@ \
		-x $(ST_PARSED_HEADERS)/kernwin_8hpp.xml -e ui_notification_t \
		-r void -n 0 -m hookgenUI \
		-R $(GENHOOKS)recipe_uihooks.py \
		-d "ui_dbg_,ui_obsolete" -D "ui:" -s "ui_"
endif # OUT_OF_TREE_BUILD

ifneq ($(HAS_HEXRAYS),)
  WITH_HEXRAYS=-DWITH_HEXRAYS
  WITH_HEXRAYS_CHKAPI=--with-hexrays
endif


# -------------------------------------------------------------------------
# Rules for preparing 'staging/swig/*.i'
#
# Note: At the time we define those rules, we cannot go and look in
# staging/pywraps/ just yet, as those will/might not have been deployed at
# that point (i.e., when building from scratch.)
# Thus, we must find the dependencies in pywraps/, and then re-route them to
# staging/pywraps/
SWIG_SOURCES=$(wildcard swig/*.i)
ST_SWIG_TARGETS=$(SWIG_SOURCES:swig/%.i=$(ST_SWIG)/%.i)
find-pywraps-deps = $(wildcard pywraps/py_$(subst .i,,$(notdir $1)).*)
define make-deploy-swig-file-rule
$1: $(subst staging/,,$1) $(addprefix staging/,$(call find-pywraps-deps,$1)) | $(ST_PYW_TARGETS)
	@$(PYTHON) tools/deploy.py --pywraps $(ST_PYW) --template $$(subst staging/,,$$@) --output $$@ --module $$(subst .i,,$$(notdir $$@))
endef
$(foreach tgt,$(ST_SWIG_TARGETS),$(eval $(call make-deploy-swig-file-rule,$(tgt))))


# Require a strict SWiG version (other versions might generate different code.)
SWIG_VERSION_ACTUAL=$(shell $(SWIG) -version | awk "/SWIG Version [0-9.]+/ { if (match(\$$0, /([0-9.]+)/)) { print substr(\$$0, RSTART, RLENGTH); } }")

# idaapi.py is created together with idaapi_include.cpp
$(F)idaapi.py: | $(F)idaapi_include.cpp
# idaapi_include.h is created together with idaapi_include.cpp
patched_idaapi_include_h: patch_directors_cc.py | $(F)idaapi_include.h
ifdef __NT__
	@$(PYTHON) patch_directors_cc.py -f $(F)idaapi_include.h
endif

$(F)idaapi_include.h: | $(F)idaapi_include.cpp
$(F)idaapi_include.cpp: $(PRECOMPILED_COPY) \
		$(ST_SDK_TARGETS) \
		$(ST_PYW_TARGETS) \
		$(ST_SWIG_TARGETS) \
	        pywraps.hpp | objdir
	@ ! (grep __EA64__ swig/* | grep -v typeconv.i) || \
	  (echo "ERROR: __EA64__ macro is foribidden in swig subdirectory (to ensure the same api for both ida versions)" && false)
ifneq ($(SWIG_VERSION_ACTUAL),$(SWIG_VERSION))
	$(error Expected SWIG version "$(SWIG_VERSION)", but got "$(SWIG_VERSION_ACTUAL)" (from $(SWIG)))
endif
	$(SWIG) -modern $(WITH_HEXRAYS) -python -threads -c++ -shadow \
	  $(MACDEFINES) -D__GNUC__ $(SWIGFLAGS) $(SWITCH64) -I$(ST_SWIG) \
	  -outdir $(F) -o $@ -I$(ST_SDK) $(ST_SWIG)/idaapi.i || \
	  { $(RM) $(F)idaapi_include.*; exit 1 ;}
	$(PYTHON) chkapi.py $(WITH_HEXRAYS_CHKAPI) -f $@ -r $(API_CONTENTS).new
	@(diff $(API_CONTENTS) $(API_CONTENTS).new) > /dev/null || \
	  (rm -f $@ $(F)idaapi_include.h && \
	   echo "API CONTENTS CHANGED! update api_contents.txt or fix the API" && \
	   echo "(New API: $(API_CONTENTS).new) ***" && \
	   (diff -U 1 -w $(API_CONTENTS) $(API_CONTENTS).new && false))


# Python version
CFLAGS= $(CCOPT) $(OSFLAGS) -D__EXPR_SRC -I. -I$(ST_SWIG) -I$(ST_SDK) -I$(F)   \
	-DVER_MAJOR="1" -DVER_MINOR="7" -DVER_PATCH="0" -D__IDP__   \
	-DUSE_STANDARD_FILE_FUNCTIONS $(IDAPYTHON_CFLAGS)           \
	$(SWITCH64) $(ARCH_CFLAGS) $(WITH_HEXRAYS)

# the html files are produced in docs\hr-html directory
docs:   hrdoc.py hrdoc.cfg hrdoc.css
	idaq -Shrdoc.py -t

# Test that all functions that are present in ftable.cpp
# are present in idc.py (and therefore made available by
# the idapython).
ifdef __NT__
  IDA_CMD=TVHEADLESS=1 $(R)idaw$(X64SUFF)$(SUFF64)
else
  IDA_CMD=TVHEADLESS=1 $(R)idal$(X64SUFF)$(SUFF64)
endif

# the demo version of ida does not have the -B command line option
ifeq ($(OUT_OF_TREE_BUILD),)
  ISDEMO=$(shell grep "define DEMO$$" $(IDA_INCLUDE)/commerc.hpp)
  ifeq ($(ISDEMO),)
    BATCH_SWITCH=-B
  endif
endif

$(TEST_IDC): $(F)idctest.log
$(F)idctest.log: $(RS)idc/idc.idc | $(BINARY) pyfiles $(PRECOMPILED_COPY)
ifneq ($(wildcard ../../tests),)
	@$(RM) $(F)idctest.log
	@$(IDA_CMD) $(BATCH_SWITCH) -S"test_idc.py $^" -t -L$(F)idctest.log> /dev/null || \
	  (echo "ERROR: The IDAPython IDC interface is incomplete. IDA log:" && cat $(F)idctest.log && false)
endif

# MAKEDEP dependency list ------------------
$(F)idaapi$(O)  : $(F)idaapi_include.cpp $(I)allins.hpp $(I)area.hpp        \
	          $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp $(I)dbg.hpp   \
	          $(I)diskio.hpp $(I)entry.hpp $(I)enum.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fixup.hpp $(I)fpro.h $(I)frame.hpp       \
	          $(I)funcs.hpp $(I)gdl.hpp $(I)graph.hpp $(I)ida.hpp       \
	          $(I)idd.hpp $(I)idp.hpp $(I)ieee.h $(I)ints.hpp           \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)moves.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)offset.hpp $(I)pro.h $(I)queue.hpp    \
	          $(I)search.hpp $(I)segment.hpp $(I)sistack.hpp            \
	          $(I)srarea.hpp $(I)strlist.hpp $(I)struct.hpp             \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp                   \
	          idaapi.cpp pywraps.hpp | patched_idaapi_include_h $(ST_SDK_TARGETS)
$(F)python$(O)  : $(I)area.hpp $(I)bitrange.hpp $(I)bytes.hpp                \
	          $(I)diskio.hpp $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp      \
	          $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp                 \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp python.cpp pywraps.hpp | $(ST_SDK_TARGETS)
endif
