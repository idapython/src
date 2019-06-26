#! /bin/bash

# This script will patch IDAPython on OSX so that it works with the homebrew version of Python,
# rather than the System version.
#
# Before running it, please follow these steps:
#
#   1. be sure that you have a 64-bit install of python 2.7 installed by homebrew:
#
#      $ brew install python@2
#      $ file /usr/local/Cellar/python\@2/2.7.15_1/Frameworks/Python.framework/Versions/2.7/Python
#      /usr/local/Cellar/python@2/2.7.15_1/Frameworks/Python.framework/Versions/2.7/Python: Mach-O 64-bit dynamically linked shared library x86_64
#
#   2. copy the this script to the root directory of your IDA installation:
#
#      $ cp patch-idapython-homebrew.sh /Applications/IDA\ Pro\ 7.1/
#
#      and make sure the HOMEBREW_PYTHON variable contains the path to the Python framework installed by homebrew in step 1
#
#   3. $ cd /Applications/IDA\ Pro\ 7.1
#      $ ./patch-idapython-homebrew.sh
#
# And that's it! IDAPython commands should still function normally.
HOMEBREW_PYTHON="/usr/local/Cellar/python@2/2.7.15_1/Frameworks/Python.framework/Versions/2.7/Python"

IDABIN=ida.app/Contents/MacOS

function backup
{
  if [ ! -f ${1}.orig ]; then
    cp -r ${1} ${1}.orig
  fi
}

PLG=${IDABIN}/plugins/python.dylib
PLG64=${IDABIN}/plugins/python64.dylib

# backup idapython plugin
backup ${PLG}
backup ${PLG64}

DYNLOAD=${IDABIN}/python/lib/python2.7/lib-dynload

# backup python submodules
backup ${DYNLOAD}/ida_32
backup ${DYNLOAD}/ida_64

function patch
{
  install_name_tool -change /System/Library/Frameworks/Python.framework/Versions/2.7/Python $HOMEBREW_PYTHON $1
}

# patch idapython plugin
patch ${PLG}
patch ${PLG64}

# patch all of idapython's submodules
for file in $DYNLOAD/ida_{32,64}/*
do
  patch $file
done
