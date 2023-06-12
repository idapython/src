Overview
========

This document describes the IDAPython linking process used on Apple Silicon Macs.

Motivation
==========

Since IDAPython must be compatible with different Python versions, we must provide the user with
a mechanism to easily switch between them. Traditionally the approach on Mac was to have the
idapyswitch utility patch the libpython load commands in all of IDAPython's modules.

However this gets us into trouble on Apple Silicon, because codesigning rules are strictly enforced.
If we patch a dylib binary in IDA's installation, its code signature is invalidated and macOS will
refuse to load it (not only that, but the process is immediately killed).

We must be able to switch between various Python versions _without_ modifying IDA's binaries.

TBD Files
=========

This is where .tbd files can help us.

A .tbd file is a stub library that can be used in place of a real dylib. It is essentially just a text file
that describes the contents of a given library - e.g. the target arch, all exported symbols, and (most importantly)
the library's install name.

This allows us to configure the libpython install name used when our IDAPython binaries are linked, so that they
point to a symlink for libpython instead of the real libpython binary. Thus, it is trivial to switch between
different Python versions because need only to modify the symlink target, and all of IDAPython's modules can
remain untouched.

Generating TBD Files
====================

.tbd files can be generated using the 'tapi' utility on macOS. It is usually found here:

    /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/tapi

For example, this is how you can recreate libpython3.tbd:

    $ alias tapi='/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/tapi'
    $ cp /Library/Frameworks/Python.framework/Versions/3.9/Python /tmp/
    $ tapi stubify /tmp/Python
    $ mv /tmp/Python.tbd ~/idasrc/current/plugins/idapython/libpython3.tbd

Then replace the following line:

    install-name:    '/Library/Frameworks/Python.framework/Versions/3.9/Python'

With:

    install-name:    '@executable_path/libpython3.link.dylib'

Note that the libpython3.link.dylib symlink will be created by idapyswitch at idapython build time
(see TBD_MODULE_DEP in idapython/makefile and pyver_tool_t::do_apply_version() in idapyswitch_mac.cpp).

It is also a good idea to clean up the .tbd file by removing all config directives that aren't
absolutely necessary. This makes it more likely that the .tbd file will continue to be compatible
with newer versions of the macOS linker (no surprise, the format is really unstable).

So far it seems that only the following options are required:

     --- !tapi-tbd
     tbd-version:     4
     targets:         [ arm64-macos, x86_64-macos ]
     install-name:    '@executable_path/libpython3.link.dylib'
     current-version: 3.9
     compatibility-version: 3.9
     exports:
       - targets:         [ arm64-macos, x86_64-macos ]
         symbols:         [ _PyAST_CompileEx, ... 

Everything else can be removed.
