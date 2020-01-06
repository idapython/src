#!/bin/sh

#generate libpython3-stub.so.with the same symbols as libpython3.M.so for linking IDAPython
set VERSION=3.5
set ABIFLAGS=`python3-config --abilags`
set  LDVERSION= $(VERSION)$(ABIFLAGS)
set PYLIB=`python3-config --configdir`/libpython$(LDVERSION).so
python makestub2.py $(PYLIB) >stub.c
gcc -pthread -shared -Wl,--no-as-needed -o libpython3-stub.so -Wl,-hlibpython3.so stub6.c
