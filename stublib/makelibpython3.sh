#!/bin/sh

#generate libpython3.so which forwads to actual libpython3.M.so for running IDA (copy it next to IDA's binary)
LDFLAGS=`python3-config --ldflags`
gcc -pthread -shared -Wl,--no-as-needed -o libpython3.so -Wl,-hlibpython3.so $LDFLAGS
