These files create stub libraries for linking and running IDA without linking to a specific libpython3.M.so
This is achieved by linking to a libpython3.so library which forwards to the actual libpython3.M.so
- makelibpython3.sh makes such libpython3.so if your Python distribution does not provide one (recipe stolen from Python's Makefile)
- makelibpython3-stub.sh makes a libpython3-stub.so which exports the same symbols 
as original libpython3.M.so but has SONAME of libpython3.so.
It can be used to check for missing symbols during linking but use libpython3.so at runtime
- makestub2.py creates a C file to create this stub by parsing the original symbol table from libpython3.M.so

