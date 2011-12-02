============================
deploy.py - usage
============================

The deploy script is used to deploy python and c++ code into SWIG interface files appropriately.
The reason it was created was because working with .i files to put a mixture of C++ and Python code is not practical for testing and development process.

In SWIG, there are three sections:

Inline
---------

C++ code will be wrapped by SWIG.

In SWIG .i files the inline code is marked with:
        %inline %{
          C++ code
        %}

In deploy.py supporting files the code to be pasted into .i files is marked with:
        //<inline(NAME)>
          C++ code
        //</inline(NAME)>


Code
-------
C++ code will be pasted and compiled into the wrapped module but will not be wrapped by SWIG.

In SWIG .i files the code is marked with:
        %{
        C++ code
        %}

Similarly, for deploy.py supporting files should be marked with:
        //<code(NAME)>
          C++ code
        //</code(NAME)>

Pythoncode
--------------

Python code allows you to insert Python code into the final Python module.

In SWIG .i files, the extra python code is marked with:
        %pythoncode %{
        Py code
        %}

In deploy.py supporting python files, it is marked with:
        #<pycode(NAME)>
        Py code
        #</pycode(NAME)>

Using deploy.py
------------------
Make sure that all of the 3 code markers exist in the interface files and deploy.py support files (C++ or Python).

As an example, let us interpret the meaning of:
        deploy.py py_idaapi py_idaapi.hpp,py_idaapi.py ..\swig\idaapi.i
It means:
        NAME = py_idaapi
        ...take code snips from py_idaapi.hpp and py_idaapi.py
        ...and paste the code there into idaapi.i SWIG interface file

Now remember that both the input files have the special markers (discussed above) and so does idaapi.i file


============================
linkgen.py - usage
============================
TODO


============================
swigdocs.py - usage
============================

The swigdocs script will extract python comments from SWIG interface files (*.i).

There are two places where Python code documentation can be found:
  1. In the "%pythoncode %{" section, we extract all the python code because it could contain docstrings.
  Inside the pythoncode section, one can find embedded commented that are commented out.
  Because they are commented out, the documentation generator will miss them. The swigdocs script will remove the comment character:
#<pydoc>
#    def OnClose(self):
#        """
#        Called when the window is being closed.
#        This callback is mandatory.
#        @return: nothing
#        """
#        pass
#</pydoc>
  After swigdocs finishes, the output will contain all the python code and all the commented code (now uncommented).

  2. In the "%inline %{" section (in C++ code), one can find functions comments like this:
/*
#<pydoc>
def dbg_read_memory(ea, sz):
    """
    Reads from the debugee's memory at the specified ea
    @return:
        - The read buffer (as a string)
        - Or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *dbg_read_memory(PyObject *py_ea, PyObject *py_sz)
{
   ......
}
  In this case, the code inside <pydoc> tag will be extracted as well.


After swigdocs finishes, the output is a Python file containing all code and comments extracted from the *.i file(s).