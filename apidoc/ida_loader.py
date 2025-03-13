
def mem2base(mem, ea, fpos):
    """
    Load database from the memory.

    @param mem: the buffer
    @param ea: start linear addresses
    @param fpos: position in the input file the data is taken from.
                 if == -1, then no file position correspond to the data.
    @return:
        - Returns zero if the passed buffer was not a string
        - Otherwise 1 is returned
    """
    pass

def load_plugin(name):
    """
    Loads a plugin

    @param name: short plugin name without path and extension,
                 or absolute path to the file name
    @return:
        - None if plugin could not be loaded
        - An opaque object representing the loaded plugin
    """
    pass

def run_plugin(plg, arg):
    """
    Runs a plugin

    @param plg: A plugin object (returned by load_plugin())
    @param arg: the code to pass to the plugin's "run()" function
    @return: Boolean
    """
    pass
