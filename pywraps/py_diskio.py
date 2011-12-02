#<pycode(py_diskio)>
def enumerate_system_files(subdir, fname, callback):
    """Similar to enumerate_files() however it searches inside IDA directory or its subdirectories"""
    return enumerate_files(idadir(subdir), fname, callback)
#</pycode(py_diskio)>
