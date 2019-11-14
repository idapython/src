
import os
import sys
import subprocess


ossfx, compiler, sosfx, buildcmd, py2_env, py3_env = {
    "win32" : (
        "win",
        "vc",
        "dll",
        "mo.bat -j 12 && mmo.bat -j 12",
        {
            "PYTHON_VERSION_MAJOR" : "2",
            "PYTHON_VERSION_MINOR" : "7",
            "PYTHON_ROOT" : "C:/Python27-x64",
        },
        {
            "PYTHON_VERSION_MAJOR" : "3",
            "PYTHON_VERSION_MINOR" : "7",
            "PYTHON_ROOT" : "C:/PROGRA~1/Python37",
        },
    ),
    "cygwin" : (
        "win",
        "vc",
        "dll",
        "mo.bat -j 12 && mmo.bat -j 12",
        {
            "PYTHON_VERSION_MAJOR" : "2",
            "PYTHON_VERSION_MINOR" : "7",
            "PYTHON_ROOT" : "C:/Python27-x64",
        },
        {
            "PYTHON_VERSION_MAJOR" : "3",
            "PYTHON_VERSION_MINOR" : "7",
            "PYTHON_ROOT" : "C:/PROGRA~1/Python37",
        },
    ),
    "linux2" : (
        "linux",
        "gcc",
        "so",
        "NDEBUG=1 BIN/idamake.pl -j 12 && NDEBUG=1 __EA64__=1 BIN/idamake.pl -j 12",
        {
            "PYTHON_VERSION_MAJOR" : "2",
            "PYTHON_VERSION_MINOR" : "7",
        },
        {
            "PYTHON_VERSION_MAJOR" : "3",
            "PYTHON_VERSION_MINOR" : "7",
            "PYTHONHOME" : "/opt/Python-3.7.4-x64-install",
            "PATH" : "/opt/Python-3.7.4-x64-install/bin:!",
            "LD_LIBRARY_PATH" : "/opt/Python-3.7.4-x64-install/lib:!"
        },
    ),
    "darwin" : (
        "mac",
        "clang",
        "dylib",
        "NDEBUG=1 BIN/idamake.pl -j 12 && NDEBUG=1 __EA64__=1 BIN/idamake.pl -j 12",
        {
            "PYTHON_VERSION_MAJOR" : "2",
            "PYTHON_VERSION_MINOR" : "7",
            "PYTHON_ROOT" : "/System/Library/Frameworks/Python.framework/Versions/2.7",
            },
        {
            "PYTHON_VERSION_MAJOR" : "3",
            "PYTHON_VERSION_MINOR" : "7",
            "PYTHON_ROOT" : "/Library/Frameworks/Python.framework/Versions/3.7/lib/python3.7",
            },
    ),
}[sys.platform]

# def run(argv):
#     if isinstance(argv, str):
#         argv = argv.split()
#     print("### Running: %s" % " ".join(argv))
#     subprocess.check_call(argv)

def run(argv):
    if not isinstance(argv, str):
        argv = " ".join(argv)
    print("### Running: %s" % argv)
    subprocess.check_call(argv, shell=True)

def trash_opt_builds():
    run("rm -rf obj/x64_%s_%s_32_opt obj/x64_%s_%s_64_opt" % (
        ossfx, compiler,
        ossfx, compiler))

def build_both():
    run(buildcmd.replace("BIN", os.path.join("..", "..", "bin")))

def rename_both(version):
    J = os.path.join
    ppath = J("..", "..", "bin", "x64_%s_%s_opt" % (ossfx, compiler), "plugins")
    parts = [""]
    if version == 3 and "linux" in sys.platform:
        parts.append(".debug")
    for part in parts:
        for easfx in ["", "64"]:
            run("mv %s %s" % (
                J(ppath, "idapython%s.%s%s" % (easfx, sosfx, part)),
                J(ppath, "idapython%s.%s.%d%s" % (easfx, sosfx, version, part))))


for py_env, major in [
        (py2_env, 2),
        (py3_env, 3)
]:
    for key, val in py_env.items():
        was = os.getenv(key)
        if was:
            val = val.replace("!", was)
        print("### Setting: %s=%s" % (key, val))
        os.putenv(key, val)
    trash_opt_builds()
    build_both()
    rename_both(major)
