from faasmtools.compile_util import wasm_cmake, wasm_copy_upload
from os import environ, makedirs
from os.path import dirname, exists, join, realpath
from shutil import rmtree
from subprocess import run
from sys import argv, exit

APPS_ROOT = dirname(realpath(__file__))
PROJ_ROOT = dirname(APPS_ROOT)


def compile(wasm=False, native=False, debug=False, time=False):
    """
    Compile the different applications supported in Accless.
    """
    build_dir = join(APPS_ROOT, "build-wasm" if wasm else "build-native")

    if not exists(build_dir):
        makedirs(build_dir)

#     if wasm:
#         wasm_cmake(
#             APPS_ROOT,
#             build_dir,
#             "FIXME: proper target name",
#             clean=False,
#             debug=False,
#             is_threads=False,
#         )

    if native:
        cmake_cmd = [
            "cmake",
            "-GNinja",
            "-DCMAKE_BUILD_TYPE={}".format("Debug" if debug else "Release"),
            "-DCMAKE_C_COMPILER=/usr/bin/clang-17",
            "-DCMAKE_CXX_COMPILER=/usr/bin/clang++-17",
            APPS_ROOT,
        ]
        cmake_cmd = " ".join(cmake_cmd)

        run(cmake_cmd, shell=True, check=True, cwd=build_dir)
        run("ninja", shell=True, check=True, cwd=build_dir)


if __name__ == "__main__":
    if "ACCLESS_DOCKER" not in environ or environ["ACCLESS_DOCKER"] != "on":
        print("ERROR: applications can only be built inside Accless' container")
        exit(1)

    debug = False
    if len(argv) == 2 and argv[1] == "--debug":
        debug = True
    elif len(argv) == 2 and argv[1] == "--clean":
        rmtree(join(APPS_ROOT, "build-native"), ignore_errors=True)
        rmtree(join(APPS_ROOT, "build-wasm"), ignore_errors=True)
        run("cargo clean-accless", shell=True, check=True, cwd=PROJ_ROOT)

    # Build the microbenchmarks
    compile(wasm=True, debug=debug)
    compile(native=True, debug=debug)
