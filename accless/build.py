from faasmtools.compile_util import wasm_cmake, wasm_copy_upload
from os import environ, makedirs
from os.path import dirname, exists, join, realpath
from shutil import rmtree
from subprocess import run
from sys import argv, exit

ACCLESS_ROOT = dirname(realpath(__file__))


def compile(wasm=False, native=False, debug=False, time=False):
    """
    Compile the different microbenchmarks
    """
    build_dir = join(ACCLESS_ROOT, "build-wasm" if wasm else "build-native")

    if not exists(build_dir):
        makedirs(build_dir)

    if wasm:
        wasm_cmake(
            ACCLESS_ROOT,
            build_dir,
            "accless",
            clean=False,
            debug=False,
            is_threads=False,
        )

    if native:
        cmake_cmd = [
            "cmake",
            "-GNinja",
            "-DACCLESS_UBENCH=on" if time else "",
            "-DCMAKE_BUILD_TYPE={}".format("Debug" if debug else "Release"),
            "-DCMAKE_C_COMPILER=/usr/bin/clang-17",
            "-DCMAKE_CXX_COMPILER=/usr/bin/clang++-17",
            ACCLESS_ROOT,
        ]
        cmake_cmd = " ".join(cmake_cmd)

        run(cmake_cmd, shell=True, check=True, cwd=build_dir)
        run("ninja", shell=True, check=True, cwd=build_dir)


if __name__ == "__main__":
    if "ACCLESS_DOCKER" not in environ or environ["ACCLESS_DOCKER"] != "on":
        print("ERROR: microbenchmarks can only be built inside Accless' container")
        exit(1)

    debug = False
    if len(argv) == 2 and argv[1] == "--debug":
        debug = True
    elif len(argv) == 2 and argv[1] == "--clean":
        rmtree(join(ACCLESS_ROOT, "build-native"), ignore_errors=True)
        rmtree(join(ACCLESS_ROOT, "build-wasm"), ignore_errors=True)

    # Build the microbenchmarks
    # compile(wasm=True, debug=debug)
    compile(native=True, debug=debug)
