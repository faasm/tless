from faasmtools.compile_util import wasm_cmake, wasm_copy_upload
from os import environ, makedirs
from os.path import dirname, exists, join, realpath
from shutil import rmtree
from subprocess import run
from sys import argv

UBENCH_ROOT = dirname(realpath(__file__))
UBENCHS = {
    "cold-start": "accless-ubench-cold-start"
}


def compile(wasm=False, native=False, debug=False, time=False):
    """
    Compile the different microbenchmarks
    """
    build_dir = join(UBENCH_ROOT, "build-wasm" if wasm else "build-native")

    if not exists(build_dir):
        makedirs(build_dir)

    for ubench in UBENCHS:
        code_dir = join(UBENCH_ROOT, ubench)
        if wasm:
            # TODO: cannot set -DACCLESS_UBENCH easily
            wasm_cmake(
                code_dir,
                build_dir,
                UBENCHS[ubench],
                clean=False,
                debug=False,
                is_threads=False,
            )

        if native:
            cmake_cmd = [
                "cmake",
                "-GNinja",
                "-DACCLESS_UBENCH" if time else "",
                "-DCMAKE_BUILD_TYPE={}".format("Debug" if debug else "Release"),
                "-DCMAKE_C_COMPILER=/usr/bin/clang-17",
                "-DCMAKE_CXX_COMPILER=/usr/bin/clang++-17",
                code_dir,
            ]
            cmake_cmd = " ".join(cmake_cmd)

            run(cmake_cmd, shell=True, check=True, cwd=build_dir)
            run("ninja {}".format(UBENCHS[ubench]), shell=True, check=True, cwd=build_dir)


if __name__ == "__main__":
    debug = False
    if len(argv) == 2 and argv[1] == "--debug":
        debug = True
    elif len(argv) == 2 and argv[1] == "--clean":
        rmtree(join(UBENCH_ROOT, "build-native"), ignore_errors=True)
        rmtree(join(UBENCH_ROOT, "build-wasm"), ignore_errors=True)
    time = len(argv) == 2 and argv[1] == "--time"

    # Build the microbenchmarks
    compile(wasm=True, debug=debug, time=time)
    compile(native=True, debug=debug, time=time)
