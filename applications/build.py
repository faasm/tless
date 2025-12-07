import argparse
from faasmtools.compile_util import wasm_cmake, wasm_copy_upload
from os import environ, makedirs, listdir
from os.path import abspath, dirname, exists, join, realpath
from shutil import rmtree
from subprocess import run
from sys import argv, exit

APPS_ROOT = dirname(realpath(__file__))
PROJ_ROOT = dirname(APPS_ROOT)


def compile(wasm=False, native=False, debug=False, clean=False, as_cert_dir=None):
    """
    Compile the different applications supported in Accless.
    """
    build_dir = join(APPS_ROOT, "build-wasm" if wasm else "build-native")

    if clean:
        if exists(build_dir):
            print(f"Cleaning build directory: {build_dir}")
            rmtree(build_dir)

    if not exists(build_dir):
        makedirs(build_dir)

    if as_cert_dir is not None:
        if not exists(as_cert_dir):
            print(f"ERROR: passed --cert-dir variable but path does not exist")
            exit(1)
        # Add check for empty directory
        if not listdir(as_cert_dir): # Check if directory is empty
            print(f"WARNING: Passed --cert-dir variable points to an empty directory: {as_cert_dir}")
        as_cert_dir = abspath(as_cert_dir)

    # if wasm:
    #     wasm_cmake(
    #         APPS_ROOT,
    #         build_dir,
    #         "FIXME: proper target name",
    #         clean=False,
    #         debug=False,
    #         is_threads=False,
    #     )

    if native:
        cmake_cmd = [
            "cmake",
            "-GNinja",
            "-DCMAKE_BUILD_TYPE={}".format("Debug" if debug else "Release"),
            "-DCMAKE_C_COMPILER=/usr/bin/clang-17",
            "-DCMAKE_CXX_COMPILER=/usr/bin/clang++-17",
            f"-DACCLESS_AS_CERT_DIR={as_cert_dir}" if as_cert_dir is not None else "",
            APPS_ROOT,
        ]
        cmake_cmd = " ".join(cmake_cmd)

        # Only run CMake command on clean builds.
        if clean:
            run(cmake_cmd, shell=True, check=True, cwd=build_dir)

        run("ninja", shell=True, check=True, cwd=build_dir)


if __name__ == "__main__":
    if "ACCLESS_DOCKER" not in environ or environ["ACCLESS_DOCKER"] != "on":
        print("ERROR: applications can only be built inside Accless' container")
        exit(1)

    parser = argparse.ArgumentParser(description="Build Accless applications.")
    parser.add_argument(
        "--clean", action="store_true", help="Clean before building."
    )
    parser.add_argument(
        "--debug", action="store_true", help="Build in debug mode."
    )
    parser.add_argument("--as-cert-dir", type=str, help="Path to certificate PEM file.")
    args = parser.parse_args()

    if args.clean:
        # This is a global clean, so we do it once here.
        print("Running global clean: cargo clean-accless")
        run("cargo clean-accless", shell=True, capture_output=True, cwd=PROJ_ROOT)

    # Build the microbenchmarks
    compile(
        wasm=True,
        debug=args.debug,
        clean=args.clean,
        as_cert_dir=args.as_cert_dir,
    )
    compile(
        native=True,
        debug=args.debug,
        clean=args.clean,
        as_cert_dir=args.as_cert_dir,
    )
