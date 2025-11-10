import argparse
from faasmtools.compile_util import wasm_cmake, wasm_copy_upload
from os import environ, makedirs
from os.path import abspath, dirname, exists, join, realpath
from shutil import rmtree
from subprocess import run
from sys import argv, exit

APPS_ROOT = dirname(realpath(__file__))
PROJ_ROOT = dirname(APPS_ROOT)


def compile(wasm=False, native=False, debug=False, clean=False, cert_path=None):
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

    if cert_path is not None and not exists(cert_path):
        print(f"ERROR: passed --cert-path variable but path does not exist")
        exit(1)
    else:
        cert_path = abspath(cert_path)

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
            f"-DACCLESS_AS_CERT_PEM={cert_path}" if cert_path is not None else "",
            APPS_ROOT,
        ]
        cmake_cmd = " ".join(cmake_cmd)

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
    parser.add_argument("--cert-path", type=str, help="Path to certificate.")
    args = parser.parse_args()

    if args.clean:
        # This is a global clean, so we do it once here.
        print("Running global clean: cargo clean-accless")
        run("cargo clean-accless", shell=True, check=True, cwd=PROJ_ROOT)

    # Build the microbenchmarks
    compile(
        wasm=True,
        debug=args.debug,
        clean=args.clean,
        cert_path=args.cert_path,
    )
    compile(
        native=True,
        debug=args.debug,
        clean=args.clean,
        cert_path=args.cert_path,
    )
