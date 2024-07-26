from faasmtools.compile_util import wasm_cmake, wasm_copy_upload
from os import listdir, makedirs
from os.path import dirname, exists, join, realpath
from shutil import rmtree

WORKFLOWS_ROOT = dirname(realpath(__file__))

WORKFLOWS = {
    "word-count": ["driver", "splitter", "mapper", "reducer"],
}


def _copy_built_function(build_dir, wflow, func):
    exe_name = "{}_{}.{}".format(wflow, func, "wasm")
    src_file = join(build_dir, wflow, exe_name)
    wasm_copy_upload(wflow, func, src_file)


def compile():
    """
    Compile a function to test a sample library
    """
    build_dir = join(WORKFLOWS_ROOT, "build")

    if exists(build_dir):
        rmtree(build_dir)

    makedirs(build_dir)

    for wflow in WORKFLOWS:
        for function in WORKFLOWS[wflow]:
            # Build the function (gets written to the build dir)
            wasm_cmake(
                WORKFLOWS_ROOT,
                build_dir,
                "{}_{}".format(wflow, function),
                clean=False,
                debug=False,
                is_threads=False,
            )

            # Copy into place in /usr/local/faasm/wasm/<user>/<func>
            _copy_built_function(build_dir, wflow, function)


if __name__ == "__main__":
    compile()
