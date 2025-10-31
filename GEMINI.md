# Accless Gemini Instructions

You are an AI coding assistant helping in the development of Accless. Accless
is an access control system for confidential serverless. Accless integrates
with two existing serverless runtimes, Faasm and Knative, with integrations
outside of this repository.

Before executing any instructions, make sure you have activated the virtual
environment using:

```bash
source ./scripts/workon.sh
```

## Project Description

Accless is a mono-repo for a research project regarding access control for
confidential serverless. Accless integrates into existing serverless runtimes
by shipping a C++ library that we link against the applications we run. The
library makes assumptions about the hosting serverless environment, which is
patched to support Accless.

Accless integrates with Faasm, a serverless runtime that executes functions
cross-compiled to WebAssembly. As a consequence Accless libraries must support
cross-compilation to WebAssembly. Accless also integrates with Knative, a
serverless runtime that executes functions inside docker containers. For this
one we build the libraries natively, and include them in a docker image.

Applications in Accless are called workflows (i.e. are serverless workflows)
defined by a workflow graph. Each node in the graph is a different function,
and functions can communicate with each other indirectly, via function
chaining.

In confidential serverless, functions execute inside TEEs. In the case of Faasm
we execute WebAssembly modules inside SGX enclaves. In the case of Knative we
execute containers inside confidential VMs. Accless implements remote
attestation protocols for each platform.

Accless access control is based on attribute-based encryption. Accless
generates an access control policy based on the workflow graph, and stores
the encrypted code and data for each function in the workflow in S3-like
storage. Functions obtain their attributes via function chaining, and from
an attribute-providing service. An attribute-providing service can perform
remote attestation of any TEE supported in Accless and, after a valid
attestation, performs ABE key generation and returns attributes to the
function.

Accless has different moving parts:
- `accless`: source code for the library that we link in function's code.
  It is written in C++ to integrate with the SGX SDK, and support cross-
  compilation to WebAssembly, as well as seamless integration with Faasm.
- `accli`: is the command-line tool to run most tasks. It is written in rust
  and can be individually compiled with `cargo -p accli`.

## Code Formatting

Before you suggest any changes, make sure they pass the code formatting checks.
You can run the code formatting checks with:

```bash
# To format code.
accli dev format-code

# To check formatting.
accli dev format-code --check
```

after applying any changes, make sure they compile by running:

```bash
cargo build
```

## Code Style

- Whenever you edit a file, make sure you add a trailing newline to the end of
  the file.

### Rust Coding Guidelines

- Do not allow the use of unwrap() or panic(). Instead, enforce proper error handling.
- For each new method, make sure to add extensive documentation in the following format:
```rust
///
/// # Description
///
/// <description>
///
/// # Arguments
///
/// - `arg1`: explanation
/// - `arg2`: explanation
///
/// # Returns
///
/// <explanation of return value>
///
/// # Example Usage
///
/// <code snippet if applicable
```
- For each new function you add, make sure to add one or multiple unit tests.

### C++ Coding Guidelines

C++ code has certain dependencies, including a cross-compilation toolchain and
system root, that we only ship inside a container.
