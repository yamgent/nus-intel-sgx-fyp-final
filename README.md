# nus-intel-sgx-fyp-final

This is the implementation code for the paper "Secure Services over Untrusted
Servers" by Tan Wang Leng.

## Prerequisites

The code is developed and tested on Ubuntu 18.04 Bionic Beaver. Therefore, you
will need Ubuntu 18.04 to compile and run the project.

Install the Intel SGX for Linux, which can be obtained through the following
URL: https://software.intel.com/en-us/sgx-sdk/download

Ensure that you are able to access the SGX tools from the terminal (run 
`sgx_sign -version`, it should respond by printing the version number for the
tools).

Additionally, install cmake and other build utilites:

```bash
sudo apt install build-essential cmake
```

## Compiling the Project

Create a temporary build folder `build/` in the root directory (it is
gitignored) and run the build commands:

```bash
mkdir build
cd build
cmake ../src
make
```

## Running the Project

### Non-enclave Version of Rewriter

To meter a program:

```bash
./nosgx_app_meter <input_filename> <output_filename>
```

### Enclave Version of Rewriter

First, run a server that provides the metering service:

```bash
./app_meterwriter 4000
```

(Note: When running `app_meterwriter` for the first time, the keys for the
enclave will be generated and placed inside a sealed data file in the same
directory. Please re-run `app_meterwriter` again to start the service proper,
as the key may not be loaded in properly after generation.)

Then, to meter a program:

```bash
# metering
./app_meterclient 4000 1 <input_filename> <output_filename>

# verifying the metered result
./app_meterclient 4000 2 <output_filename>
```

### Sample Program to Test Metering

`src/sample_program/` provides a sample source code of a normal program,
which can be used to observe how the metering is added.

```bash
# switch to the directory
cd src/sample_program

# generate the assembly code
make asm

# do the meter rewriting (see above sections depending on which version you
# want to use)
...     # ("meterize" test_source.s to test_source_metered.s before proceeding)
        # (verify the hash using 'sha256sum' if needed)

# generate the final binary from the metered assembly
make out

# run the program
./work_enclave.out <loop_iterations>
```

(Note: `./work_enclave.out` prints out the number of instructions executed at
the end, this is deliberately done so that we can verify that the metering does
work properly).
