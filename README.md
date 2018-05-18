# radeco-csmith-tester
Test `radeco-lib` with a randomly generated program from Csmith.

## Usage
```
radeco-csmith-tester 0.0.1
HMPerson1 <hmperson1@gmail.com>
Test `radeco-lib` with a randomly generated program from Csmith.

You may need to run `sysctl kernel.unprivileged_userns_clone=1` for `nsjail` to work.

USAGE:
    radeco-csmith-tester [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Pass many times for more log output.

OPTIONS:
        --compiler_bin <compiler_bin>                 Name of the compiler executable. [default: cc]
        --csmith_bin <csmith_bin>                     Name of the `csmith` executable. [default: csmith]
        --csmith_headers <csmith_headers>
            Directory containing csmith's runtime headers [default: /usr/include/csmith-2.3.0]

        --csmith_opts <csmith_opts>...                Options to pass to csmith to generate the original source.
        --nsjail_bin <nsjail_bin>                     Name of the `nsjail` executable. [default: nsjail]
        --nsjail_bindmounts <nsjail_bindmounts>...
            Files that nsjail should mount --bind inside the container. Defaults to ["/usr/lib/libc.so.6", "/lib64/ld
            -linux-x86-64.so.2"] if left empty.
        --orig_compile_opts <orig_compile_opts>...    Options to pass to the compiler to compile the original binary.
        --output-prefix <output_prefix>               Prefix for output folders. [default: out_]
        --seed <seed>                                 Seed for Csmith. By default, generate a random seed.
```
