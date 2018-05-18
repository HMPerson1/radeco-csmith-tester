#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]

// extern crate radeco_lib;

extern crate failure;
#[macro_use]
extern crate quicli;
extern crate rand;

use quicli::prelude::*;

// use radeco_lib::frontend::radeco_containers::ProjectLoader;

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

/*
 * 1. orig_source <- csmith()
 * 2. orig_binary <- compile(orig_source)
 * 3. deco_soucce <- radeco(orig_binary)
 * 4. deco_binary <- compile(deco_source)
 * 5. success     <- run(orig_binary) == run(deco_binary)
 */

/// Test `radeco-lib` with a randomly generated program from Csmith.
///
/// You may need to run `sysctl kernel.unprivileged_userns_clone=1` for `nsjail`
/// to work.
#[derive(Debug, StructOpt)]
struct Cli {
    /// Prefix for output folders.
    #[structopt(long = "output-prefix", default_value = "out_", parse(from_os_str))]
    output_prefix: OsString,

    /// Seed for Csmith. By default, generate a random seed.
    #[structopt(long = "seed")]
    seed: Option<u64>,

    /// Options to pass to csmith to generate the original source.
    #[structopt(long = "csmith_opts", parse(from_os_str))]
    csmith_opts: Vec<OsString>,

    /// Directory containing csmith's runtime headers
    #[structopt(
        long = "csmith_headers", default_value = "/usr/include/csmith-2.3.0", parse(from_os_str)
    )]
    csmith_headers: OsString,

    /// Options to pass to the compiler to compile the original binary.
    #[structopt(long = "orig_compile_opts", parse(from_os_str))]
    orig_compile_opts: Vec<OsString>,

    /// Files that nsjail should mount --bind inside the container.
    /// Defaults to ["/usr/lib/libc.so.6", "/lib64/ld-linux-x86-64.so.2"]
    /// if left empty.
    #[structopt(long = "nsjail_bindmounts", parse(from_os_str))]
    nsjail_bindmounts: Vec<OsString>,

    /// Name of the `csmith` executable.
    #[structopt(long = "csmith_bin", default_value = "csmith", parse(from_os_str))]
    csmith_bin: OsString,

    /// Name of the compiler executable.
    #[structopt(long = "compiler_bin", default_value = "cc", parse(from_os_str))]
    compiler_bin: OsString,

    /// Name of the `nsjail` executable.
    #[structopt(long = "nsjail_bin", default_value = "nsjail", parse(from_os_str))]
    nsjail_bin: OsString,

    /// Pass many times for more log output.
    #[structopt(long = "verbose", short = "v", parse(from_occurrences))]
    verbosity: u8,
}

const CSMITH_OPTS: &[&str] = &["--max-block-depth", "3", "--max-funcs", "3"];

const ORIG_COMPILE_OPTS: &[&str] = &["-O2", "-xc", "-std=c99", "-w"];

const DECO_COMPILE_OPTS: &[&str] = &[
    "-O2",
    "-xc",
    "-std=c99",
    "-Wall",
    "-Wextra",
    "-fno-strict-overflow",
    "-fno-strict-aliasing",
    // "-I/usr/include/csmith-2.3.0/",
];

const NSJAIL_OPTS: &[&str] = &[
    "-v",
    "-Mo",
    "-t8",
    "-u99999",
    "-g99999",
    "--disable_proc",
    "--iface_no_lo",
    "--seccomp_string",
    NSJAIL_SECCOMP_STRING,
    "--execute_fd",
];

// minimum that nsjail and ld-linux need to launch the program
#[cfg_attr(rustfmt, rustfmt_skip)]
const NSJAIL_SECCOMP_STRING: &str = "\
  POLICY p { \
    ALLOW { \
      read, write, openat, close, newstat, newfstat, mmap, \
      mprotect, brk, access, execveat, arch_prctl, exit_group \
    } \
  } \
  USE p DEFAULT KILL\
";

main!(|args: Cli, log_level: verbosity| {
    debug!("args={:#?}", args);

    let seed: u64 = args.seed.unwrap_or_else(rand::random);
    info!("seed={}", seed);

    let mut output_prefix = args.output_prefix;
    output_prefix.push(&format!("{:016x}", seed));
    let mut output_dir_buf = PathBuf::from(output_prefix);

    let output_dir = output_dir_buf.clone();
    fs::create_dir(&output_dir)
        .with_context(|_| format_err!("Could not create directory {:?}", output_dir))?;
    output_dir_buf.push("_");

    output_dir_buf.set_file_name("orig_src.c");
    let orig_source_filename = output_dir_buf.clone();
    output_dir_buf.set_file_name("orig_bin");
    let orig_binary_filename = output_dir_buf.clone();
    output_dir_buf.set_file_name("deco_src.c");
    let deco_source_filename = output_dir_buf.clone();
    output_dir_buf.set_file_name("deco_bin");
    let deco_binary_filename = output_dir_buf.clone();

    // 1
    info!("csmithing...");
    gen_orig_source(
        &args.csmith_bin,
        seed,
        &args.csmith_opts,
        orig_source_filename.as_os_str(),
    )?;

    // 2
    info!("compiling original...");
    compile(
        &args.compiler_bin,
        ORIG_COMPILE_OPTS,
        &args.orig_compile_opts,
        Some(&args.csmith_headers),
        orig_source_filename.as_os_str(),
        orig_binary_filename.as_os_str(),
    )?;

    // 3
    info!("decompiling...");
    let deco_res: std::thread::Result<_> =
        std::panic::catch_unwind(|| decompile(&orig_binary_filename, &deco_source_filename));
    match deco_res {
        Err(e) => {
            test_fail(&output_dir, seed, &format!("radeco panicked with: {:?}", e));
            return Ok(());
        }
        Ok(Err(e)) => {
            test_fail(&output_dir, seed, &format!("radeco failed with: {}", e));
            return Ok(());
        }
        Ok(Ok(())) => (),
    }

    // 4
    info!("compiling radeco output...");
    let deco_comp_res = compile(
        &args.compiler_bin,
        DECO_COMPILE_OPTS,
        &[],
        None,
        deco_source_filename.as_os_str(),
        deco_binary_filename.as_os_str(),
    );
    if let Err(e) = deco_comp_res {
        test_fail(
            &output_dir,
            seed,
            &format!("compiling radeco output failed:\n{}", e),
        );
        return Ok(());
    }

    // 5
    info!("testing...");
    let success = test_binaries(
        &args.nsjail_bin,
        &args.nsjail_bindmounts,
        orig_binary_filename.as_os_str(),
        deco_binary_filename.as_os_str(),
    )?;
    if success {
        println!("success!");
    } else {
        test_fail(&output_dir, seed, "program outputs were different");
        return Ok(());
    }

    // everything succeeded; cleanup files
    fs::remove_dir_all(&output_dir)
        .with_context(|_| format_err!("Could not remove directory {:?}", output_dir))?;
});

fn gen_orig_source(
    csmith_bin: &OsStr,
    seed: u64,
    extra_opts: &[OsString],
    output: &OsStr,
) -> Result<()> {
    run_command(csmith_bin, |cmd| {
        cmd.args(CSMITH_OPTS);
        cmd.args(extra_opts);
        cmd.arg("-s").arg(format!("{}", seed));
        cmd.arg("-o").arg(output);
    })?;
    Ok(())
}

fn compile(
    compiler_bin: &OsStr,
    default_opts: &[&str],
    extra_opts: &[OsString],
    opt_include_dir: Option<&OsStr>,
    input: &OsStr,
    output: &OsStr,
) -> Result<()> {
    let compiler_out = run_command(compiler_bin, |cmd| {
        cmd.args(default_opts);
        if let Some(include_dir) = opt_include_dir {
            cmd.arg("-I").arg(include_dir);
        }
        cmd.args(extra_opts);
        cmd.arg("-o").arg(output);
        cmd.arg(input);
    })?;
    if !compiler_out.stderr.is_empty() {
        warn!(
            "compiler emitted warnings:\n{}",
            String::from_utf8_lossy(&compiler_out.stderr)
        );
    }
    Ok(())
}

fn decompile(_input: &Path, output: &Path) -> Result<()> {
    // XXX
    const DUMMY_PROG_SOURCE: &str = r#"\
#include <stdio.h>
int main() {
puts("Hello, World!");
}
"#;
    // let mut rproj = ProjectLoader::new().path(input.to_str().expect()).load();
    // XXX: cheat for testing purposes :P
    // fs::copy(output.with_file_name("orig_src.c"), output)?;
    // XXX: actually decompile
    write_to_file(output, DUMMY_PROG_SOURCE)?;
    Ok(())
}

fn test_binaries(
    nsjail_bin: &OsStr,
    bindmounts: &[OsString],
    orig: &OsStr,
    deco: &OsStr,
) -> Result<bool> {
    fn run_in_nsjail(
        nsjail_bin: &OsStr,
        bindmounts: &[OsString],
        bin: &OsStr,
        bail_if_empty: bool,
    ) -> Result<Option<Vec<u8>>> {
        // 100 + SIGKILL
        // see https://github.com/google/nsjail/blob/f8db8c7eea56e2cb9dd8771ff407ff50cf9c30c1/subproc.cc#L336
        const TIMED_OUT_EXIT_CODE: i32 = 109;

        let nsjail_out_res = run_command(nsjail_bin, |cmd| {
            cmd.args(NSJAIL_OPTS);
            if bindmounts.is_empty() {
                cmd.args(&["-R/usr/lib/libc.so.6", "-R/lib64/ld-linux-x86-64.so.2"]);
            } else {
                cmd.args(bindmounts.into_iter().map(|file| {
                    let mut arg = OsString::from("-R");
                    arg.push(file);
                    arg
                }));
            }
            cmd.arg("--").arg(bin);
        });
        match nsjail_out_res {
            Ok(nsjail_out) => {
                let cksum_line = nsjail_out.stdout;
                debug!(
                    "{:?} outputed {:?}",
                    bin,
                    String::from_utf8_lossy(&cksum_line)
                );
                if cksum_line.is_empty() && bail_if_empty {
                    bail!(
                        "Got empty output from {}; nsjail stderr:\n{}\n\
                         Try `sysctl kernel.unprivileged_userns_clone=1`",
                        bin.to_string_lossy(),
                        String::from_utf8_lossy(&nsjail_out.stderr)
                    )
                }
                Ok(Some(cksum_line))
            }

            Err(RunCommandError::ExitStatus(_, ref nsjail_out))
                if nsjail_out.status.code() == Some(TIMED_OUT_EXIT_CODE) =>
            {
                debug!("{:?} timed out", bin);
                Ok(None)
            }

            Err(x) => Err(x.into()),
        }
    }

    let orig_cksum = run_in_nsjail(nsjail_bin, bindmounts, orig, true)?;
    let deco_cksum = run_in_nsjail(nsjail_bin, bindmounts, deco, false)?;
    Ok(orig_cksum == deco_cksum)
}

fn test_fail(output_dir: &Path, seed: u64, msg: &str) -> () {
    println!("========== RADECO FAILURE ==========");
    println!("** seed={}", seed);
    println!("** {}", msg);
    println!(
        "** files are in \"{}\" for further analysis",
        output_dir.display()
    );
}

fn run_command<F>(name: &OsStr, build: F) -> std::result::Result<process::Output, RunCommandError>
where
    F: FnOnce(&mut Command) -> (),
{
    let mut cmd = Command::new(name);
    build(&mut cmd);
    trace!("about to run: {:?}", cmd);
    let out = cmd.output()
        .map_err(|e| RunCommandError::CouldNotStart(name.to_owned(), e))?;
    debug!("{:?} exited with {:?}", name, out.status);
    if !out.status.success() {
        return Err(RunCommandError::ExitStatus(name.to_owned(), out));
    }
    Ok(out)
}

#[derive(Fail, Debug)]
enum RunCommandError {
    CouldNotStart(OsString, #[cause] io::Error),
    ExitStatus(OsString, process::Output),
}

impl fmt::Display for RunCommandError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RunCommandError::CouldNotStart(ref cmd_name, ref cause) => write!(
                fmt,
                "Could not start {}: {}",
                cmd_name.to_string_lossy(),
                cause
            ),
            RunCommandError::ExitStatus(ref cmd_name, ref out) => write!(
                fmt,
                "{} exited with {}; stderr was:\n{}",
                cmd_name.to_string_lossy(),
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }
}

// racer is unusably slow for some reason
// Local Variables:
// racer-cmd: /bin/true
// End:
