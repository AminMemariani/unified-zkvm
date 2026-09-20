//! Internal task runner for the unified-zkvm workspace.
//!
//! Deliberately dependency-light: `std::env::args` and a `match`, no clap. This
//! binary is built on every CI job, so keeping its dependency graph near zero
//! keeps the whole pipeline fast.
//!
//! ```text
//! cargo run -p xtask -- portability-test
//! cargo run -p xtask -- backend-check [--run]
//! cargo run -p xtask -- capabilities
//! ```

use std::process::{Command, ExitCode};

use anyhow::{bail, Result};
use unified_zkvm_core::{
    BackendAdapter, Capability, CapabilitySet, PublicValues, ZkMessage, ZkVmError,
};
use unified_zkvm_host::ZkHostRunner;
use unified_zkvm_mock::MockBackend;

/// Reference Fibonacci - the shared computation every backend must reproduce.
///
/// Duplicated here rather than pulled from the test-support crate so that
/// `xtask` has no dependency on the test package; the values it produces are
/// cross-checked by `tests/portability`.
fn fibonacci(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    a
}

const N: u32 = 20;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");

    let result = match command {
        "portability-test" => portability_test(),
        "backend-check" => backend_check(args.iter().any(|a| a == "--run")),
        "capabilities" => capabilities(),
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            usage();
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    println!("unified-zkvm xtask");
    println!();
    println!("USAGE: cargo run -p xtask -- <command>");
    println!();
    println!("COMMANDS:");
    println!("  portability-test      run the reference computation through every");
    println!("                        compiled-in backend and compare results");
    println!("  backend-check [--run] print (or run) the `cargo check` commands for the");
    println!("                        excluded SP1 / RISC Zero adapter crates");
    println!("  capabilities          print the capability matrix for compiled-in backends");
    println!("  help                  this message");
}

/// One backend's participation in the portability run.
enum Outcome {
    /// The backend ran and produced this value.
    Ran(u64),
    /// The backend did not run, for this reason.
    Absent(&'static str),
}

fn portability_test() -> Result<()> {
    let expected = fibonacci(N);
    let mut rows: Vec<(&str, Outcome)> = Vec::new();

    rows.push(("reference", Outcome::Ran(expected)));
    rows.push(("mock", Outcome::Ran(run_mock()?)));

    // SP1 and RISC Zero adapters live outside the default workspace because
    // they pull vendor toolchains. They are genuinely not here, so they are
    // reported as absent rather than silently skipped.
    rows.push((
        "sp1",
        if cfg!(feature = "sp1") {
            Outcome::Absent("feature `sp1` enabled but no adapter wired into xtask")
        } else {
            Outcome::Absent("adapter not compiled in (feature `sp1`)")
        },
    ));
    rows.push((
        "risc0",
        if cfg!(feature = "risc0") {
            Outcome::Absent("feature `risc0` enabled but no adapter wired into xtask")
        } else {
            Outcome::Absent("adapter not compiled in (feature `risc0`)")
        },
    ));

    println!("unified-zkvm portability test");
    println!();

    let mut mismatched = Vec::new();
    let mut ran = 0usize;
    for (name, outcome) in &rows {
        match outcome {
            Outcome::Ran(value) => {
                ran += 1;
                if *value == expected {
                    println!("  {name:<10} yes  fib({N}) = {value}");
                } else {
                    mismatched.push(*name);
                    println!("  {name:<10} no  fib({N}) = {value}  (expected {expected})");
                }
            }
            Outcome::Absent(reason) => println!("  {name:<10} -  {reason}"),
        }
    }

    println!();
    if !mismatched.is_empty() {
        bail!("backend(s) disagreed with the reference model: {mismatched:?}");
    }
    if ran < 2 {
        bail!("a portability test needs at least the reference and one backend");
    }
    println!("  All available backends agree.");
    Ok(())
}

fn run_mock() -> Result<u64> {
    let backend = MockBackend::new().with_guest(|input: &[u8]| -> Result<Vec<u8>, ZkVmError> {
        let n: u32 = ZkMessage::decode(input)?;
        // `PublicValues::encode` is the canonical commitment encoding, so
        // xtask needs no direct postcard dependency.
        Ok(PublicValues::encode(&fibonacci(n))?.into_bytes())
    });
    let program = backend.build_program(b"xtask-fibonacci-guest")?;
    let runner = ZkHostRunner::new(backend);
    let (_proof, verified) = runner.prove_and_verify(&program, &N)?;
    Ok(verified.decode::<u64>()?)
}

/// A host prerequisite that must be satisfied before an adapter will build.
struct Prerequisite {
    /// The tool or environment variable.
    name: &'static str,
    /// Why it is needed and how to satisfy it.
    detail: &'static str,
}

/// An adapter crate excluded from the default workspace, and what it needs.
struct Adapter {
    /// Cargo feature name.
    feature: &'static str,
    /// Path to the standalone crate.
    path: &'static str,
    /// Host prerequisites discovered by actually building it.
    prerequisites: &'static [Prerequisite],
}

/// The adapter crates and the environment each one needs.
const ADAPTERS: &[Adapter] = &[
    Adapter {
        feature: "sp1",
        path: "crates/unified-zkvm-sp1",
        prerequisites: &[Prerequisite {
            name: "protoc",
            detail: "required on PATH; `brew install protobuf`",
        }],
    },
    Adapter {
        feature: "risc0",
        path: "crates/unified-zkvm-risc0",
        prerequisites: &[Prerequisite {
            name: "RISC0_SKIP_BUILD_KERNELS=1",
            detail: "required on macOS without the Xcode Metal Toolchain",
        }],
    },
];

fn backend_check(run: bool) -> Result<()> {
    println!("unified-zkvm backend check");
    println!();
    println!("  The SP1 and RISC Zero adapters are excluded from the default");
    println!("  workspace on purpose: each pulls a multi-hundred-crate proving");
    println!("  SDK. Check them explicitly with the commands below.");
    println!();

    let mut failures = Vec::new();
    for adapter in ADAPTERS {
        let name = adapter.feature;
        println!("  {name}:");
        for prereq in adapter.prerequisites {
            println!("    prerequisite: {} - {}", prereq.name, prereq.detail);
        }

        let needs_kernel_skip = name == "risc0";
        let env_prefix = if needs_kernel_skip {
            "RISC0_SKIP_BUILD_KERNELS=1 "
        } else {
            ""
        };
        println!(
            "    {env_prefix}cargo check --manifest-path {}/Cargo.toml --all-targets",
            adapter.path
        );

        if run {
            let mut cmd = Command::new("cargo");
            cmd.args([
                "check",
                "--manifest-path",
                &format!("{}/Cargo.toml", adapter.path),
                "--all-targets",
            ]);
            if needs_kernel_skip {
                cmd.env("RISC0_SKIP_BUILD_KERNELS", "1");
            }
            println!("    running...");
            let status = cmd.status()?;
            if status.success() {
                println!("    {name}: ok");
            } else {
                println!("    {name}: FAILED ({status})");
                failures.push(name);
            }
        }
        println!();
    }

    if !run {
        println!("  (pass --run to execute these commands)");
        return Ok(());
    }
    if !failures.is_empty() {
        bail!("adapter check failed for: {failures:?}");
    }
    println!("  all adapter checks passed.");
    Ok(())
}

fn capabilities() -> Result<()> {
    println!("unified-zkvm capability matrix");
    println!();
    println!("  Only backends whose adapter is compiled into this build appear.");
    println!();

    let backends: Vec<(String, CapabilitySet)> = {
        let mock = MockBackend::new();
        vec![(mock.backend_id().to_string(), mock.capabilities())]
    };

    let width = Capability::ALL
        .iter()
        .map(|c| format!("{c:?}").len())
        .max()
        .unwrap_or(20);

    print!("  {:<width$}", "capability", width = width);
    for (name, _) in &backends {
        print!("  {name:<10}");
    }
    println!();

    for capability in Capability::ALL {
        print!("  {:<width$}", format!("{capability:?}"), width = width);
        for (_, caps) in &backends {
            let mark = if caps.supports(*capability) {
                "yes"
            } else {
                "no"
            };
            print!("  {mark:<10}");
        }
        println!();
    }

    println!();
    println!("  sp1    -  adapter not compiled in (feature `sp1`)");
    println!("  risc0  -  adapter not compiled in (feature `risc0`)");
    Ok(())
}
