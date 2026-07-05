use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

fn target_env_key(prefix: &str, target: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        target
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
            .collect::<String>()
    )
}

fn default_target_cc(target: &str) -> Option<&'static str> {
    match target {
        "x86_64-unknown-linux-gnu" => Some("x86_64-linux-gnu-gcc"),
        "aarch64-unknown-linux-gnu" => Some("aarch64-linux-gnu-gcc"),
        _ => None,
    }
}

fn linux_init_cc() -> String {
    if let Ok(cc) = std::env::var("CC_LINUX") {
        return cc;
    }

    let target = std::env::var("TARGET").unwrap_or_default();
    let host = std::env::var("HOST").unwrap_or_default();
    if !target.is_empty() && target != host {
        for key in [
            target_env_key("CC", &target),
            target_env_key("CARGO_TARGET", &target) + "_LINKER",
        ] {
            if let Ok(cc) = std::env::var(&key) {
                return cc;
            }
        }
        if let Some(cc) = default_target_cc(&target) {
            return cc.to_string();
        }
    }

    std::env::var("CC").unwrap_or_else(|_| "cc".to_string())
}

fn build_default_init() -> PathBuf {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let libkrun_root = manifest_dir.join("../..");
    let init_src = libkrun_root.join("init/init.c");
    let dhcp_src = libkrun_root.join("init/dhcp.c");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let init_bin = out_dir.join("init");

    println!("cargo:rerun-if-env-changed=CC_LINUX");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rerun-if-env-changed=CC_X86_64_UNKNOWN_LINUX_GNU");
    println!("cargo:rerun-if-env-changed=CC_AARCH64_UNKNOWN_LINUX_GNU");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER");
    println!("cargo:rerun-if-env-changed=TIMESYNC");
    println!("cargo:rerun-if-changed={}", init_src.display());
    println!("cargo:rerun-if-changed={}", dhcp_src.display());
    println!(
        "cargo:rerun-if-changed={}",
        libkrun_root.join("init/jsmn.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        libkrun_root.join("init/dhcp.h").display()
    );

    let mut init_cc_flags = vec!["-O2", "-static", "-Wall"];
    if std::env::var_os("TIMESYNC").as_deref() == Some(OsStr::new("1")) {
        init_cc_flags.push("-D__TIMESYNC__");
    }

    let cc_value = linux_init_cc();
    let mut cc_parts = cc_value.split_ascii_whitespace();
    let cc = cc_parts.next().expect("CC_LINUX/CC must not be empty");
    let status = Command::new(cc)
        .args(cc_parts)
        .args(&init_cc_flags)
        .arg("-o")
        .arg(&init_bin)
        .arg(&init_src)
        .arg(&dhcp_src)
        .status()
        .unwrap_or_else(|e| panic!("failed to execute {cc}: {e}"));

    if !status.success() {
        panic!("failed to compile init/init.c: {status}");
    }
    init_bin
}

fn main() {
    let init_binary_path = std::env::var_os("KRUN_INIT_BINARY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let init_path = build_default_init();
            // SAFETY: The build script is single threaded.
            unsafe { std::env::set_var("KRUN_INIT_BINARY_PATH", &init_path) };
            init_path
        });
    println!(
        "cargo:rustc-env=KRUN_INIT_BINARY_PATH={}",
        init_binary_path.display()
    );
    println!("cargo:rerun-if-env-changed=KRUN_INIT_BINARY_PATH");
}
