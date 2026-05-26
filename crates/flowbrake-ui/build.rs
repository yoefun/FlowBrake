fn main() {
    println!("cargo:rerun-if-changed=ui/main.slint");
    println!("cargo:rerun-if-changed=../../assets/app.ico");
    println!("cargo:rerun-if-changed=../../third_party/windivert/WinDivert.dll");
    println!("cargo:rerun-if-changed=../../third_party/windivert/WinDivert64.sys");

    embed_windows_manifest();
    embed_windows_icon();
    slint_build::compile("ui/main.slint").expect("failed to compile Slint UI");

    copy_runtime_artifacts();
}

fn embed_windows_manifest() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }

    println!("cargo:rustc-link-arg-bin=flowbrake-ui=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bin=flowbrake-ui=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    );
}

fn embed_windows_icon() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let icon_path = repo_root().join("assets").join("app.ico");
    if !icon_path.exists() {
        return;
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR must be set"));
    let rc_path = out_dir.join("flowbrake-ui.rc");
    let res_path = out_dir.join("flowbrake-ui.res");
    let icon_literal = icon_path.display().to_string().replace('\\', "\\\\");
    std::fs::write(&rc_path, format!("1 ICON \"{icon_literal}\"\n"))
        .expect("failed to write icon resource script");

    let rc_exe =
        find_windows_sdk_tool("rc.exe").unwrap_or_else(|| std::path::PathBuf::from("rc.exe"));
    let status = std::process::Command::new(&rc_exe)
        .arg("/nologo")
        .arg(format!("/fo{}", res_path.display()))
        .arg(&rc_path)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", rc_exe.display()));

    if !status.success() {
        panic!(
            "{} failed while compiling app icon resource",
            rc_exe.display()
        );
    }

    println!(
        "cargo:rustc-link-arg-bin=flowbrake-ui={}",
        res_path.display()
    );
}

fn copy_runtime_artifacts() {
    let repo_root = repo_root();
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR must be set"));
    let mut profile_dir = out_dir;
    for _ in 0..3 {
        profile_dir.pop();
    }

    let artifacts = [
        (
            repo_root
                .join("third_party")
                .join("windivert")
                .join("WinDivert.dll"),
            "WinDivert.dll",
        ),
        (
            repo_root
                .join("third_party")
                .join("windivert")
                .join("WinDivert64.sys"),
            "WinDivert64.sys",
        ),
    ];

    for (source, file_name) in artifacts {
        if source.exists() {
            let destination = profile_dir.join(file_name);
            copy_if_changed(&source, &destination);
        }
    }
}

fn copy_if_changed(source: &std::path::Path, destination: &std::path::Path) {
    if destination.exists()
        && std::fs::read(source)
            .ok()
            .zip(std::fs::read(destination).ok())
            .is_some_and(|(source_bytes, destination_bytes)| source_bytes == destination_bytes)
    {
        return;
    }

    std::fs::copy(source, destination).unwrap_or_else(|err| {
        panic!(
            "failed to copy {} to {}: {err}",
            source.display(),
            destination.display()
        )
    });
}

fn find_windows_sdk_tool(tool_name: &str) -> Option<std::path::PathBuf> {
    let sdk_bin = std::path::PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let entries = std::fs::read_dir(sdk_bin).ok()?;
    let mut versions = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_dir()))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    versions.sort();
    versions.reverse();

    for version in versions {
        for arch in ["x64", "x86", "arm64"] {
            let candidate = version.join(arch).join(tool_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn repo_root() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"),
    );
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("ui crate must live under crates/flowbrake-ui")
        .to_path_buf()
}
