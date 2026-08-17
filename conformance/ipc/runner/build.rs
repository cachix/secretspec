use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../libsecretspec-ipc");
    let mut build = cc::Build::new();
    build
        .std("c11")
        .opt_level(1)
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .flag_if_supported("-Wpedantic")
        .flag_if_supported("-fvisibility=hidden")
        .define("SECRETSPEC_IPC_BUILDING", None)
        .define("yyjson_api", Some(""))
        .include(root.join("include"))
        .include(root.join("vendor"))
        .include(root.join("src"))
        .file(root.join("src/frame.c"))
        .file(root.join("src/json.c"))
        .file(root.join("src/secure_memory.c"))
        .file(root.join("src/session.c"))
        .file(root.join("vendor/yyjson.c"));

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        build.file(root.join("src/process_windows.c"));
    } else {
        build.file(root.join("src/process_posix.c"));
    }
    build.compile("secretspec_ipc_conformance_c");

    if std::env::var_os("CARGO_CFG_UNIX").is_some() {
        println!("cargo:rustc-link-lib=pthread");
    }
    println!("cargo:rerun-if-changed={}", root.display());
}
