use std::path::PathBuf;

/// Point the C sources at the system yyjson.
///
/// pkg-config is the portable answer: Nix, Homebrew, apt, and vcpkg all ship
/// `yyjson.pc`. Runners without pkg-config (Windows) can name the install
/// prefix through `YYJSON_INCLUDE_DIR` and `YYJSON_LIB_DIR` instead. Inside the
/// devenv shell neither path is needed, because `pkgs.yyjson` already puts its
/// header and library on the compiler's search paths through
/// `NIX_CFLAGS_COMPILE` and `NIX_LDFLAGS`.
fn link_yyjson(build: &mut cc::Build) {
    println!("cargo:rerun-if-env-changed=YYJSON_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=YYJSON_LIB_DIR");

    let include_dir = std::env::var_os("YYJSON_INCLUDE_DIR");
    let lib_dir = std::env::var_os("YYJSON_LIB_DIR");
    if include_dir.is_none() && lib_dir.is_none() {
        // `probe` emits the link directives itself when it succeeds.
        if let Ok(yyjson) = pkg_config::Config::new().probe("yyjson") {
            for path in yyjson.include_paths {
                build.include(path);
            }
            return;
        }
    }

    if let Some(path) = include_dir {
        build.include(path);
    }
    if let Some(path) = lib_dir {
        println!(
            "cargo:rustc-link-search=native={}",
            PathBuf::from(path).display()
        );
    }
    println!("cargo:rustc-link-lib=yyjson");
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../libsecretspec-resolver");
    let mut build = cc::Build::new();
    build
        .std("c11")
        .opt_level(1)
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .flag_if_supported("-Wpedantic")
        .flag_if_supported("-fvisibility=hidden")
        .define("SECRETSPEC_RESOLVER_BUILDING", None)
        .include(root.join("include"))
        .include(root.join("src"))
        .file(root.join("src/frame.c"))
        .file(root.join("src/json.c"))
        .file(root.join("src/secure_memory.c"))
        .file(root.join("src/session.c"));

    link_yyjson(&mut build);

    // MSVC gates <stdatomic.h> behind an opt-in switch even in C11 mode.
    if build.get_compiler().is_like_msvc() {
        build.flag("/experimental:c11atomics");
    }

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        build.file(root.join("src/process_windows.c"));
    } else {
        build.file(root.join("src/process_posix.c"));
    }
    build.compile("secretspec_resolver_conformance_c");

    if std::env::var_os("CARGO_CFG_UNIX").is_some() {
        println!("cargo:rustc-link-lib=pthread");
    }
    println!("cargo:rerun-if-changed={}", root.display());
}
