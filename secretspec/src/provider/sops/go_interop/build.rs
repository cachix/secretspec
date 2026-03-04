use std::env;
use std::process::Command;

fn main() {
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let go_dir = current_dir.join("go");

    println!("cargo:warning=Building Go library in: {}", go_dir.display());

    // Ensure we're in the go directory
    env::set_current_dir(&go_dir).expect("Failed to change to go directory");

    // Build the Go static library - make sure the name matches what we're linking
    let lib_name = "sops_wrapper";
    let lib_file = format!("lib{}.a", lib_name);

    let output = Command::new("go")
        .args([
            "build",
            "-buildmode=c-archive",
            "-o",
            &lib_file,
            "sops_wrapper.go",
        ])
        .output()
        .expect("Failed to execute go build command");

    if !output.status.success() {
        panic!(
            "Go build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Check if the files were created
    let lib_path = go_dir.join(&lib_file);
    let header_file = format!("lib{}.h", lib_name);
    let header_path = go_dir.join(&header_file);

    if !lib_path.exists() {
        panic!("Static library was not created at: {}", lib_path.display());
    }
    if !header_path.exists() {
        panic!("Header file was not created at: {}", header_path.display());
    }

    println!("cargo:warning=Library created at: {}", lib_path.display());
    println!("cargo:warning=Header created at: {}", header_path.display());

    // Generate bindings from the header file
    let bindings = bindgen::Builder::default()
        .header(header_path.to_string_lossy())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the go directory
    let bindings_path = go_dir.join("bindings.rs");
    bindings
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    println!(
        "cargo:warning=Bindings created at: {}",
        bindings_path.display()
    );

    // Tell cargo to link the static library
    println!("cargo:rustc-link-search=native={}", go_dir.display());
    println!("cargo:rustc-link-lib=static={}", lib_name); // This should match the lib name without lib prefix

    // Platform-specific linking
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=resolv");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=resolv");
    } else if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=userenv");
    }

    // Rerun if Go files change
    // TODO: Is this actually working?
    println!("cargo:rerun-if-changed=src/provider/sops/go_interop/go/sops_wrapper.go");
    println!("cargo:rerun-if-changed=src/provider/sops/go_interop/go/go.mod");
    println!("cargo:rerun-if-changed=src/provider/sops/go_interop/go/go.sum");
}
