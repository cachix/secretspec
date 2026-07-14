fn main() {
    // On macOS a cdylib is linked with a two-level namespace and errors on any
    // undefined symbol. A PHP extension deliberately leaves the Zend/PHP symbols
    // (`_zend_*`, `_zval_ptr_dtor`, …) undefined — they are provided by the PHP
    // binary at dlopen time, inside the process that loads the extension. Tell
    // the linker to defer them, the same `-undefined dynamic_lookup` that pyo3
    // and ext-php-rs extensions need on macOS. Linux/ELF resolves these lazily at
    // load already, so no flag is needed there.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
