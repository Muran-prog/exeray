fn main() {
    let dst = cmake::Config::new("../../core").profile("Release").build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    // spdlog is built in CMake's _deps subdirectory
    // On Linux (Makefile generator): directly in spdlog-build/
    // On Windows (Visual Studio): in spdlog-build/Release/
    println!(
        "cargo:rustc-link-search=native={}/build/_deps/spdlog-build",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/_deps/spdlog-build/Release",
        dst.display()
    );
    println!("cargo:rustc-link-lib=static=exeray_core");
    println!("cargo:rustc-link-lib=static=spdlog");

    cxx_build::bridge("src/lib.rs")
        .include("../../core/include")
        .std("c++20")
        .compile("exeray_ffi");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=../../core/include");
}
