fn main() {
    let dst = cmake::Config::new("../../core").profile("Release").build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=exeray_core");

    cxx_build::bridge("src/lib.rs")
        .include("../../core/include")
        .std("c++20")
        .compile("exeray_ffi");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=../../core/include");
}
