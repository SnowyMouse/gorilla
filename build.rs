extern crate embed_resource;

fn main() {
    // Compile in windows.rc if Windows
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        embed_resource::compile("windows.rc");
    }

    // Store gorilla version
    println!("cargo:rustc-env=gorilla_version={} {}", std::env::var("CARGO_PKG_NAME").unwrap(), std::env::var("CARGO_PKG_VERSION").unwrap());
}
