extern crate embed_resource;

fn var(what : &str) -> String {
    std::env::var(what).unwrap()
}

use std::fs::File;
use std::path::Path;
use std::io::Write;

fn main() {
    let gorilla_version = var("CARGO_PKG_VERSION");
    let gorilla_version_dot = gorilla_version.replace(".",",");
    let gorilla_pkg = var("CARGO_PKG_NAME");

    // Compile in windows.rc if Windows
    if var("CARGO_CFG_TARGET_OS") == "windows" {
        let windows_rc_path_raw = format!("{}/windows.rc", var("OUT_DIR"));
        let windows_rc_path = Path::new(&windows_rc_path_raw);

        write!(File::create(windows_rc_path).unwrap(),
"1 VERSIONINFO
FILEVERSION      {gorilla_version_dot},0
PRODUCTVERSION   {gorilla_version_dot},0
BEGIN
    BLOCK \"StringFileInfo\"
    BEGIN
        BLOCK \"040904B0\"
        BEGIN
            VALUE \"Comments\",         \"Definition dumper for guerilla.exe\"
            VALUE \"CompanyName\",      \"Snowy Mouse\"
            VALUE \"FileDescription\",  \"Definition dumper for guerilla.exe\"
            VALUE \"FileVersion\",      \"{gorilla_version}\"
            VALUE \"InternalName\",     \"{gorilla_pkg}.exe\"
            VALUE \"OriginalFilename\", \"{gorilla_pkg}.exe\"
            VALUE \"ProductName\",      \"{gorilla_pkg}.exe\"
            VALUE \"ProductVersion\",   \"{gorilla_version}\"
            VALUE \"LegalCopyright\",   \"'22 Snowy Mouse\"
        END
    END
    BLOCK \"VarFileInfo\"
    BEGIN
        VALUE \"Translation\", 0x409, 1200
    END
END

IDI_ICON1 ICON DISCARDABLE \"icon/icon.ico\"
").unwrap();

        embed_resource::compile(windows_rc_path);
    }

    // Store gorilla version
    println!("cargo:rustc-env=gorilla_version={} {}", gorilla_pkg, gorilla_version);

    // We only need to change if Cargo.toml was modified, since that's where the version is stored
    println!("cargo:rerun-if-changed=Cargo.toml");
}
