use std::{
    env,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    generate_c_header(&crate_dir);
    generate_version_rs(&out_dir).expect("failed to generate version.rs");
}

fn generate_c_header(crate_dir: &str) {
    cbindgen::generate(&crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(format!("{crate_dir}/maybenot.h"));
}

/// Generate version.rs and embed a symbol containing the crate version
fn generate_version_rs(out_dir: &Path) -> io::Result<()> {
    let version_rs_path = out_dir.join("version.rs");
    let mut f = File::create(version_rs_path)?;
    let pkg_version = env!("CARGO_PKG_VERSION");
    writeln!(&mut f, "#[no_mangle]")?;
    writeln!(
        &mut f,
        r#"static MAYBENOT_FFI_VERSION: &core::ffi::CStr = c"maybenot-ffi/{pkg_version}";"#,
    )?;

    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    Ok(())
}
