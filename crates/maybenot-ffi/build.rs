use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    generate_c_header(&crate_dir);
}

fn generate_c_header(crate_dir: &str) {
    cbindgen::generate(&crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(format!("{crate_dir}/maybenot.h"));
}
