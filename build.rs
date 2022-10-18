extern crate rustc_version;
use rustc_version::{version, Version};

fn main() {
    let version = version().expect("Failed to get rustc version.");
    if version < Version::parse("1.54.0").unwrap() {
        eprintln!(
            "\n\nAt least Rust version 1.54 is required.\n\
             Version {} is used for building.\n\
             Build aborted.\n\n",
            version
        );
        panic!();
    }
}
