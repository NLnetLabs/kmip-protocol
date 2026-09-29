use std::io::Read;

use crate::{
    tag_map::{make_kmip_enum_map, make_kmip_tag_map},
    util::PrettyPrinter,
};

mod tag_map;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: hex_to_text <path/to/ttlv_input_hex.txt>");
        std::process::exit(1);
    }

    let mut buf = vec![];
    let mut ttlv_hex_str = if args[1] == "-" {
        std::io::stdin()
            .read_to_end(&mut buf)
            .expect("Failed to read from standard input");
        String::from_utf8(buf).expect("Standard input is not UTF-8")
    } else {
        std::fs::read_to_string(&args[1]).expect("Failed to read the input file")
    };

    for string_to_remove in &[" ", "\n", r#"""#, ","] {
        ttlv_hex_str = ttlv_hex_str.replace(string_to_remove, "");
    }

    let ttlv_bin = hex::decode(ttlv_hex_str)
        .expect("Failed to parse the input file. Make sure it is in hex format, e.g. 42007A..");

    let pretty_printer = PrettyPrinter::new()
        .with_tag_prefix("4200".into())
        .with_tag_map(make_kmip_tag_map())
        .with_enum_map(make_kmip_enum_map());

    println!("{}", pretty_printer.to_string(&ttlv_bin));
}
