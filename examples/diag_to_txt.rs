use std::io::Read;

use kmip_protocol::tag_map;
use kmip_ttlv::PrettyPrinter;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: diag_to_txt - | <path/to/ttlv_input.txt>");
        std::process::exit(1);
    }

    let ttlv_diag_str = match args[1].as_str() {
        "-" => {
            let mut buf = String::new();
            let _ = std::io::stdin()
                .read_to_string(&mut buf)
                .expect("Failed to read from stdin");
            buf
        }
        file_path => std::fs::read_to_string(file_path).expect("Failed to read the input file"),
    };

    let mut pretty_printer = PrettyPrinter::new();
    pretty_printer.with_tag_prefix("4200".into());
    pretty_printer.with_tag_map(tag_map::make_kmip_tag_map());

    println!("{}", pretty_printer.from_diag_string(&ttlv_diag_str));
}
