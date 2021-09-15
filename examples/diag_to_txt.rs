use kmip_protocol::tag_map;
use kmip_ttlv::PrettyPrinter;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: text_to_hex <path/to/ttlv_input.txt>");
        std::process::exit(1);
    }

    let ttlv_diag_str = std::fs::read_to_string(&args[1]).expect("Failed to read the input file");

    let mut pretty_printer = PrettyPrinter::new();
    pretty_printer.with_tag_prefix("4200".into());
    pretty_printer.with_tag_map(tag_map::make_kmip_tag_map());

    println!("{}", pretty_printer.from_diag_string(&ttlv_diag_str));
}
