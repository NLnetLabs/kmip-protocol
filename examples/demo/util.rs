use tracing::Level;

use crate::config::Opt;

pub(crate) fn init_logging(opt: &Opt) {
    let level = match (opt.quiet, opt.verbose) {
        (true, _) => Level::ERROR,
        (false, 1) => Level::DEBUG,
        (false, n) if n >= 2 => Level::TRACE,
        _ => Level::INFO,
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}

pub(crate) trait ToCsvString {
    fn to_csv_string(self) -> String;
}

impl<T> ToCsvString for Option<Vec<T>>
where
    T: ToString,
{
    fn to_csv_string(self) -> String {
        self.unwrap_or_default()
            .iter()
            .map(|op| op.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }
}
