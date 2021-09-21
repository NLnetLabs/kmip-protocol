use kmip_protocol::client::Client;
use kmip_protocol::types::traits::ReadWrite;
use log::error;

use crate::config::Opt;

pub(crate) fn init_logging(opt: &Opt) {
    let level = match (opt.quiet, opt.verbose) {
        (true, _) => log::LevelFilter::Error,
        (false, 1) => log::LevelFilter::Debug,
        (false, n) if n >= 2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    simple_logging::log_to_stderr(level);
}

pub(crate) trait ToCsvString {
    fn to_csv_string(self) -> String;
}

impl<T> ToCsvString for Option<Vec<T>>
where
    T: ToString,
{
    fn to_csv_string(self) -> String {
        self.unwrap_or(Vec::new())
            .iter()
            .map(|op| op.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }
}

pub(crate) trait SelfLoggingError<T: ReadWrite, U> {
    fn log_error(self, client: &Client<T>) -> Self;
}

impl<T: ReadWrite, U> SelfLoggingError<T, U> for kmip_protocol::client::Result<U> {
    fn log_error(self, client: &Client<T>) -> Self {
        if let Err(err) = &self {
            error!(
                "{}: [req: {:?}, res: {:?}]",
                err,
                client.last_req_diag_str(),
                client.last_res_diag_str()
            );
        }
        self
    }
}
