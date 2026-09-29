use kmip_protocol::{
    net::{ClientServer, NetError, NetResult},
    types::traits::ReadWrite,
};
use tracing::{Level, error};

use crate::config::Opt;

pub(crate) fn init_logging(opt: &Opt) {
    let level = match (opt.quiet, opt.verbose) {
        (true, _) => Level::ERROR,
        (false, 1) => Level::DEBUG,
        (false, n) if n >= 2 => Level::TRACE,
        _ => Level::INFO,
    };
    // simple_logging::log_to_stderr(level);
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

pub(crate) trait SelfLoggingError<T: ReadWrite, U> {
    fn log_error(self, client: &ClientServer<T>) -> Self;
}

impl<T: ReadWrite, U> SelfLoggingError<T, U> for NetResult<U> {
    fn log_error(self, _client: &ClientServer<T>) -> Self {
        if let Err(err) = &self {
            if let NetError::DeserializeError { err, req, res } = err {
                error!(
                    "{err}: [req: {}, res: {}]",
                    hex::encode_upper(req),
                    hex::encode_upper(res),
                );
            } else {
                error!("{err}");
            }
        }
        self
    }
}
