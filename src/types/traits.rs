//! Dynamic traits for sync or async use depending on the Cargo features used.
//!
//! The `ReadWrite` trait is the set of traits used by the [Client](crate::client::Client) to read/write to a TLS
//! stream.
//!
//! The exact composition of the set is dependent on the Cargo feature flags used to compile this crate.
//!
//! | Feature Flag           | Traits included in the `ReadWrite` trait |
//! |------------------------|------------------------------------------|
//! | `sync` (default)       | `std::io::Read + std::io::Write`         |
//! | `async-with-tokio`     | `tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + std::marker::Unpin` |
//! | `async-with-async-std` | `async_std::io::ReadExt + async_std::io::WriteExt + std::marker::Unpin` |
//!
//! This enables code that is otherwise identical to be re-used.

cfg_if::cfg_if! {
    if #[cfg(feature = "sync")] {
        pub trait ReadWrite: std::io::Read + std::io::Write {}

        impl<T: ?Sized + std::io::Read + std::io::Write> ReadWrite for T {}
    } else if #[cfg(feature = "async-with-tokio")] {
        pub trait ReadWrite: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + std::marker::Unpin {}

        impl<T: ?Sized + tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + std::marker::Unpin> ReadWrite for T {}
    } else if #[cfg(feature = "async-with-async-std")] {
        pub trait ReadWrite: async_std::io::ReadExt + async_std::io::WriteExt + std::marker::Unpin {}

        impl<T: ?Sized + async_std::io::ReadExt + async_std::io::WriteExt + std::marker::Unpin> ReadWrite for T {}
    }
}
