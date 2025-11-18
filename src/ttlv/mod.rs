//! Low-level TTLV (de)serialization.
//!
//! This module provides a fast TTLV scanner and formatter, without support for
//! how TTLV gets used within the KMIP protocol.

pub mod fast_scan;
pub mod format;
pub mod types;
