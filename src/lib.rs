//! Library crate: the reusable pieces of pgwiretap.
//!
//! `main.rs` (the binary) wires these together with libpcap; the integration
//! tests exercise them directly.

pub mod decode;
pub mod flow;
pub mod net;
