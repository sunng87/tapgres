//! Library crate: the reusable pieces of tapgres.
//!
//! `main.rs` (the binary) wires these together with libpcap; the integration
//! tests exercise them directly.

pub mod capture;
pub mod decode;
pub mod filter;
pub mod flow;
pub mod net;
pub mod proxy;
pub mod state;
pub mod tui;
