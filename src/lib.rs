//! roBrowserLegacy Remote Client.
//!
//! The binary in `main.rs` is a thin wrapper around these modules; they are
//! public so the integration tests can drive the real router, the real index
//! and the real GRF reader rather than a stand-in for them.

pub mod cache;
pub mod client;
pub mod config;
pub mod des;
pub mod encoding;
pub mod grf;
pub mod http;
pub mod index;
pub mod logger;
pub mod routes;
pub mod util;
pub mod validator;
pub mod wsproxy;
