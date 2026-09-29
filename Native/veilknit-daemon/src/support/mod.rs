//! Small shared utilities that do not own network state.
//!
//! Keeping clocks, backoff, and sliding-window accounting here prevents each
//! protocol module from inventing subtly different timer behavior.

pub mod timing;
