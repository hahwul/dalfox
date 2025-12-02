//! Dalfox XSS Scanner Library
//!
//! This library provides XSS scanning capabilities including:
//! - Parameter analysis and discovery
//! - XSS payload generation and encoding
//! - Reflection and DOM-based XSS detection
//! - AST-based JavaScript analysis

pub mod cmd;
pub mod config;
pub mod encoding;
pub mod mcp;
pub mod parameter_analysis;
pub mod payload;
pub mod scanning;
pub mod target_parser;
pub mod utils;

pub use std::sync::atomic::AtomicBool;
pub use std::sync::atomic::AtomicU64;

pub static DEBUG: AtomicBool = AtomicBool::new(false);
pub static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
