//! Functional tests for Dalfox
//!
//! This module contains functional tests that test the behavior of the
//! dalfox tool from a user's perspective.

pub mod basic;
// XSS detection tests (requires mock server - placeholder)
pub mod xss_mock_server;
// New structured XSS mock server tests
pub mod xss_mock_server_v2;
// Mock case loader for structured test case management
pub mod mock_case_loader;
// Mining tests (placeholder)
// pub mod mining;
// Pipeline tests (placeholder)
// pub mod pipelines;
