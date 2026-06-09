//! Functional tests for Dalfox
//!
//! This module contains functional tests that test the behavior of the
//! dalfox tool from a user's perspective.

pub mod basic;
// XSS mock server tests
pub mod xss_mock_server;
// Mock case loader for structured test case management
pub mod mock_case_loader;
// DOM XSS detection tests
pub mod dom_xss_tests;
// --analyze-external-js integration tests
pub mod analyze_external_js_test;
// Mining tests (placeholder)
// pub mod mining;
// Pipeline tests (placeholder)
// pub mod pipelines;
