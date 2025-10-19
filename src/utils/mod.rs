/*!
Utility helpers for Dalfox.

This module re-exports commonly used helpers so other modules can simply
`use crate::utils::*;` or import the specific functions directly.
*/

pub mod banner;
pub mod scan_id;

// Re-export banner helpers at `crate::utils::*`
pub use banner::{print_banner, print_banner_once, render_banner};
// Re-export scan_id helpers at `crate::utils::*`
pub use scan_id::{make_scan_id, make_scan_id_with_nonce, short_scan_id};
