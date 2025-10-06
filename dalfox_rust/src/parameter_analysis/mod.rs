pub mod mining;
pub mod reflection;

pub use mining::*;
pub use reflection::*;

use crate::target_parser::Target;

#[derive(Debug, Clone)]
pub enum Location {
    Query,
    Body,
    JsonBody,
    Header,
}

#[derive(Debug, Clone)]
pub enum InjectionContext {
    Html,
    Javascript,
    Comment,
    Attribute,
    StringSingle,
    StringDouble,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub value: String,
    pub location: Location,
    pub injection_context: Option<InjectionContext>,
}

pub fn analyze_parameters(target: &mut Target) {
    check_reflection(target);
    mine_parameters(target);
}
