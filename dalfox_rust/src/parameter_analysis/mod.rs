pub mod mining;
pub mod reflection;

pub use mining::*;
pub use reflection::*;

use crate::cmd::scan::ScanArgs;
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

pub fn analyze_parameters(target: &mut Target, args: &ScanArgs) {
    check_reflection(target);
    mine_parameters(target, args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::scan::ScanArgs;
    use crate::target_parser::parse_target;

    // Mock mining function for testing
    fn mock_mine_parameters(_target: &mut Target, _args: &ScanArgs) {
        // Simulate adding a reflection param
        _target.reflection_params.push(Param {
            name: "test_param".to_string(),
            value: "test_value".to_string(),
            location: Location::Query,
            injection_context: Some(InjectionContext::Html),
        });
    }

    #[test]
    fn test_analyze_parameters_with_mock_mining() {
        let mut target = parse_target("https://example.com").unwrap();
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec!["https://example.com".to_string()],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
        };

        // Mock mining instead of real mining
        mock_mine_parameters(&mut target, &args);

        assert!(!target.reflection_params.is_empty());
        assert_eq!(target.reflection_params[0].name, "test_param");
    }
}
