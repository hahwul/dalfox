use crate::parameter_analysis::Param;
use url::Url;

#[derive(Debug)]
pub struct Target {
    pub url: Url,
    pub method: String,
    pub data: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub user_agent: Option<String>,
    pub reflection_params: Vec<Param>,
}

pub fn parse_target(s: &str) -> Result<Target, Box<dyn std::error::Error>> {
    let url_str = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{}", s)
    };
    let url = Url::parse(&url_str)?;
    Ok(Target {
        url,
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        reflection_params: vec![],
    })
}
