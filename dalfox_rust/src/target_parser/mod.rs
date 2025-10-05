use url::Url;

#[derive(Debug)]
pub struct Target {
    pub url: Url,
    pub data: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
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
        data: None,
        headers: vec![],
        cookies: vec![],
    })
}
