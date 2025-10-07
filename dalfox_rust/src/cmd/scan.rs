use clap::Args;
use std::fs;
use std::io::{self, Read};

use crate::parameter_analysis::analyze_parameters;
use crate::target_parser::*;

#[derive(Args)]
pub struct ScanArgs {
    #[clap(help_heading = "INPUT")]
    /// Input type: auto, url, file, pipe, raw-http
    #[arg(short = 'i', long, default_value = "auto")]
    pub input_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Output format
    #[arg(short, long, default_value = "json")]
    pub format: String,

    #[clap(help_heading = "TARGETS")]
    /// Targets (URLs or file paths)
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    #[clap(help_heading = "TARGETS")]
    /// HTTP request body data
    #[arg(short = 'd', long)]
    pub data: Option<String>,

    #[clap(help_heading = "TARGETS")]
    /// HTTP headers (can be specified multiple times)
    #[arg(short = 'H', long)]
    pub headers: Vec<String>,

    #[clap(help_heading = "TARGETS")]
    /// Cookies (can be specified multiple times)
    #[arg(long)]
    pub cookies: Vec<String>,

    #[clap(help_heading = "TARGETS")]
    /// Override the HTTP method. Example: -X 'PUT' (default "GET")
    #[arg(short = 'X', long, default_value = "GET")]
    pub method: String,

    #[clap(help_heading = "TARGETS")]
    /// Set a custom User-Agent header. Example: --user-agent 'Mozilla/5.0'
    #[arg(long)]
    pub user_agent: Option<String>,

    #[clap(help_heading = "TARGETS")]
    /// Load cookies from a raw HTTP request file. Example: --cookie-from-raw 'request.txt'
    #[arg(long)]
    pub cookie_from_raw: Option<String>,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Skip all discovery checks
    #[arg(long)]
    pub skip_discovery: bool,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Skip header-based reflection checks
    #[arg(long)]
    pub skip_reflection_header: bool,

    #[clap(help_heading = "PARAMETER DISCOVERY")]
    /// Skip cookie-based reflection checks
    #[arg(long)]
    pub skip_reflection_cookie: bool,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Dictionary analysis with wordlist file path
    #[arg(short = 'W', long)]
    pub mining_dict_word: Option<String>,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Skip all mining
    #[arg(long)]
    pub skip_mining: bool,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Skip dictionary-based mining
    #[arg(long)]
    pub skip_mining_dict: bool,

    #[clap(help_heading = "PARAMETER MINING")]
    /// Skip DOM-based mining
    #[arg(long)]
    pub skip_mining_dom: bool,

    #[clap(help_heading = "NETWORK")]
    /// Timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    #[clap(help_heading = "NETWORK")]
    /// Delay in milliseconds
    #[arg(long, default_value = "0")]
    pub delay: u64,

    #[clap(help_heading = "NETWORK")]
    /// Proxy URL (e.g., http://localhost:8080)
    #[arg(long)]
    pub proxy: Option<String>,

    #[clap(help_heading = "ENGINE")]
    /// Number of concurrent workers
    #[arg(long, default_value = "10")]
    pub workers: usize,
}

pub async fn run_scan(args: &ScanArgs) {
    let input_type = if args.input_type == "auto" {
        if args.targets.is_empty() {
            eprintln!("Error: No targets specified");
            return;
        }
        // Check if all targets look like raw HTTP requests
        let is_raw_http = args.targets.iter().all(|t| {
            t.starts_with("GET ")
                || t.starts_with("POST ")
                || t.starts_with("PUT ")
                || t.starts_with("DELETE ")
                || t.starts_with("HEAD ")
                || t.starts_with("OPTIONS ")
                || t.starts_with("PATCH ")
        });
        if is_raw_http {
            "raw-http".to_string()
        } else {
            "auto".to_string()
        }
    } else {
        args.input_type.clone()
    };

    let mut target_strings = Vec::new();

    if input_type == "auto" {
        for target in &args.targets {
            if target.contains("://") {
                target_strings.push(target.clone());
            } else {
                // Try as file first
                match fs::read_to_string(target) {
                    Ok(content) => {
                        for line in content.lines() {
                            let line = line.trim();
                            if !line.is_empty() {
                                target_strings.push(line.to_string());
                            }
                        }
                    }
                    Err(_) => {
                        // Not a file, treat as URL
                        target_strings.push(target.clone());
                    }
                }
            }
        }
    } else {
        target_strings = match input_type.as_str() {
            "url" => args.targets.clone(),
            "file" => {
                if args.targets.is_empty() {
                    eprintln!("Error: No file specified for input-type=file");
                    return;
                }
                let file_path = &args.targets[0];
                match fs::read_to_string(file_path) {
                    Ok(content) => content.lines().map(|s| s.to_string()).collect(),
                    Err(e) => {
                        eprintln!("Error reading file {}: {}", file_path, e);
                        return;
                    }
                }
            }
            "pipe" => {
                let mut buffer = String::new();
                match io::stdin().read_to_string(&mut buffer) {
                    Ok(_) => buffer
                        .lines()
                        .filter_map(|line| {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed.to_string())
                            }
                        })
                        .collect(),
                    Err(e) => {
                        eprintln!("Error reading from stdin: {}", e);
                        return;
                    }
                }
            }
            "raw-http" => {
                // TODO: Implement raw HTTP request handling
                eprintln!("raw-http input-type not implemented yet");
                return;
            }

            _ => {
                eprintln!(
                    "Error: Invalid input-type '{}'. Use 'auto', 'url', 'file', 'pipe', or 'raw-http'",
                    input_type
                );
                return;
            }
        };
    }

    if target_strings.is_empty() {
        eprintln!("Error: No targets specified");
        return;
    }

    let mut parsed_targets = Vec::new();
    for s in target_strings {
        match parse_target(&s) {
            Ok(mut target) => {
                target.data = args.data.clone();
                target.headers = args
                    .headers
                    .iter()
                    .filter_map(|h| h.split_once(": "))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                target.method = args.method.clone();
                if let Some(ua) = &args.user_agent {
                    target.headers.push(("User-Agent".to_string(), ua.clone()));
                    target.user_agent = Some(ua.clone());
                }
                target.cookies = args
                    .cookies
                    .iter()
                    .filter_map(|c| c.split_once("="))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                target.timeout = args.timeout;
                target.delay = args.delay;
                target.proxy = args.proxy.clone();
                target.workers = args.workers;
                parsed_targets.push(target);
            }
            Err(e) => {
                eprintln!("Error parsing target '{}': {}", s, e);
                return;
            }
        }
    }

    if parsed_targets.is_empty() {
        eprintln!("Error: No targets specified");
        return;
    }

    // Load cookies from raw HTTP request file if specified
    if let Some(path) = &args.cookie_from_raw {
        for target in &mut parsed_targets {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    if let Some(cookie_line) = line.strip_prefix("Cookie: ") {
                        for cookie in cookie_line.split("; ") {
                            if let Some((name, value)) = cookie.split_once('=') {
                                target
                                    .cookies
                                    .push((name.trim().to_string(), value.trim().to_string()));
                            }
                        }
                    }
                }
            } else {
                eprintln!("Error reading cookie file: {}", path);
            }
        }
    }

    // Analyze parameters for each target
    for target in &mut parsed_targets {
        analyze_parameters(target, &args).await;
    }

    println!(
        "Scanning with input-type: {}, format: {}",
        input_type, args.format
    );
    for target in &parsed_targets {
        println!(
            "Target: {} method: {}, user_agent: {:?}, data: {:?}, headers: {:?}, cookies: {:?}, reflection_params: {:?}, timeout: {}, delay: {}, proxy: {:?}, workers: {}",
            target.url,
            target.method,
            target.user_agent,
            target.data,
            target.headers,
            target.cookies,
            target.reflection_params,
            target.timeout,
            target.delay,
            target.proxy,
            target.workers
        );
        // TODO: Implement actual scanning logic for each target
    }
}
