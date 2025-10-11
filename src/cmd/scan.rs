use clap::Args;
use indicatif::MultiProgress;
use std::fs;
use std::io::{self, Read};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::parameter_analysis::analyze_parameters;
use crate::scanning::result::Result;
use crate::target_parser::*;

fn extract_context(response: &str, payload: &str) -> Option<(usize, String)> {
    for (line_num, line) in response.lines().enumerate() {
        if line.contains(payload) {
            let mut context = line.to_string();
            if context.len() > 40 {
                if let Some(pos) = line.find(payload) {
                    let start = pos.saturating_sub(20);
                    let end = (pos + payload.len() + 20).min(line.len());
                    context = line[start..end].to_string();
                } else {
                    context = context.chars().take(40).collect();
                }
            }
            return Some((line_num + 1, context));
        }
    }
    None
}

#[derive(Clone, Args)]
pub struct ScanArgs {
    #[clap(help_heading = "INPUT")]
    /// Input type: auto, url, file, pipe, raw-http
    #[arg(short = 'i', long, default_value = "auto")]
    pub input_type: String,

    #[clap(help_heading = "OUTPUT")]
    /// Output format: json, jsonl, plain
    #[arg(short, long, default_value = "plain")]
    pub format: String,

    #[clap(help_heading = "OUTPUT")]
    /// Write output to a file. Example: -o 'output.txt'
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    #[clap(help_heading = "OUTPUT")]
    /// Include HTTP request information in output
    #[arg(long)]
    pub include_request: bool,

    #[clap(help_heading = "OUTPUT")]
    /// Include HTTP response information in output
    #[arg(long)]
    pub include_response: bool,

    #[clap(help_heading = "OUTPUT")]
    /// Silence all logs except POC output to STDOUT
    #[arg(long)]
    pub silence: bool,

    #[clap(help_heading = "TARGETS")]
    /// Targets (URLs or file paths)
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    #[clap(help_heading = "TARGETS")]
    /// Specify parameter names to analyze (e.g., -p sort -p id:query). Types: query, body, json, cookie, header.
    #[arg(short = 'p', long)]
    pub param: Vec<String>,

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

    #[clap(help_heading = "NETWORK")]
    /// Follow HTTP redirects. Example: -F
    #[arg(short = 'F', long)]
    pub follow_redirects: bool,

    #[clap(help_heading = "ENGINE")]
    /// Number of concurrent workers
    #[arg(long, default_value = "10")]
    pub workers: usize,

    #[clap(help_heading = "ENGINE")]
    /// Maximum number of concurrent targets to scan
    #[arg(long, default_value = "10")]
    pub max_concurrent_targets: usize,

    #[clap(help_heading = "ENGINE")]
    /// Maximum number of targets per host
    #[arg(long, default_value = "100")]
    pub max_targets_per_host: usize,

    #[clap(help_heading = "XSS SCANNING")]
    /// Specify payload encoders to use (comma-separated). Options: none, url, 2url, html, base64. Default: url,html
    #[arg(short = 'e', long, value_delimiter = ',', default_values = &["url", "html"])]
    pub encoders: Vec<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Load custom blind XSS payloads from a file. Example: --custom-blind-xss-payload 'payloads.txt'
    #[arg(long)]
    pub custom_blind_xss_payload: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Load custom payloads from a file. Example: --custom-payload 'payloads.txt'
    #[arg(long)]
    pub custom_payload: Option<String>,

    #[clap(help_heading = "XSS SCANNING")]
    /// Only test custom payloads. Example: --only-custom-payload --custom-payload=p.txt
    #[arg(long)]
    pub only_custom_payload: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Common XSS payloads only
    #[arg(long)]
    pub fast_scan: bool,

    #[clap(help_heading = "XSS SCANNING")]
    /// Skip XSS scanning entirely
    #[arg(long)]
    pub skip_xss_scanning: bool,
}

pub async fn run_scan(args: &ScanArgs) {
    let input_type = if args.input_type == "auto" {
        if args.targets.is_empty() {
            if !args.silence {
                eprintln!("Error: No targets specified");
            }
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
                    if !args.silence {
                        eprintln!("Error: No file specified for input-type=file");
                    }
                    return;
                }
                let file_path = &args.targets[0];
                match fs::read_to_string(file_path) {
                    Ok(content) => content.lines().map(|s| s.to_string()).collect(),
                    Err(e) => {
                        if !args.silence {
                            eprintln!("Error reading file {}: {}", file_path, e);
                        }
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
                        if !args.silence {
                            eprintln!("Error reading from stdin: {}", e);
                        }
                        return;
                    }
                }
            }
            "raw-http" => {
                // TODO: Implement raw HTTP request handling
                if !args.silence {
                    eprintln!("raw-http input-type not implemented yet");
                }
                return;
            }

            _ => {
                if !args.silence {
                    eprintln!(
                        "Error: Invalid input-type '{}'. Use 'auto', 'url', 'file', 'pipe', or 'raw-http'",
                        input_type
                    );
                }
                return;
            }
        };
    }

    if target_strings.is_empty() {
        if !args.silence {
            eprintln!("Error: No targets specified");
        }
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
                } else {
                    target.user_agent = Some("".to_string());
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
                target.follow_redirects = args.follow_redirects;
                target.workers = args.workers;
                parsed_targets.push(target);
            }
            Err(e) => {
                if !args.silence {
                    eprintln!("Error parsing target '{}': {}", s, e);
                }
                return;
            }
        }
    }

    if parsed_targets.is_empty() {
        if !args.silence {
            eprintln!("Error: No targets specified");
        }
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
                if !args.silence {
                    eprintln!("Error reading cookie file: {}", path);
                }
            }
        }
    }

    let results = Arc::new(Mutex::new(Vec::<Result>::new()));

    let multi_pb = if args.silence {
        None
    } else {
        Some(Arc::new(MultiProgress::new()))
    };

    // Group targets by host
    let mut host_groups: std::collections::HashMap<String, Vec<Target>> =
        std::collections::HashMap::new();
    for target in parsed_targets {
        let host = target.url.host_str().unwrap_or("unknown").to_string();
        host_groups.entry(host).or_insert(Vec::new()).push(target);
    }

    // Analyze parameters for each target sequentially to avoid Send issues
    for group in host_groups.values_mut() {
        // Limit targets per host
        if group.len() > args.max_targets_per_host {
            group.truncate(args.max_targets_per_host);
        }
        for target in group {
            analyze_parameters(target, &args, multi_pb.clone()).await;
        }
    }

    // Semaphore for limiting concurrent targets across all hosts
    let global_semaphore = Arc::new(tokio::sync::Semaphore::new(args.max_concurrent_targets));

    let mut group_handles = vec![];

    for (host, group) in host_groups {
        let global_semaphore_clone = global_semaphore.clone();
        let multi_pb_clone = multi_pb.clone();
        let args_arc = Arc::new(args.clone());
        let results_clone = results.clone();

        let group_handle = tokio::spawn(async move {
            // Calculate total overall tasks for this group
            let mut total_overall_tasks = 0u64;
            for target in &group {
                for param in &target.reflection_params {
                    let payloads = if let Some(context) = &param.injection_context {
                        crate::scanning::dynamic::get_dynamic_payloads(context, &args_arc)
                            .unwrap_or_else(|_| vec![])
                    } else {
                        crate::scanning::common::get_payloads(&args_arc).unwrap_or_else(|_| vec![])
                    };
                    total_overall_tasks += payloads.len() as u64;
                }
            }

            let overall_pb: Option<Arc<Mutex<indicatif::ProgressBar>>> = if let Some(ref mp) =
                multi_pb_clone
            {
                let pb = mp.add(indicatif::ProgressBar::new(total_overall_tasks));
                pb.set_style(
                    indicatif::ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} Overall scanning")
                        .unwrap()
                        .progress_chars("#>-"),
                );
                Some(Arc::new(Mutex::new(pb)))
            } else {
                None
            };

            let mut target_handles = vec![];

            for target in group {
                let permit = global_semaphore_clone
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap();
                let args_clone = args_arc.clone();
                let results_clone_inner = results_clone.clone();
                let multi_pb_clone_inner = multi_pb_clone.clone();
                let overall_pb_clone = overall_pb.clone();

                let target_handle = tokio::spawn(async move {
                    if !args_clone.skip_xss_scanning {
                        crate::scanning::run_scanning(
                            &target,
                            &args_clone,
                            results_clone_inner,
                            multi_pb_clone_inner,
                            overall_pb_clone,
                        )
                        .await;
                    }
                    drop(permit);
                });
                target_handles.push(target_handle);
            }

            for handle in target_handles {
                handle.await.unwrap();
            }

            if let Some(pb) = overall_pb {
                pb.lock()
                    .await
                    .finish_with_message(format!("All scanning completed for {}", host));
            }
        });
        group_handles.push(group_handle);
    }

    for handle in group_handles {
        handle.await.unwrap();
    }

    // Output results
    let final_results = results.lock().await;
    let output_content = if args.format == "json" {
        serde_json::to_string_pretty(&*final_results).unwrap()
    } else if args.format == "jsonl" {
        let mut output = String::new();
        for result in &*final_results {
            output.push_str(&serde_json::to_string(&result).unwrap());
            output.push('\n');
        }
        output
    } else if args.format == "plain" {
        let mut output = String::new();
        for result in &*final_results {
            output.push_str(&format!(
                "[POC][V][{}][{}] {}\n",
                result.method, result.inject_type, result.data
            ));
            if !args.silence {
                eprintln!("   \x1b[90mPayload: {}\x1b[0m\n", result.payload);
                if let Some(resp) = &result.response {
                    if let Some((line_num, context)) = extract_context(resp, &result.payload) {
                        eprintln!("   \x1b[90mL{}: {}\x1b[0m\n", line_num, context);
                    }
                }
            }
        }
        output
    } else {
        let mut output = String::new();
        for result in &*final_results {
            output.push_str(&format!(
                "Found XSS: {} - {}\n",
                result.param, result.payload
            ));
        }
        output
    };

    if let Some(output_path) = &args.output {
        match std::fs::write(output_path, &output_content) {
            Ok(_) => {
                if !args.silence {
                    println!("Results written to {}", output_path);
                }
            }
            Err(e) => {
                if !args.silence {
                    eprintln!("Error writing to file {}: {}", output_path, e);
                }
            }
        }
    } else {
        println!("{}", output_content);
    }

    // Include request/response if requested
    if args.include_request || args.include_response {
        for result in &*final_results {
            if args.include_request {
                if let Some(request) = &result.request {
                    println!("Request:\n{}", request);
                }
            }
            if args.include_response {
                if let Some(response) = &result.response {
                    println!("Response:\n{}", response);
                }
            }
            println!("---");
        }
    }
}
