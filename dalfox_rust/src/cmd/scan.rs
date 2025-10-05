use clap::Args;
use std::fs;
use std::io::{self, Read};

#[derive(Args)]
pub struct ScanArgs {
    /// Input type: auto, url, file, raw-http
    #[arg(long, default_value = "auto")]
    pub input_type: String,

    /// Output format
    #[arg(short, long, default_value = "json")]
    pub format: String,

    /// Targets (URLs or file paths)
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
}

pub fn run_scan(args: ScanArgs) {
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

    let mut targets = Vec::new();

    if input_type == "auto" {
        for target in &args.targets {
            if target.starts_with("http://") || target.starts_with("https://") {
                targets.push(target.clone());
            } else {
                // Assume it's a file
                match fs::read_to_string(target) {
                    Ok(content) => {
                        for line in content.lines() {
                            targets.push(line.to_string());
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading file {}: {}", target, e);
                        return;
                    }
                }
            }
        }
    } else {
        targets = match input_type.as_str() {
            "url" => args.targets,
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
                    Ok(_) => buffer.lines().map(|s| s.to_string()).collect(),
                    Err(e) => {
                        eprintln!("Error reading from stdin: {}", e);
                        return;
                    }
                }
            }
            "raw-http" => {
                println!(
                    "Scanning with input-type: raw-http, format: {}",
                    args.format
                );
                // TODO: Implement raw HTTP request handling
                eprintln!("raw-http input-type not implemented yet");
                return;
            }
            _ => {
                eprintln!(
                    "Error: Invalid input-type '{}'. Use 'auto', 'url', 'file', or 'raw-http'",
                    input_type
                );
                return;
            }
        };
    }

    if targets.is_empty() {
        eprintln!("Error: No targets specified");
        return;
    }

    println!(
        "Scanning with input-type: {}, format: {}",
        input_type, args.format
    );
    for target in targets {
        println!("Target: {}", target);
        // TODO: Implement actual scanning logic for each target
    }
}
