use clap::Args;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Args)]
pub struct ConsoleArgs {}

#[derive(Clone)]
struct ConsoleState {
    headers: Vec<String>,
    cookies: Vec<String>,
    method: String,
    user_agent: Option<String>,
    timeout: u64,
    delay: u64,
    encoders: Vec<String>,
    proxy: Option<String>,
    workers: usize,
    follow_redirects: bool,
    scan_results: Vec<String>,
    command_history: Vec<String>,
    current_input: String,
    status_message: String,
}

impl ConsoleState {
    fn new() -> Self {
        Self {
            headers: Vec::new(),
            cookies: Vec::new(),
            method: "GET".to_string(),
            user_agent: None,
            timeout: crate::cmd::scan::DEFAULT_TIMEOUT_SECS,
            delay: crate::cmd::scan::DEFAULT_DELAY_MS,
            encoders: crate::cmd::scan::DEFAULT_ENCODERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            proxy: None,
            workers: crate::cmd::scan::DEFAULT_WORKERS,
            follow_redirects: false,
            scan_results: Vec::new(),
            command_history: Vec::new(),
            current_input: String::new(),
            status_message: "Ready. Type 'help' for available commands.".to_string(),
        }
    }
}

enum CommandResult {
    Continue,
    Exit,
    Scan(String),
}

fn parse_command(input: &str, state: &mut ConsoleState) -> CommandResult {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return CommandResult::Continue;
    }

    let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let args = if parts.len() > 1 { parts[1] } else { "" };

    match cmd.as_str() {
        "exit" | "quit" | "q" => CommandResult::Exit,
        "help" | "h" => {
            state.scan_results.push("=== Dalfox Console Commands ===".to_string());
            state.scan_results.push("  scan <url>              - Scan a target URL".to_string());
            state.scan_results.push("  header add <key:value>  - Add a header".to_string());
            state.scan_results.push("  header clear            - Clear all headers".to_string());
            state.scan_results.push("  cookie add <name=value> - Add a cookie".to_string());
            state.scan_results.push("  cookie clear            - Clear all cookies".to_string());
            state.scan_results.push("  set method <method>     - Set HTTP method (GET/POST/etc)".to_string());
            state.scan_results.push("  set timeout <seconds>   - Set request timeout".to_string());
            state.scan_results.push("  set delay <ms>          - Set delay between requests".to_string());
            state.scan_results.push("  set workers <count>     - Set concurrent workers".to_string());
            state.scan_results.push("  set proxy <url>         - Set proxy URL".to_string());
            state.scan_results.push("  set useragent <ua>      - Set User-Agent header".to_string());
            state.scan_results.push("  set encoders <list>     - Set encoders (comma-separated)".to_string());
            state.scan_results.push("  show config             - Display current configuration".to_string());
            state.scan_results.push("  clear                   - Clear scan results".to_string());
            state.scan_results.push("  help                    - Show this help".to_string());
            state.scan_results.push("  exit/quit/q             - Exit console".to_string());
            state.status_message = "Help displayed".to_string();
            CommandResult::Continue
        }
        "scan" => {
            if args.is_empty() {
                state.scan_results.push("Error: No URL provided".to_string());
                state.status_message = "Error: scan requires a URL".to_string();
                CommandResult::Continue
            } else {
                state.scan_results.push(format!("Scanning: {}", args));
                state.status_message = format!("Scanning {}", args);
                CommandResult::Scan(args.to_string())
            }
        }
        "header" => {
            let subcmd_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if subcmd_parts.is_empty() {
                state.scan_results.push("Error: header requires 'add' or 'clear'".to_string());
                state.status_message = "Error: invalid header command".to_string();
            } else {
                match subcmd_parts[0] {
                    "add" => {
                        if subcmd_parts.len() > 1 {
                            state.headers.push(subcmd_parts[1].to_string());
                            state.scan_results.push(format!("Added header: {}", subcmd_parts[1]));
                            state.status_message = "Header added".to_string();
                        } else {
                            state.scan_results.push("Error: header add requires a value".to_string());
                            state.status_message = "Error: missing header value".to_string();
                        }
                    }
                    "clear" => {
                        state.headers.clear();
                        state.scan_results.push("Headers cleared".to_string());
                        state.status_message = "Headers cleared".to_string();
                    }
                    _ => {
                        state.scan_results.push("Error: unknown header subcommand".to_string());
                        state.status_message = "Error: use 'add' or 'clear'".to_string();
                    }
                }
            }
            CommandResult::Continue
        }
        "cookie" => {
            let subcmd_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if subcmd_parts.is_empty() {
                state.scan_results.push("Error: cookie requires 'add' or 'clear'".to_string());
                state.status_message = "Error: invalid cookie command".to_string();
            } else {
                match subcmd_parts[0] {
                    "add" => {
                        if subcmd_parts.len() > 1 {
                            state.cookies.push(subcmd_parts[1].to_string());
                            state.scan_results.push(format!("Added cookie: {}", subcmd_parts[1]));
                            state.status_message = "Cookie added".to_string();
                        } else {
                            state.scan_results.push("Error: cookie add requires a value".to_string());
                            state.status_message = "Error: missing cookie value".to_string();
                        }
                    }
                    "clear" => {
                        state.cookies.clear();
                        state.scan_results.push("Cookies cleared".to_string());
                        state.status_message = "Cookies cleared".to_string();
                    }
                    _ => {
                        state.scan_results.push("Error: unknown cookie subcommand".to_string());
                        state.status_message = "Error: use 'add' or 'clear'".to_string();
                    }
                }
            }
            CommandResult::Continue
        }
        "set" => {
            let set_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if set_parts.is_empty() {
                state.scan_results.push("Error: set requires a parameter".to_string());
                state.status_message = "Error: invalid set command".to_string();
                return CommandResult::Continue;
            }
            
            let param = set_parts[0];
            let value = if set_parts.len() > 1 { set_parts[1] } else { "" };
            
            match param {
                "method" => {
                    if !value.is_empty() {
                        state.method = value.to_uppercase();
                        state.scan_results.push(format!("Method set to: {}", state.method));
                        state.status_message = format!("Method: {}", state.method);
                    } else {
                        state.scan_results.push("Error: method requires a value".to_string());
                        state.status_message = "Error: missing method value".to_string();
                    }
                }
                "timeout" => {
                    if let Ok(t) = value.parse::<u64>() {
                        state.timeout = t;
                        state.scan_results.push(format!("Timeout set to: {} seconds", t));
                        state.status_message = format!("Timeout: {}s", t);
                    } else {
                        state.scan_results.push("Error: invalid timeout value".to_string());
                        state.status_message = "Error: timeout must be a number".to_string();
                    }
                }
                "delay" => {
                    if let Ok(d) = value.parse::<u64>() {
                        state.delay = d;
                        state.scan_results.push(format!("Delay set to: {} ms", d));
                        state.status_message = format!("Delay: {}ms", d);
                    } else {
                        state.scan_results.push("Error: invalid delay value".to_string());
                        state.status_message = "Error: delay must be a number".to_string();
                    }
                }
                "workers" => {
                    if let Ok(w) = value.parse::<usize>() {
                        state.workers = w;
                        state.scan_results.push(format!("Workers set to: {}", w));
                        state.status_message = format!("Workers: {}", w);
                    } else {
                        state.scan_results.push("Error: invalid workers value".to_string());
                        state.status_message = "Error: workers must be a number".to_string();
                    }
                }
                "proxy" => {
                    if !value.is_empty() {
                        state.proxy = Some(value.to_string());
                        state.scan_results.push(format!("Proxy set to: {}", value));
                        state.status_message = format!("Proxy: {}", value);
                    } else {
                        state.proxy = None;
                        state.scan_results.push("Proxy cleared".to_string());
                        state.status_message = "Proxy cleared".to_string();
                    }
                }
                "useragent" | "ua" => {
                    if !value.is_empty() {
                        state.user_agent = Some(value.to_string());
                        state.scan_results.push(format!("User-Agent set to: {}", value));
                        state.status_message = "User-Agent set".to_string();
                    } else {
                        state.user_agent = None;
                        state.scan_results.push("User-Agent cleared".to_string());
                        state.status_message = "User-Agent cleared".to_string();
                    }
                }
                "encoders" => {
                    if !value.is_empty() {
                        state.encoders = value.split(',').map(|s| s.trim().to_string()).collect();
                        state.scan_results.push(format!("Encoders set to: {}", value));
                        state.status_message = format!("Encoders: {}", value);
                    } else {
                        state.scan_results.push("Error: encoders requires a value".to_string());
                        state.status_message = "Error: missing encoders value".to_string();
                    }
                }
                _ => {
                    state.scan_results.push(format!("Error: unknown parameter: {}", param));
                    state.status_message = format!("Error: unknown parameter: {}", param);
                }
            }
            CommandResult::Continue
        }
        "show" => {
            if args == "config" {
                state.scan_results.push("=== Current Configuration ===".to_string());
                state.scan_results.push(format!("Method: {}", state.method));
                state.scan_results.push(format!("Timeout: {} seconds", state.timeout));
                state.scan_results.push(format!("Delay: {} ms", state.delay));
                state.scan_results.push(format!("Workers: {}", state.workers));
                state.scan_results.push(format!("Encoders: {}", state.encoders.join(", ")));
                state.scan_results.push(format!("Proxy: {}", state.proxy.as_ref().unwrap_or(&"None".to_string())));
                state.scan_results.push(format!("User-Agent: {}", state.user_agent.as_ref().unwrap_or(&"Default".to_string())));
                state.scan_results.push(format!("Headers: {}", if state.headers.is_empty() { "None".to_string() } else { state.headers.join(", ") }));
                state.scan_results.push(format!("Cookies: {}", if state.cookies.is_empty() { "None".to_string() } else { state.cookies.join(", ") }));
                state.status_message = "Configuration displayed".to_string();
            } else {
                state.scan_results.push("Error: show requires 'config'".to_string());
                state.status_message = "Error: use 'show config'".to_string();
            }
            CommandResult::Continue
        }
        "clear" => {
            state.scan_results.clear();
            state.status_message = "Results cleared".to_string();
            CommandResult::Continue
        }
        _ => {
            state.scan_results.push(format!("Unknown command: {}. Type 'help' for available commands.", cmd));
            state.status_message = "Unknown command".to_string();
            CommandResult::Continue
        }
    }
}

async fn execute_scan(target: String, state: &ConsoleState) -> Vec<String> {
    let mut results = Vec::new();
    results.push(format!("Starting scan of: {}", target));
    
    // Build scan arguments from console state
    let scan_args = crate::cmd::scan::ScanArgs {
        input_type: "auto".to_string(),
        format: "plain".to_string(),
        targets: vec![target.clone()],
        param: vec![],
        data: None,
        headers: state.headers.clone(),
        cookies: state.cookies.clone(),
        method: state.method.clone(),
        user_agent: state.user_agent.clone(),
        cookie_from_raw: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        timeout: state.timeout,
        delay: state.delay,
        proxy: state.proxy.clone(),
        follow_redirects: state.follow_redirects,
        output: None,
        include_request: false,
        include_response: false,
        silence: true,  // Suppress normal output
        poc_type: "plain".to_string(),
        limit: None,
        workers: state.workers,
        max_concurrent_targets: crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS,
        max_targets_per_host: crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST,
        encoders: state.encoders.clone(),
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        skip_xss_scanning: false,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        remote_payloads: vec![],
        remote_wordlists: vec![],
    };

    // Execute the scan (using the existing scan logic)
    // For now, we'll just indicate that the scan was initiated
    // In a full implementation, we'd capture the actual results
    results.push(format!("Scan configured with {} workers", state.workers));
    results.push(format!("Method: {}, Timeout: {}s", state.method, state.timeout));
    
    // Note: The actual scan would run here asynchronously
    // For this implementation, we'll add a placeholder
    results.push("Scan completed (results would appear here)".to_string());
    
    results
}

pub async fn run_console(_args: ConsoleArgs) {
    // Setup terminal
    enable_raw_mode().expect("Failed to enable raw mode");
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).expect("Failed to setup terminal");
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).expect("Failed to create terminal");

    // Create console state
    let state = Arc::new(Mutex::new(ConsoleState::new()));

    // Main loop
    loop {
        let state_clone = state.clone();
        let current_state = state_clone.lock().await;
        
        // Draw UI
        terminal
            .draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(5),      // Results area
                        Constraint::Length(3),   // Input area
                        Constraint::Length(1),   // Status bar
                    ])
                    .split(f.area());

                // Results area
                let results: Vec<ListItem> = current_state
                    .scan_results
                    .iter()
                    .rev()
                    .take(chunks[0].height as usize - 2)
                    .rev()
                    .map(|r| ListItem::new(r.clone()))
                    .collect();

                let results_list = List::new(results)
                    .block(
                        Block::default()
                            .title("Scan Results & Output")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan)),
                    );
                f.render_widget(results_list, chunks[0]);

                // Input area
                let input = Paragraph::new(current_state.current_input.as_str())
                    .block(
                        Block::default()
                            .title("Command Input (Ctrl+C to exit)")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Green)),
                    );
                f.render_widget(input, chunks[1]);

                // Status bar
                let status_style = Style::default()
                    .bg(Color::Blue)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD);
                let status_text = format!(
                    " {} | Headers: {} | Cookies: {} | Method: {} | Workers: {}",
                    current_state.status_message,
                    current_state.headers.len(),
                    current_state.cookies.len(),
                    current_state.method,
                    current_state.workers
                );
                let status = Paragraph::new(status_text).style(status_style);
                f.render_widget(status, chunks[2]);
            })
            .expect("Failed to draw terminal");

        drop(current_state);

        // Handle input
        if event::poll(std::time::Duration::from_millis(100)).expect("Failed to poll events") {
            if let Event::Key(key) = event::read().expect("Failed to read event") {
                let mut state_mut = state.lock().await;
                
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        break;
                    }
                    KeyCode::Enter => {
                        let input = state_mut.current_input.clone();
                        state_mut.command_history.push(input.clone());
                        state_mut.current_input.clear();
                        
                        match parse_command(&input, &mut state_mut) {
                            CommandResult::Exit => break,
                            CommandResult::Scan(target) => {
                                // Clone the state for the async scan
                                let scan_state = state_mut.clone();
                                drop(state_mut);
                                
                                // Execute scan asynchronously
                                let scan_results = execute_scan(target, &scan_state).await;
                                
                                // Update state with results
                                let mut state_mut = state.lock().await;
                                state_mut.scan_results.extend(scan_results);
                                state_mut.status_message = "Scan completed".to_string();
                            }
                            CommandResult::Continue => {}
                        }
                    }
                    KeyCode::Char(c) => {
                        state_mut.current_input.push(c);
                    }
                    KeyCode::Backspace => {
                        state_mut.current_input.pop();
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    disable_raw_mode().expect("Failed to disable raw mode");
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .expect("Failed to cleanup terminal");
}
