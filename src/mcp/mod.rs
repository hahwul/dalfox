//! Dalfox MCP (Model Context Protocol) integration
//!
//! Exposes two MCP tools over stdio when `dalfox mcp` is executed:
//! 1. `scan_with_dalfox`  - Start an asynchronous XSS scan on a single target URL
//! 2. `get_results_dalfox` - Fetch status/results of a previously started scan
//!
//! Design goals (minimal blocking server):
//! - In-memory job storage only (no persistence)
//! - Non-blocking scans via `tokio::spawn`
//! - Lean tool schemas (only input params are schematized)
//! - Result output as JSON (string content) to avoid complex schema for findings
//!
//! Example client flow (conceptual):
//!   call_tool(name="scan_with_dalfox", arguments={"target":"https://example.com"})
//!     -> {"scan_id":"<id>","status":"queued"}
//!   call_tool(name="get_results_dalfox", arguments={"scan_id":"<id>"})
//!     -> {"scan_id":"<id>","status":"running"}
//!     -> {"scan_id":"<id>","status":"done","results":[ ... ]}
//!
//! The MCP runtime (stdio JSON-RPC) is provided by the `rmcp` crate.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use rmcp::{
    ErrorData,
    handler::server::tool::ToolRouter,
    model::{CallToolResult, Content, JsonObject},
    tool, tool_handler, tool_router,
};

use crate::{
    cmd::scan::ScanArgs,
    parameter_analysis::analyze_parameters,
    scanning::result::{Result as ScanResult, SanitizedResult},
    target_parser::parse_target,
};

/// Internal job representation.
#[derive(Clone)]
struct Job {
    status: String,                        // queued | running | done | error
    results: Option<Vec<SanitizedResult>>, // Present when done (or partial in future)
    include_request: bool,
    include_response: bool,
}

/// MCP handler state.
#[derive(Clone)]
pub struct DalfoxMcp {
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    tool_router: ToolRouter<Self>,
}

impl DalfoxMcp {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            tool_router: Self::tool_router(),
        }
    }

    fn make_scan_id(s: &str) -> String {
        crate::utils::make_scan_id(s)
    }

    fn log(level: &str, msg: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        eprintln!("[{}] [{}] {}", ts, level, msg);
    }

    /// Execute a scan job (parameter discovery + scanning) using a fully prepared ScanArgs.
    async fn run_job(&self, scan_id: String, scan_args: ScanArgs) {
        {
            let mut jobs = self.jobs.lock().await;
            if let Some(j) = jobs.get_mut(&scan_id) {
                j.status = "running".into();
            }
        }

        let url = scan_args
            .targets
            .get(0)
            .cloned()
            .unwrap_or_else(|| "<missing>".to_string());
        let include_request = scan_args.include_request;
        let include_response = scan_args.include_response;

        // Parse and hydrate a single target
        let mut target = match parse_target(&url) {
            Ok(mut t) => {
                t.method = scan_args.method.clone();
                t.timeout = scan_args.timeout;
                t.delay = scan_args.delay;
                t.proxy = scan_args.proxy.clone();
                t.follow_redirects = scan_args.follow_redirects;
                t.workers = scan_args.workers;
                t.user_agent = scan_args.user_agent.clone().or(Some("".to_string()));
                t.headers = scan_args
                    .headers
                    .iter()
                    .filter_map(|h| h.split_once(":"))
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                    .collect();
                t.cookies = scan_args
                    .cookies
                    .iter()
                    .filter_map(|c| c.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                t.data = scan_args.data.clone();
                t
            }
            Err(e) => {
                Self::log("ERR", &format!("parse_target failed: {}", e));
                let mut jobs = self.jobs.lock().await;
                if let Some(j) = jobs.get_mut(&scan_id) {
                    j.status = "error".into();
                }
                return;
            }
        };

        // Parameter discovery / mining
        analyze_parameters(&mut target, &scan_args, None).await;

        // Collect raw results
        let results_arc = Arc::new(Mutex::new(Vec::<ScanResult>::new()));
        crate::scanning::run_scanning(
            &target,
            Arc::new(scan_args.clone()),
            results_arc.clone(),
            None,
            None,
        )
        .await;

        let sanitized = {
            let locked = results_arc.lock().await;
            locked
                .iter()
                .map(|r| r.to_sanitized(include_request, include_response))
                .collect::<Vec<_>>()
        };

        {
            let mut jobs = self.jobs.lock().await;
            if let Some(j) = jobs.get_mut(&scan_id) {
                j.status = "done".into();
                j.results = Some(sanitized);
            }
        }

        Self::log(
            "JOB",
            &format!("scan finished scan_id={} url={}", scan_id, url),
        );
    }
}

/* ---------------------------
 * Tool Parameter Definitions
 * ---------------------------
 */

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanWithDalfoxParams {
    /// Target URL to scan for reflected or stored XSS
    pub target: String,
    /// Include serialized HTTP request in each finding
    #[serde(default)]
    pub include_request: bool,
    /// Include serialized HTTP response in each finding
    #[serde(default)]
    pub include_response: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetResultsDalfoxParams {
    /// A scan_id previously returned by scan_with_dalfox
    pub scan_id: String,
}

/* ---------------------------
 * Tool Implementations
 * ---------------------------
 */

#[tool_router]
impl DalfoxMcp {
    /// Start an asynchronous Dalfox XSS scan (returns immediately with scan_id).
    #[tool(
        name = "scan_with_dalfox",
        description = "Start an asynchronous Dalfox XSS scan for a single target URL"
    )]
    async fn scan_with_dalfox(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if target.trim().is_empty() {
            return Err(ErrorData::invalid_params("target must not be empty", None));
        }
        let include_request = args
            .get("include_request")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let include_response = args
            .get("include_response")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let scan_id = Self::make_scan_id(&target);

        {
            let mut jobs = self.jobs.lock().await;
            jobs.insert(
                scan_id.clone(),
                Job {
                    status: "queued".into(),
                    results: None,
                    include_request,
                    include_response,
                },
            );
        }

        Self::log(
            "JOB",
            &format!(
                "queued scan_id={} target={} include_request={} include_response={}",
                scan_id, target, include_request, include_response
            ),
        );

        // Extract additional scan configuration flags
        let param_filters: Vec<String> = args
            .get("param")
            .and_then(|v| {
                if v.is_array() {
                    Some(
                        v.as_array()
                            .unwrap()
                            .iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>(),
                    )
                } else if let Some(s) = v.as_str() {
                    Some(vec![s.to_string()])
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let data_body = args
            .get("data")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let headers_list: Vec<String> = args
            .get("headers")
            .and_then(|v| {
                if v.is_array() {
                    Some(
                        v.as_array()
                            .unwrap()
                            .iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>(),
                    )
                } else if let Some(s) = v.as_str() {
                    Some(vec![s.to_string()])
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let cookies_list: Vec<String> = args
            .get("cookies")
            .and_then(|v| {
                if v.is_array() {
                    Some(
                        v.as_array()
                            .unwrap()
                            .iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>(),
                    )
                } else if let Some(s) = v.as_str() {
                    Some(vec![s.to_string()])
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let method_override = args
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "GET".to_string());

        let user_agent = args
            .get("user_agent")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // cookie_from_raw: read Cookie: line and append
        let mut all_cookies = cookies_list.clone();
        if let Some(raw_path) = args
            .get("cookie_from_raw")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        {
            if let Ok(content) = std::fs::read_to_string(&raw_path) {
                for line in content.lines() {
                    if line.to_ascii_lowercase().starts_with("cookie:") {
                        let rest = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                        for part in rest.split(';') {
                            let trimmed = part.trim();
                            if trimmed.contains('=') {
                                all_cookies.push(trimmed.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Prepare ScanArgs
        let scan_args = ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec![target.clone()],
            param: param_filters,
            data: data_body,
            headers: headers_list,
            cookies: all_cookies,
            method: method_override,
            user_agent,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request,
            include_response,
            silence: true,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 50,
            max_concurrent_targets: 50,
            max_targets_per_host: 100,
            encoders: vec!["url".into(), "html".into()],
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

        // Spawn scan in dedicated thread runtime
        let handler = self.clone();
        let sid = scan_id.clone();
        std::thread::spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    rt.block_on(handler.run_job(sid, scan_args));
                }
                Err(e) => {
                    eprintln!("[MCP][ERR] runtime build failed for scan_id={}: {}", sid, e);
                }
            }
        });

        let out = serde_json::json!({
            "scan_id": scan_id,
            "status": "queued"
        });
        Ok(CallToolResult::success(vec![Content::text(
            out.to_string(),
        )]))
    }

    /// Fetch status and (if done) results for a scan.
    #[tool(
        name = "get_results_dalfox",
        description = "Get scan status/results by scan_id (statuses: queued|running|done|error)"
    )]
    async fn get_results_dalfox(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        let pid = args
            .get("scan_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if pid.is_empty() {
            return Err(ErrorData::invalid_params("scan_id must not be empty", None));
        }
        let job_opt = {
            let jobs = self.jobs.lock().await;
            jobs.get(&pid).cloned()
        };

        match job_opt {
            Some(job) => {
                let out = serde_json::json!({
                    "scan_id": pid,
                    "status": job.status,
                    "results": job.results
                });
                Ok(CallToolResult::success(vec![Content::text(
                    out.to_string(),
                )]))
            }
            None => Err(ErrorData::invalid_params("scan_id not found", None)),
        }
    }
}

#[tool_handler]
impl rmcp::handler::server::ServerHandler for DalfoxMcp {}

/// Run an MCP (stdio) server exposing Dalfox tools.
/// Blocks until the client disconnects or the process is terminated.
pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{stdin, stdout};
    let transport = (stdin(), stdout());
    use rmcp::service::serve_server;
    let running = serve_server(DalfoxMcp::new(), transport).await?;
    running.waiting().await?;
    Ok(())
}
