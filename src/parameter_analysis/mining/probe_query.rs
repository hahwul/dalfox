//! Shared bucketed query-parameter miner.
//!
//! A one-request-per-wordlist-entry miner spends almost all of its time on
//! round trips. This module borrows the useful part of Param Miner/Gori's
//! approach: put many candidates in one request, identify reflected canaries
//! in one response pass, and only split a bucket when its response differs
//! from a calibrated control. The public behaviour remains the same — a
//! candidate becomes a `Param` — but the request shape changes from O(N) to
//! O(N/B + H log_B B) for a wordlist with bucket width B and H hits.

use super::{
    MiningSampleStats, SENTINEL_PROBE_COUNT, collapse_mined_params, pre_collapse_query_probe,
    unique_query_candidates,
};
use crate::cmd::scan::{DEFAULT_MINING_BUCKET_SIZE, MINING_BISECT_WAYS, ScanArgs};
use crate::parameter_analysis::{InjectionContext, Location, Param, ReflectionAnalysis};
use crate::target_parser::Target;
use crate::utils::http::{build_request, read_body, send_counted};
use crate::utils::shimmer::ShimmerSpinner;
use reqwest::Client;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};
use url::Url;

/// Keep the initial request line below the size accepted by the common proxy
/// and origin defaults. Existing URLs can already consume most of this budget,
/// so `initial_buckets` also cuts a bucket early on long candidate names.
const MAX_QUERY_PROBE_URL_BYTES: usize = 8 * 1024;
const CANARY_ID_LEN: usize = 17; // `m` + 16 lower-case hex characters
const DEFAULT_LENGTH_TOLERANCE: usize = 0;
const DEFAULT_COUNT_TOLERANCE: usize = 0;

static NEXT_MINING_CANARY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy)]
pub(super) struct QueryFingerprint {
    status: u16,
    body_len: usize,
    words: usize,
    lines: usize,
    location_len: usize,
}

#[derive(Debug, Clone, Copy)]
struct QueryTolerance {
    length: usize,
    words: usize,
    lines: usize,
    location: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct QueryBaseline {
    fingerprint: QueryFingerprint,
    tolerance: QueryTolerance,
}

impl QueryBaseline {
    /// Seed a baseline from a response another mining stage already had to
    /// fetch (the DOM miner's HTML request). The comparison starts exact and
    /// still uses a same-width control before accepting metric-only findings.
    pub(super) fn from_response(status: u16, body: &str, location: Option<&str>) -> Self {
        Self {
            fingerprint: fingerprint(status, body, location),
            tolerance: QueryTolerance::zero(),
        }
    }

    fn differs(&self, other: QueryFingerprint) -> bool {
        self.fingerprint.differs(other, self.tolerance)
    }
}

impl QueryTolerance {
    fn zero() -> Self {
        Self {
            length: DEFAULT_LENGTH_TOLERANCE,
            words: DEFAULT_COUNT_TOLERANCE,
            lines: DEFAULT_COUNT_TOLERANCE,
            location: DEFAULT_LENGTH_TOLERANCE,
        }
    }
}

impl QueryFingerprint {
    fn differs(self, other: Self, tolerance: QueryTolerance) -> bool {
        self.status != other.status
            || self.body_len.abs_diff(other.body_len) > tolerance.length
            || self.words.abs_diff(other.words) > tolerance.words
            || self.lines.abs_diff(other.lines) > tolerance.lines
            || self.location_len.abs_diff(other.location_len) > tolerance.location
    }
}

#[derive(Debug)]
struct QueryResponse {
    fingerprint: QueryFingerprint,
    body: String,
    location: Option<String>,
}

#[derive(Debug)]
struct MiningCanary {
    id: String,
    marker: String,
}

#[derive(Debug)]
struct BucketProbe {
    /// Number of candidate names whose final bucket outcome is known. Names
    /// in a positive metric-only bucket are deliberately excluded until their
    /// child bucket resolves them, so progress and EWMA do not double-count
    /// bisection retries.
    resolved_names: usize,
    response_received: bool,
    reflected_names: usize,
    non_reflected_names: usize,
    discovered: Vec<Param>,
    children: Vec<Vec<String>>,
}

impl BucketProbe {
    fn failed(names: usize) -> Self {
        Self {
            resolved_names: names,
            response_received: false,
            reflected_names: 0,
            non_reflected_names: 0,
            discovered: Vec::new(),
            children: Vec::new(),
        }
    }
}

pub(super) struct QueryMiningContext<'a> {
    pub(super) target: &'a Target,
    pub(super) args: &'a ScanArgs,
    pub(super) reflection_params: Arc<Mutex<Vec<Param>>>,
    pub(super) semaphore: Arc<Semaphore>,
    pub(super) pb: Option<ShimmerSpinner>,
    pub(super) client: Client,
}

/// Mine a raw set of query candidates. `baseline_seed` is used by the DOM
/// miner because it already fetched the untouched HTML response; dictionary
/// mining passes `None` and pays for one clean baseline sample here. Same-width
/// controls handle response changes caused by the candidate names themselves.
pub(super) async fn probe_query_candidates(
    ctx: &QueryMiningContext<'_>,
    raw_candidates: Vec<String>,
    preexisting: std::collections::HashSet<String>,
    stage_label: &'static str,
    baseline_seed: Option<QueryBaseline>,
) {
    if raw_candidates.is_empty() {
        return;
    }

    let silence = ctx.args.silence;
    // Measure eligibility before deduplication. If the wordlist is large but
    // all of its names were already found by Stage 1, the arbitrary-name
    // sentinel still provides the only evidence needed to create `any`.
    let sentinel_eligible = raw_candidates.len() > SENTINEL_PROBE_COUNT * 5;
    let client_for_sentinel = ctx.client.clone();
    let mut arbitrary_names_disproved = false;
    if sentinel_eligible {
        if let Some(text) = pre_collapse_query_probe(&client_for_sentinel, ctx.target).await {
            if !silence {
                eprintln!(
                    "[mining-collapse] sentinel pre-probe collapsed {stage_label} mining: \
                     every random param name reflected; adding single 'any' param"
                );
            }
            collapse_mined_params(
                &ctx.reflection_params,
                &preexisting,
                Location::Query,
                Some(&text),
            )
            .await;
            if let Some(ref pb) = ctx.pb {
                pb.finish_and_clear();
            }
            return;
        }
        arbitrary_names_disproved = true;
    }

    let candidates = unique_query_candidates(raw_candidates, &ctx.reflection_params).await;
    if candidates.is_empty() {
        if let Some(ref pb) = ctx.pb {
            pb.finish_and_clear();
        }
        return;
    }

    if let Some(ref pb) = ctx.pb {
        pb.set_length(candidates.len() as u64);
        pb.set_message(format!("Mining {stage_label} parameters"));
    }

    let target = Arc::new(ctx.target.clone());
    let method = target.parse_method();
    let delay = target.delay;
    let baseline = match baseline_seed {
        Some(seed) => Some(seed),
        None => {
            calibrate_baseline(&target, &ctx.client, &ctx.semaphore, method.clone(), delay).await
        }
    };

    let bucket_size = initial_bucket_size(&target, &candidates);
    let mut pending: VecDeque<Vec<String>> = initial_buckets(&target, candidates, bucket_size);
    let stats = Arc::new(Mutex::new(MiningSampleStats::new()));
    let parallel = ctx.args.workers.clamp(1, 64);
    let mut active = JoinSet::new();

    // A single queue is shared by initial buckets and bisection children. This
    // keeps independent buckets from waiting for a whole level to finish and
    // bounds live tasks by the configured worker count.
    loop {
        while active.len() < parallel && !pending.is_empty() {
            let Some(names) = pending.pop_front() else {
                break;
            };
            let target_clone = target.clone();
            let client_clone = ctx.client.clone();
            let semaphore_clone = ctx.semaphore.clone();
            let baseline_clone = baseline;
            let method_clone = method.clone();
            active.spawn(crate::with_job_scopes(
                crate::JobScopes::capture(),
                async move {
                    probe_bucket(
                        &target_clone,
                        &client_clone,
                        &semaphore_clone,
                        method_clone,
                        delay,
                        names,
                        baseline_clone,
                    )
                    .await
                },
            ));
        }

        let Some(joined) = active.join_next().await else {
            break;
        };
        let Ok(result) = joined else {
            continue;
        };
        if let Some(ref pb) = ctx.pb {
            pb.inc(result.resolved_names as u64);
        }

        if result.response_received {
            let mut st = stats.lock().await;
            for _ in 0..result.reflected_names {
                st.record_attempt();
                st.record_reflection();
            }
            for _ in 0..result.non_reflected_names {
                st.record_attempt();
                st.record_non_reflection();
            }
        }

        if !result.discovered.is_empty() {
            let mut guard = ctx.reflection_params.lock().await;
            guard.extend(result.discovered);
        }

        pending.extend(result.children);
    }

    let collapsed = {
        let mut st = stats.lock().await;
        st.collapsed = st.should_collapse();
        if st.collapsed && !silence {
            eprintln!(
                "[mining-collapse] high reflection EWMA {:.2} after {} attempts ({} reflections)",
                st.ewma_ratio, st.attempts, st.reflections
            );
        }
        st.collapsed
    };
    if collapsed {
        // The EWMA identifies pages that reflect most candidates. It is not
        // enough evidence to replace selective reflected names with `any`;
        // only the sentinel path can prove arbitrary-name reflection.
        let confirmed = if arbitrary_names_disproved {
            None
        } else {
            pre_collapse_query_probe(&ctx.client, &target).await
        };
        if let Some(text) = confirmed {
            collapse_mined_params(
                &ctx.reflection_params,
                &preexisting,
                Location::Query,
                Some(&text),
            )
            .await;
        } else if !silence {
            eprintln!(
                "[mining-collapse] high reflection EWMA, but the sentinels did not \
                 reflect: keeping the mined params instead of folding them into 'any'"
            );
        }
    }

    if let Some(ref pb) = ctx.pb {
        pb.finish_and_clear();
    }
}

async fn calibrate_baseline(
    target: &Arc<Target>,
    client: &Client,
    semaphore: &Arc<Semaphore>,
    method: reqwest::Method,
    delay: u64,
) -> Option<QueryBaseline> {
    let response =
        send_query_request(target, client, semaphore, method, delay, target.url.clone()).await?;
    Some(QueryBaseline {
        fingerprint: response.fingerprint,
        tolerance: QueryTolerance::zero(),
    })
}

async fn probe_bucket(
    target: &Arc<Target>,
    client: &Client,
    semaphore: &Arc<Semaphore>,
    method: reqwest::Method,
    delay: u64,
    names: Vec<String>,
    baseline: Option<QueryBaseline>,
) -> BucketProbe {
    if names.is_empty() {
        return BucketProbe::failed(0);
    }

    let canaries: Vec<MiningCanary> = names.iter().map(|_| fresh_canary()).collect();
    let name_lengths: Vec<usize> = names.iter().map(String::len).collect();
    let pairs: Vec<(String, String)> = names
        .iter()
        .zip(canaries.iter())
        .map(|(name, canary)| (name.clone(), canary.marker.clone()))
        .collect();
    let url = append_query_pairs(target, &pairs);
    let Some(response) =
        send_query_request(target, client, semaphore, method.clone(), delay, url).await
    else {
        return BucketProbe::failed(names.len());
    };

    let expected_ids: HashSet<String> = canaries.iter().map(|canary| canary.id.clone()).collect();
    let body_ids = reflected_ids(&response.body, &expected_ids);
    let location_ids = response
        .location
        .as_deref()
        .map(|location| reflected_ids(location, &expected_ids))
        .unwrap_or_default();
    let mut reflected_indices = Vec::new();
    let mut discovered = Vec::new();
    for (index, canary) in canaries.iter().enumerate() {
        if !body_ids.contains(&canary.id) && !location_ids.contains(&canary.id) {
            continue;
        }
        reflected_indices.push(index);
        let param = if location_ids.contains(&canary.id) {
            Param {
                injection_context: Some(InjectionContext::AttributeUrl(None)),
                ..Param::new(
                    names[index].clone(),
                    crate::scanning::markers::bracketed_marker().to_string(),
                    Location::Query,
                )
            }
        } else {
            let analysis = ReflectionAnalysis::of_with_marker(&response.body, &canary.id);
            Param::new(
                names[index].clone(),
                crate::scanning::markers::bracketed_marker().to_string(),
                Location::Query,
            )
            .with_analysis(&analysis)
        };
        discovered.push(param);
    }

    let mut occupied_control_names: HashSet<String> = names.iter().cloned().collect();
    let remaining: Vec<String> = names
        .into_iter()
        .enumerate()
        .filter_map(|(index, name)| (!reflected_indices.contains(&index)).then_some(name))
        .collect();

    let mut metric_positive = false;
    // If calibration failed, a control still gives us a useful candidate-vs-
    // control comparison. It is better for coverage than silently disabling
    // metric-only discovery for the whole wordlist.
    let candidate_differs = baseline.is_none_or(|base| base.differs(response.fingerprint));
    // A reflection can change the response length even when it is not enough
    // to cross the baseline tolerance. Ask a same-width control whenever a
    // bucket has both reflected and unresolved names, so a hidden metric-only
    // name in the same bucket is not silently skipped.
    if !remaining.is_empty() && (candidate_differs || !reflected_indices.is_empty()) {
        // The control carries the SAME width as the candidate request. When
        // a few names reflected, using only `remaining` here would make a
        // response that reacts to parameter count look positive at every
        // bucket, exactly the false-positive class the control is meant to
        // remove. Match name lengths as well so echo pages do not differ just
        // because the random control names are longer.
        let control_canaries: Vec<MiningCanary> =
            name_lengths.iter().map(|_| fresh_canary()).collect();
        let control_pairs: Vec<(String, String)> = name_lengths
            .iter()
            .zip(control_canaries.iter())
            .enumerate()
            .map(|(index, (name_len, canary))| {
                let name = control_name(*name_len, index, &occupied_control_names);
                occupied_control_names.insert(name.clone());
                (name, canary.marker.clone())
            })
            .collect();
        let control_url = append_query_pairs(target, &control_pairs);
        if let Some(control) =
            send_query_request(target, client, semaphore, method, delay, control_url).await
        {
            let tolerance = baseline
                .map(|base| base.tolerance)
                .unwrap_or_else(QueryTolerance::zero);
            metric_positive = response.fingerprint.differs(control.fingerprint, tolerance);
        }
    }

    let remaining_len = remaining.len();
    let (children, non_reflected_names) = if metric_positive {
        if remaining_len <= 1 {
            if let Some(name) = remaining.into_iter().next() {
                discovered.push(Param::new(
                    name,
                    crate::scanning::markers::bracketed_marker().to_string(),
                    Location::Query,
                ));
            }
            (Vec::new(), remaining_len)
        } else {
            (split_bucket(remaining, MINING_BISECT_WAYS), 0)
        }
    } else {
        (Vec::new(), remaining_len)
    };

    BucketProbe {
        resolved_names: reflected_indices.len() + non_reflected_names,
        response_received: true,
        reflected_names: reflected_indices.len(),
        non_reflected_names,
        discovered,
        children,
    }
}

fn fresh_canary() -> MiningCanary {
    let sequence = NEXT_MINING_CANARY.fetch_add(1, Ordering::Relaxed);
    let id = format!("m{sequence:016x}");
    let marker = format!(
        "{}{}{}",
        crate::scanning::markers::open_marker(),
        id,
        crate::scanning::markers::close_marker()
    );
    MiningCanary { id, marker }
}

/// Find known canary cores in one linear scan of a response rather than
/// running `body.contains()` once for every candidate in the bucket.
fn reflected_ids(text: &str, expected: &HashSet<String>) -> HashSet<String> {
    let mut found = HashSet::new();
    for (offset, _) in text.match_indices('m') {
        let Some(end) = offset.checked_add(CANARY_ID_LEN) else {
            continue;
        };
        let Some(core) = text.get(offset..end) else {
            continue;
        };
        if expected.contains(core) {
            found.insert(core.to_string());
        }
    }
    found
}

fn fingerprint(status: u16, body: &str, location: Option<&str>) -> QueryFingerprint {
    let (words, lines) = count_words_lines(body);
    QueryFingerprint {
        status,
        body_len: body.len(),
        words,
        lines,
        location_len: location.map_or(0, str::len),
    }
}

fn count_words_lines(body: &str) -> (usize, usize) {
    let mut words = 0;
    let mut lines = 0;
    let mut in_word = false;
    for byte in body.bytes() {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            in_word = false;
            if byte == b'\n' {
                lines += 1;
            }
        } else if !in_word {
            in_word = true;
            words += 1;
        }
    }
    (words, lines)
}

async fn send_query_request(
    target: &Arc<Target>,
    client: &Client,
    semaphore: &Arc<Semaphore>,
    method: reqwest::Method,
    delay: u64,
    url: Url,
) -> Option<QueryResponse> {
    let Ok(permit) = semaphore.acquire().await else {
        return None;
    };
    let request = build_request(client, target, method, url, target.data.clone());
    crate::record_outbound_request().await;
    let response = send_counted(request).await;
    let result = match response {
        Ok(response) => {
            let status = response.status();
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
            let body = read_body(response).await.ok();
            body.map(|body| QueryResponse {
                fingerprint: fingerprint(status.as_u16(), &body, location.as_deref()),
                body,
                location,
            })
            .filter(|_| !status.is_server_error())
        }
        Err(_) => None,
    };
    if delay > 0 {
        sleep(Duration::from_millis(delay)).await;
    }
    drop(permit);
    result
}

fn append_query_pairs(target: &Target, pairs: &[(String, String)]) -> Url {
    let mut url = target.url.clone();
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in pairs {
            query.append_pair(name, value);
        }
    }
    url
}

fn initial_bucket_size(target: &Target, candidates: &[String]) -> usize {
    let configured = DEFAULT_MINING_BUCKET_SIZE.clamp(1, crate::cmd::scan::MAX_MINING_BUCKET_SIZE);
    if candidates.is_empty() {
        return configured;
    }
    // A long captured URL should leave room for at least one candidate. The
    // actual bucket builder still enforces the byte budget for every name.
    let remaining = MAX_QUERY_PROBE_URL_BYTES.saturating_sub(target.url.as_str().len());
    if remaining < 512 {
        1
    } else if remaining < 2048 {
        configured.min(16)
    } else if remaining < 4096 {
        configured.min(32)
    } else {
        configured
    }
}

fn initial_buckets(
    target: &Target,
    candidates: Vec<String>,
    bucket_size: usize,
) -> VecDeque<Vec<String>> {
    let mut buckets = VecDeque::new();
    let mut current = Vec::with_capacity(bucket_size);
    let mut estimated = target.url.as_str().len();
    let marker_bytes = crate::scanning::markers::open_marker().len()
        + crate::scanning::markers::close_marker().len()
        + CANARY_ID_LEN
        + 2; // `=` + `&`

    for name in candidates {
        let pair_bytes = encoded_query_len(&name) + marker_bytes;
        let would_overflow = !current.is_empty()
            && (current.len() >= bucket_size
                || estimated.saturating_add(pair_bytes) > MAX_QUERY_PROBE_URL_BYTES);
        if would_overflow {
            buckets.push_back(std::mem::take(&mut current));
            estimated = target.url.as_str().len();
        }
        estimated = estimated.saturating_add(pair_bytes);
        current.push(name);
    }
    if !current.is_empty() {
        buckets.push_back(current);
    }
    buckets
}

fn encoded_query_len(value: &str) -> usize {
    value.bytes().fold(0, |size, byte| {
        size + if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            1
        } else {
            3
        }
    })
}

fn split_bucket(names: Vec<String>, ways: usize) -> Vec<Vec<String>> {
    let parts = names.len().min(ways.max(2));
    let base = names.len() / parts;
    let extra = names.len() % parts;
    let mut iter = names.into_iter();
    let mut result = Vec::with_capacity(parts);
    for index in 0..parts {
        let size = base + usize::from(index < extra);
        result.push(iter.by_ref().take(size).collect());
    }
    result
}

fn control_name(original_len: usize, index: usize, occupied_names: &HashSet<String>) -> String {
    let length = original_len.max(1);
    let mut fallback = String::new();
    // Keep the width identical to the candidate name so response differences
    // caused only by query-name length do not make a control look positive.
    // The suffix varies even for very short names, and occupied names are
    // skipped when a custom wordlist contains a generated-looking control.
    for salt in 0..256usize {
        let seed = format!("dlfxctrl{index:016x}{salt:04x}");
        let candidate = if seed.len() >= length {
            seed[seed.len() - length..].to_string()
        } else {
            format!("{}{}", seed, "x".repeat(length - seed.len()))
        };
        fallback = candidate.clone();
        if !occupied_names.contains(&candidate) {
            return candidate;
        }
    }
    fallback
}
