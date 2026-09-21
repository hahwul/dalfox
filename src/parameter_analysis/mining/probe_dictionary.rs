//! Mining: dictionary. See module docs in `mod.rs`.

use super::*;

pub async fn probe_dictionary_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let client = target.build_client_or_default();
    // Taken before this stage pushes anything, so a later collapse can drop
    // only what the wordlist mined without touching Stage 1 discovery.
    let preexisting = snapshot_param_slots(&reflection_params).await;

    // Resolve candidate parameter names (remote, file, or the expanded
    // built-in list). Remote fetches remain process-cached by provider set.
    let mut params: Vec<String> = Vec::new();
    let mut loaded = false;

    if !args.remote_wordlists.is_empty() {
        if let Err(e) = crate::payload::init_remote_wordlists(&args.remote_wordlists).await
            && !args.silence
        {
            eprintln!("Error initializing remote wordlists: {}", e);
        }
        // Keyed by this scan's provider set: the cache is process-global, so a
        // provider-less lookup in a server/MCP daemon must not return a list
        // fetched by an earlier job with different providers.
        if let Some(words) = crate::payload::get_remote_words_for(&args.remote_wordlists)
            && !words.is_empty()
        {
            params = words.as_ref().clone();
            loaded = true;
        }
    }

    if !loaded && let Some(wordlist_path) = &args.mining_dict_word {
        match crate::utils::fs::read_bounded(
            std::path::Path::new(wordlist_path),
            crate::utils::fs::MAX_FILE_READ_BYTES,
            "parameter wordlist",
        ) {
            Ok(content) => {
                params = content
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                    .map(ToString::to_string)
                    .collect();
                loaded = true;
            }
            Err(e) => {
                // Always surface an unreadable user-supplied wordlist on
                // stderr; machine-readable stdout remains clean.
                eprintln!("Error reading wordlist file {}: {}", wordlist_path, e);
                return;
            }
        }
    }

    if !loaded {
        params = crate::payload::mining::built_in_mining_params();
    }

    let query_ctx = QueryMiningContext {
        target,
        args,
        reflection_params,
        semaphore,
        pb,
        client,
    };
    probe_query_candidates(&query_ctx, params, preexisting, "dictionary", None).await;
}
