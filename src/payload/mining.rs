// Fallback parameter-name wordlist used when no `--mining-dict-word` /
// `--remote-wordlists` source is supplied. Seeded from
// https://github.com/1ndianl33t/Gf-Patterns/blob/master/xss.json and extended
// with high-signal reflected-input parameter names drawn from common
// param-mining corpora (Arjun / param-miner / SecLists) — redirect &
// return-URL params (frequent reflected-XSS / open-redirect sinks), free-text
// fields (title/message/comment/description), view/format/template selectors,
// and identity/locale fields. Kept de-duplicated and ordered most-common-first
// so the first query buckets start with the highest-value names.
pub(crate) const GF_PATTERNS_PARAMS: &[&str] = &[
    // --- original gf-patterns xss.json seed ---
    "q",
    "s",
    "search",
    "lang",
    "keyword",
    "query",
    "page",
    "keywords",
    "year",
    "view",
    "email",
    "type",
    "name",
    "p",
    "callback",
    "jsonp",
    "api_key",
    "api",
    "password",
    "emailto",
    "token",
    "username",
    "csrf_token",
    "unsubscribe_token",
    "id",
    "item",
    "page_id",
    "month",
    "immagine",
    "list_type",
    "url",
    "terms",
    "categoryid",
    "key",
    "l",
    "begindate",
    "enddate",
    // --- redirect / return-URL family (reflected-XSS + open-redirect sinks) ---
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redirecturl",
    "redir",
    "return",
    "returnurl",
    "return_url",
    "returnto",
    "return_to",
    "next",
    "continue",
    "goto",
    "dest",
    "destination",
    "target",
    "to",
    "out",
    "u",
    "uri",
    "link",
    "ref",
    "referrer",
    "referer",
    "back",
    "backurl",
    "checkout_url",
    "success_url",
    "cancel_url",
    "image_url",
    "domain",
    "host",
    // --- free-text / reflected-content fields ---
    "title",
    "subject",
    "message",
    "msg",
    "body",
    "comment",
    "content",
    "text",
    "description",
    "desc",
    "note",
    "data",
    "value",
    "input",
    "tag",
    "tags",
    "label",
    "caption",
    "summary",
    "feedback",
    "reason",
    "error",
    "error_description",
    "err",
    "status",
    "info",
    "alert",
    "notice",
    // --- view / format / template selectors ---
    "mode",
    "action",
    "format",
    "output",
    "template",
    "theme",
    "style",
    "sort",
    "order",
    "orderby",
    "filter",
    "category",
    "cat",
    "tab",
    "section",
    "step",
    "state",
    "color",
    // --- identity / locale / misc ---
    "user",
    "userid",
    "user_id",
    "uid",
    "account",
    "profile",
    "nick",
    "nickname",
    "firstname",
    "lastname",
    "fullname",
    "display",
    "locale",
    "country",
    "region",
    "city",
    "date",
    "time",
    "day",
    "week",
    "from",
    "code",
    "file",
    "filename",
    "path",
    "dir",
    "folder",
    "preview",
    "debug",
    "test",
];

/// Additional curated names from the gori Param Miner wordlist. Keeping this
/// as a source asset instead of another giant Rust literal makes updates easy
/// and lets the loader deduplicate overlaps with the GF seed above while
/// preserving the high-signal ordering of the existing list.
const GORI_MINER_PARAMS: &str = include_str!("gori_miner_params.txt");

/// Return the default parameter candidates in stable, de-duplicated order.
/// The first block preserves Dalfox's historical XSS-oriented priority; the
/// gori-derived block broadens API, auth, pagination, feature-flag, media,
/// commerce, and operational parameter coverage without requiring a network
/// fetch. Remote `burp`/`assetnote` lists still replace this set when selected.
pub(crate) fn built_in_mining_params() -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut params = Vec::new();
    for name in GF_PATTERNS_PARAMS {
        if seen.insert(*name) {
            params.push((*name).to_string());
        }
    }
    for line in GORI_MINER_PARAMS.lines() {
        let name = line.trim();
        if !name.is_empty() && !name.starts_with('#') && seen.insert(name) {
            params.push(name.to_string());
        }
    }
    params
}

#[cfg(test)]
mod tests;
