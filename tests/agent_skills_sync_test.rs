//! The agent-facing skill is published in three places that must agree, and
//! nothing enforced that: a change to one and not the others rots silently,
//! because none of them is compiled or linked.
//!
//!   1. `skills/dalfox/SKILL.md` — the source of truth in the repo
//!   2. `docs/static/.well-known/agent-skills/dalfox/SKILL.md` — the copy the
//!      docs site serves, which must be byte-identical
//!   3. `docs/static/.well-known/agent-skills/index.json` — carries a
//!      `sha256:` digest of (2), which discovery clients verify
//!
//! A stale digest makes the published skill fail verification for every agent
//! that checks it, and a stale copy serves instructions that no longer match
//! the tool. Both are invisible until someone reports it.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

const SOURCE: &str = "skills/dalfox/SKILL.md";
const PUBLISHED: &str = "docs/static/.well-known/agent-skills/dalfox/SKILL.md";
const INDEX: &str = "docs/static/.well-known/agent-skills/index.json";

/// Read a repo file with line endings normalized to LF.
///
/// The digest in `index.json` is taken over the file *as served*, which is LF.
/// A Windows checkout can materialize CRLF (`.gitattributes` now pins these
/// three paths, but a pre-existing clone or a zip download still can), and
/// hashing those bytes would fail against a digest that is perfectly correct.
/// Normalizing here keeps the test about drift rather than about checkout
/// settings.
fn read_lf(rel: &str) -> Vec<u8> {
    let raw = std::fs::read(repo_path(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

#[test]
fn published_skill_is_byte_identical_to_the_source() {
    let source = read_lf(SOURCE);
    let published = read_lf(PUBLISHED);
    assert_eq!(
        source, published,
        "{SOURCE} and {PUBLISHED} have drifted — the docs site would serve \
         instructions that no longer match the repo. Copy the source over the \
         published file and refresh the digest in {INDEX}."
    );
}

#[test]
fn index_digest_matches_the_published_skill() {
    let published = read_lf(PUBLISHED);
    let mut hasher = Sha256::new();
    hasher.update(&published);
    let actual = format!("sha256:{}", hex::encode(hasher.finalize()));

    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repo_path(INDEX)).expect("read the agent-skills index"),
    )
    .expect("index.json must be valid JSON");

    let entry = index["skills"]
        .as_array()
        .expect("index.json must carry a `skills` array")
        .iter()
        .find(|s| s["name"] == "dalfox")
        .expect("index.json must list the dalfox skill");
    let recorded = entry["digest"]
        .as_str()
        .expect("the dalfox entry must carry a digest");

    assert_eq!(
        recorded, actual,
        "the digest in {INDEX} is stale — discovery clients that verify it will \
         reject the published skill. Recompute with:\n    \
         shasum -a 256 {PUBLISHED}"
    );
}
