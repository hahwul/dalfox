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

#[test]
fn published_skill_is_byte_identical_to_the_source() {
    let source = std::fs::read(repo_path(SOURCE)).expect("read skills/dalfox/SKILL.md");
    let published = std::fs::read(repo_path(PUBLISHED)).expect("read the .well-known copy");
    assert_eq!(
        source, published,
        "{SOURCE} and {PUBLISHED} have drifted — the docs site would serve \
         instructions that no longer match the repo. Copy the source over the \
         published file and refresh the digest in {INDEX}."
    );
}

#[test]
fn index_digest_matches_the_published_skill() {
    let published = std::fs::read(repo_path(PUBLISHED)).expect("read the .well-known copy");
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
