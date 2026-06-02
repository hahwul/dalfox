//! Detection of outdated / known-vulnerable JavaScript libraries (issue #1074).
//!
//! retire.js-style, but deliberately small: extract a `(library, version)` pair
//! from a response — script `src` URLs/filenames and inline version banners —
//! and match it against a bundled, curated dataset of known-vulnerable version
//! ranges. Each match becomes an **informational** finding (CWE-1104, "Use of a
//! component with known vulnerabilities"); it is NOT a claim of an exploitable
//! XSS on this target, just a flagged stale dependency that enriches a report.
//!
//! Scope notes:
//! - The dataset is a curated subset (the libraries most commonly fingerprinted
//!   on the web, each with well-known advisories), embedded so offline scans
//!   still work. It is intentionally not the full retire.js corpus.
//! - Version comparison is dotted-numeric (`1.7.2` < `3.5.0`); pre-release
//!   suffixes are truncated to their numeric prefix. Good enough for the
//!   coarse "older than the fixed release" test these ranges express.

use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// A detected outdated/vulnerable library instance.
#[derive(Debug, Clone, PartialEq)]
pub struct VulnLib {
    pub library: String,
    pub version: String,
    /// Advisory identifiers (CVE / GHSA) for the matched ranges.
    pub advisories: Vec<String>,
    /// Highest severity across matched ranges (`"Low"` | `"Medium"` | `"High"`).
    pub severity: &'static str,
    /// The earliest release that fixes every matched range (informational hint).
    pub fixed_in: String,
}

/// One known-vulnerable version range for a library.
struct VulnRange {
    /// Inclusive lower bound; `None` means "from 0".
    introduced: Option<&'static str>,
    /// Exclusive upper bound — versions `< fixed` are in range.
    fixed: &'static str,
    advisories: &'static [&'static str],
    severity: &'static str,
}

/// A library the detector knows how to fingerprint and judge.
struct LibSpec {
    name: &'static str,
    /// Regexes that capture the version (group 1) from a script URL/filename,
    /// e.g. `jquery-1.7.2.min.js` or `/ajax/libs/jquery/1.11.0/`.
    url_patterns: &'static [&'static str],
    /// Regexes that capture the version (group 1) from inline script content,
    /// e.g. a `jQuery JavaScript Library v1.7.2` banner.
    inline_patterns: &'static [&'static str],
    ranges: &'static [VulnRange],
}

const SEV_LOW: &str = "Low";
const SEV_MEDIUM: &str = "Medium";
const SEV_HIGH: &str = "High";

/// Curated dataset. Each library lists how to read its version and the ranges
/// with known advisories. Kept small and high-signal; extend as needed.
static LIB_SPECS: &[LibSpec] = &[
    LibSpec {
        name: "jQuery",
        url_patterns: &[
            r"(?i)jquery[._-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
            r"(?i)/jquery/(\d+\.\d+(?:\.\d+)?)/",
        ],
        inline_patterns: &[r"(?i)jQuery(?: JavaScript Library)? v(\d+\.\d+(?:\.\d+)?)"],
        ranges: &[
            VulnRange {
                introduced: None,
                fixed: "1.9.0",
                advisories: &["CVE-2012-6708"],
                severity: SEV_MEDIUM,
            },
            VulnRange {
                introduced: None,
                fixed: "3.0.0",
                advisories: &["CVE-2015-9251"],
                severity: SEV_MEDIUM,
            },
            VulnRange {
                introduced: None,
                fixed: "3.4.0",
                advisories: &["CVE-2019-11358"],
                severity: SEV_MEDIUM,
            },
            VulnRange {
                introduced: None,
                fixed: "3.5.0",
                advisories: &["CVE-2020-11022", "CVE-2020-11023"],
                severity: SEV_MEDIUM,
            },
        ],
    },
    LibSpec {
        name: "jQuery UI",
        url_patterns: &[r"(?i)jquery[-.]ui[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"],
        inline_patterns: &[r"(?i)jQuery UI(?: -)? v(\d+\.\d+(?:\.\d+)?)"],
        ranges: &[VulnRange {
            introduced: None,
            fixed: "1.13.0",
            advisories: &[
                "CVE-2021-41182",
                "CVE-2021-41183",
                "CVE-2021-41184",
                "CVE-2022-31160",
            ],
            severity: SEV_MEDIUM,
        }],
    },
    LibSpec {
        name: "AngularJS",
        url_patterns: &[r"(?i)angular[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"],
        inline_patterns: &[r#"(?i)angular.*?\bversion\b.*?["'](\d+\.\d+\.\d+)["']"#],
        ranges: &[VulnRange {
            // AngularJS 1.x reached end-of-life with multiple sandbox/XSS issues.
            introduced: None,
            fixed: "1.8.3",
            advisories: &["CVE-2020-7676", "CVE-2019-10768", "CVE-2022-25869"],
            severity: SEV_MEDIUM,
        }],
    },
    LibSpec {
        name: "Bootstrap",
        url_patterns: &[r"(?i)bootstrap[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"],
        inline_patterns: &[r"(?i)Bootstrap(?: v)?\s*v?(\d+\.\d+(?:\.\d+)?)"],
        ranges: &[
            VulnRange {
                introduced: None,
                fixed: "3.4.1",
                advisories: &["CVE-2019-8331", "CVE-2018-14041", "CVE-2018-14042"],
                severity: SEV_MEDIUM,
            },
            VulnRange {
                introduced: Some("4.0.0"),
                fixed: "4.3.1",
                advisories: &["CVE-2019-8331"],
                severity: SEV_MEDIUM,
            },
        ],
    },
    LibSpec {
        name: "Lodash",
        url_patterns: &[r"(?i)lodash[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"],
        inline_patterns: &[
            r"(?i)lodash(?: modern build)? <(\d+\.\d+\.\d+)>|@license lodash (\d+\.\d+\.\d+)",
        ],
        ranges: &[VulnRange {
            introduced: None,
            fixed: "4.17.21",
            advisories: &["CVE-2019-10744", "CVE-2020-8203", "CVE-2021-23337"],
            severity: SEV_HIGH,
        }],
    },
    LibSpec {
        name: "Handlebars",
        url_patterns: &[r"(?i)handlebars[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"],
        inline_patterns: &[r"(?i)Handlebars(?:\.js)?(?: v| version )(\d+\.\d+(?:\.\d+)?)"],
        ranges: &[VulnRange {
            introduced: None,
            fixed: "4.7.7",
            advisories: &["CVE-2019-19919", "CVE-2021-23369", "CVE-2021-23383"],
            severity: SEV_HIGH,
        }],
    },
    LibSpec {
        name: "Moment.js",
        url_patterns: &[r"(?i)moment[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"],
        inline_patterns: &[r"(?i)//! moment\.js\s*\n//! version : (\d+\.\d+(?:\.\d+)?)"],
        ranges: &[VulnRange {
            introduced: None,
            fixed: "2.29.4",
            advisories: &["CVE-2022-31129", "CVE-2022-24785"],
            severity: SEV_MEDIUM,
        }],
    },
];

/// Compiled form of a [`LibSpec`] (regexes built once).
struct CompiledLib {
    name: &'static str,
    url_res: Vec<Regex>,
    inline_res: Vec<Regex>,
    ranges: &'static [VulnRange],
}

static COMPILED: LazyLock<Vec<CompiledLib>> = LazyLock::new(|| {
    LIB_SPECS
        .iter()
        .map(|spec| CompiledLib {
            name: spec.name,
            url_res: spec
                .url_patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
            inline_res: spec
                .inline_patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
            ranges: spec.ranges,
        })
        .collect()
});

/// Parse a dotted version into numeric components, truncating any non-numeric
/// suffix on each component (`"1.7.2-rc1"` → `[1, 7, 2]`).
fn parse_version(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|p| {
            let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().unwrap_or(0)
        })
        .collect()
}

/// `a < b` under dotted-numeric ordering (missing components treated as 0).
fn version_lt(a: &str, b: &str) -> bool {
    let (av, bv) = (parse_version(a), parse_version(b));
    for i in 0..av.len().max(bv.len()) {
        let x = av.get(i).copied().unwrap_or(0);
        let y = bv.get(i).copied().unwrap_or(0);
        if x != y {
            return x < y;
        }
    }
    false
}

/// `a >= b`.
fn version_ge(a: &str, b: &str) -> bool {
    !version_lt(a, b)
}

fn severity_rank(s: &str) -> u8 {
    match s {
        SEV_HIGH => 3,
        SEV_MEDIUM => 2,
        SEV_LOW => 1,
        _ => 0,
    }
}

/// Judge a single `(library, version)`: returns the aggregated advisories,
/// worst severity, and earliest fixing release across all ranges the version
/// falls into, or `None` if the version is not known-vulnerable.
fn judge(lib: &CompiledLib, version: &str) -> Option<VulnLib> {
    let mut advisories: Vec<String> = Vec::new();
    let mut severity = SEV_LOW;
    let mut fixed_in: Option<&'static str> = None;
    for range in lib.ranges {
        let in_range = range.introduced.is_none_or(|lo| version_ge(version, lo))
            && version_lt(version, range.fixed);
        if in_range {
            for a in range.advisories {
                if !advisories.iter().any(|x| x == a) {
                    advisories.push((*a).to_string());
                }
            }
            if severity_rank(range.severity) > severity_rank(severity) {
                severity = range.severity;
            }
            // The most relevant "fixed in" is the highest fixed version among
            // matched ranges (upgrading there clears them all).
            fixed_in = Some(match fixed_in {
                Some(f) if version_lt(range.fixed, f) => f,
                _ => range.fixed,
            });
        }
    }
    if advisories.is_empty() {
        return None;
    }
    Some(VulnLib {
        library: lib.name.to_string(),
        version: version.to_string(),
        advisories,
        severity,
        fixed_in: fixed_in.unwrap_or("").to_string(),
    })
}

/// Scan a response body for outdated/known-vulnerable JS libraries. Returns one
/// [`VulnLib`] per distinct `(library, version)` found and judged vulnerable.
pub fn detect_vulnerable_libraries(body: &str) -> Vec<VulnLib> {
    let mut out: Vec<VulnLib> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for lib in COMPILED.iter() {
        let mut versions: Vec<String> = Vec::new();
        for re in lib.url_res.iter().chain(lib.inline_res.iter()) {
            for cap in re.captures_iter(body) {
                // First non-empty capture group is the version (inline patterns
                // may use alternation with two groups).
                if let Some(v) = (1..cap.len()).find_map(|i| cap.get(i)).map(|m| m.as_str()) {
                    versions.push(v.to_string());
                }
            }
        }
        for version in versions {
            if let Some(found) = judge(lib, &version)
                && seen.insert((lib.name.to_string(), version.clone()))
            {
                out.push(found);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
