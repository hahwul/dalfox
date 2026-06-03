use super::*;

#[test]
fn test_make_scan_id_shape() {
    let id = make_scan_id_with_nonce("https://example.com", 42);
    assert_eq!(id.len(), 64);
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_lowercase() || c.is_ascii_digit()))
    );
}

#[test]
fn test_make_scan_id_uniqueness_with_different_nonces() {
    let a = make_scan_id_with_nonce("seed", 1);
    let b = make_scan_id_with_nonce("seed", 2);
    assert_ne!(a, b);
}

#[test]
fn test_make_unique_scan_id_regenerates_on_collision() {
    use std::cell::RefCell;
    // Report the first candidate as already-taken, the second as free. The
    // predicate must be consulted twice, the two candidates must differ
    // (the suffixed reseed re-draws the nonce), and the returned id is the
    // second (free) one. `make_scan_id` is non-deterministic, so we capture
    // the candidates the helper actually produced rather than precomputing.
    let seen = RefCell::new(Vec::<String>::new());
    let id = make_unique_scan_id("seed", |candidate| {
        seen.borrow_mut().push(candidate.to_string());
        seen.borrow().len() == 1
    });
    let seen = seen.into_inner();
    assert_eq!(
        seen.len(),
        2,
        "should regenerate once after the first collides"
    );
    assert_ne!(
        seen[0], seen[1],
        "regenerated id must differ from the colliding one"
    );
    assert_eq!(id, seen[1]);
    assert_eq!(id.len(), 64);
}

#[test]
fn test_make_unique_scan_id_no_collision_returns_first() {
    // When nothing collides, the predicate is consulted once and the first id
    // is returned unchanged.
    let calls = std::cell::Cell::new(0u32);
    let id = make_unique_scan_id("seed", |_| {
        calls.set(calls.get() + 1);
        false
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(id.len(), 64);
}

#[test]
fn test_short_scan_id() {
    assert_eq!(short_scan_id("abcdef1234"), "abcdef1");
    assert_eq!(short_scan_id("abc"), "abc");
    let id = make_scan_id_with_nonce("seed", 999);
    assert_eq!(short_scan_id(&id).len(), 7);
}
