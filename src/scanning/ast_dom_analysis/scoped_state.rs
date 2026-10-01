//! Undo-journaled maps for the visitor's scoped state.
//!
//! Function bodies, callbacks, event handlers and summary walks all need the
//! taint state they mutate rolled back on exit. Cloning the whole map on entry
//! made that O(live state) per body — O(N²) for a script with `N` tainted
//! bindings followed by `N` callbacks. [`ScopedMap`] instead records the prior
//! value of every key it changes while a [`Checkpoint`] is open, and
//! [`ScopedMap::rollback`] replays that journal backwards, so a scope costs
//! O(mutations it made) and the restored contents are exactly what a clone
//! would have held.

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// A `HashMap` whose mutations can be undone back to a [`Checkpoint`].
///
/// Only the read/write surface the visitor uses is exposed, and every write
/// goes through it, so the journal can't miss a change.
pub(super) struct ScopedMap<K, V> {
    map: HashMap<K, V>,
    /// `(key, value before the write)` for every write since the oldest open
    /// checkpoint. Empty whenever no checkpoint is open, so the top-level walk
    /// pays nothing.
    journal: Vec<(K, Option<V>)>,
    open_checkpoints: usize,
}

/// Journal position returned by [`ScopedMap::checkpoint`]; must be handed back
/// to [`ScopedMap::rollback`] on the same map, innermost first.
#[must_use = "an open checkpoint keeps journaling until it is rolled back"]
pub(super) struct Checkpoint(usize);

/// A `HashSet` with the same checkpoint/rollback semantics, exposing the
/// `HashSet` method signatures the visitor's call sites already use.
pub(super) struct ScopedSet<K>(ScopedMap<K, ()>);

impl<K, V> Default for ScopedMap<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            journal: Vec::new(),
            open_checkpoints: 0,
        }
    }
}

impl<K: Eq + Hash + Clone, V: Clone> ScopedMap<K, V> {
    pub(super) fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key)
    }

    pub(super) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.contains_key(key)
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    pub(super) fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.open_checkpoints == 0 {
            return self.map.insert(key, value);
        }
        let old = self.map.insert(key.clone(), value);
        self.journal.push((key, old.clone()));
        old
    }

    pub(super) fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if self.open_checkpoints == 0 {
            return self.map.remove(key);
        }
        let (key, old) = self.map.remove_entry(key)?;
        self.journal.push((key, Some(old.clone())));
        Some(old)
    }

    pub(super) fn clear(&mut self) {
        if self.open_checkpoints == 0 {
            self.map.clear();
            return;
        }
        self.journal
            .extend(self.map.drain().map(|(key, old)| (key, Some(old))));
    }

    /// Open a scope: every write from here until the matching
    /// [`rollback`](Self::rollback) is undone by it.
    pub(super) fn checkpoint(&mut self) -> Checkpoint {
        self.open_checkpoints += 1;
        Checkpoint(self.journal.len())
    }

    /// Restore the contents to what they were at `checkpoint`.
    pub(super) fn rollback(&mut self, checkpoint: Checkpoint) {
        debug_assert!(self.open_checkpoints > 0 && checkpoint.0 <= self.journal.len());
        while self.journal.len() > checkpoint.0 {
            let Some((key, old)) = self.journal.pop() else {
                break;
            };
            match old {
                Some(value) => {
                    self.map.insert(key, value);
                }
                None => {
                    self.map.remove(&key);
                }
            }
        }
        self.open_checkpoints = self.open_checkpoints.saturating_sub(1);
    }

    /// Keys present now that were absent at `checkpoint` — what a
    /// `now - saved_clone` set difference would yield, in O(writes since the
    /// checkpoint) instead of O(map size).
    pub(super) fn keys_added_since(&self, checkpoint: &Checkpoint) -> Vec<K> {
        let mut seen: HashSet<&K> = HashSet::new();
        let mut added = Vec::new();
        for (key, old) in &self.journal[checkpoint.0..] {
            // The first journal entry for a key holds its value at the
            // checkpoint; later entries only record intermediate writes.
            if seen.insert(key) && old.is_none() && self.map.contains_key(key) {
                added.push(key.clone());
            }
        }
        added
    }
}

impl<K> Default for ScopedSet<K> {
    fn default() -> Self {
        Self(ScopedMap::default())
    }
}

impl<K: Eq + Hash + Clone> ScopedSet<K> {
    pub(super) fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.contains_key(key)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &K> {
        self.0.keys()
    }

    /// `true` when the key was not present.
    pub(super) fn insert(&mut self, key: K) -> bool {
        self.0.insert(key, ()).is_none()
    }

    /// `true` when the key was present.
    pub(super) fn remove<Q>(&mut self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.remove(key).is_some()
    }

    pub(super) fn clear(&mut self) {
        self.0.clear();
    }

    pub(super) fn checkpoint(&mut self) -> Checkpoint {
        self.0.checkpoint()
    }

    pub(super) fn rollback(&mut self, checkpoint: Checkpoint) {
        self.0.rollback(checkpoint);
    }

    pub(super) fn keys_added_since(&self, checkpoint: &Checkpoint) -> Vec<K> {
        self.0.keys_added_since(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_restores_exact_contents_through_nested_scopes() {
        let mut m: ScopedMap<String, String> = ScopedMap::default();
        m.insert("a".into(), "1".into());
        m.insert("b".into(), "2".into());

        let outer = m.checkpoint();
        m.insert("a".into(), "1x".into());
        m.remove("b");
        m.insert("c".into(), "3".into());

        let inner = m.checkpoint();
        m.clear();
        m.insert("d".into(), "4".into());
        m.insert("a".into(), "1y".into());
        m.rollback(inner);
        assert_eq!(m.get("a").map(String::as_str), Some("1x"));
        assert!(!m.contains_key("b"));
        assert_eq!(m.get("c").map(String::as_str), Some("3"));
        assert!(!m.contains_key("d"));

        m.rollback(outer);
        let mut now: Vec<_> = m.keys().cloned().collect();
        now.sort();
        assert_eq!(now, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
        // Nothing open: writes are no longer journaled.
        m.insert("e".into(), "5".into());
        assert!(m.journal.is_empty());
    }

    #[test]
    fn keys_added_since_matches_a_set_difference() {
        let mut s: ScopedSet<String> = ScopedSet::default();
        s.insert("kept".into());
        s.insert("dropped".into());
        let cp = s.checkpoint();
        s.insert("new".into());
        s.insert("kept".into());
        s.remove("dropped");
        s.insert("dropped".into());
        s.insert("transient".into());
        s.remove("transient");
        assert_eq!(s.keys_added_since(&cp), vec!["new".to_string()]);
        s.rollback(cp);
        let mut now: Vec<_> = s.iter().cloned().collect();
        now.sort();
        assert_eq!(now, vec!["dropped".to_string(), "kept".to_string()]);
    }
}
