//! VeilKnit distributed lexical library.
//!
//! # ELI5 overview
//!
//! Think of each normalized word as having a tiny decentralized librarian.
//! The word is hashed, and nodes whose lexical coordinate is closest to that
//! hash preferentially keep its statistics when their local library fills up.
//! Librarians do **not** decide what a word means and they do not store an
//! authoritative global list of profiles. They remember merge-friendly clues:
//! how often the word is seen, which words tend to appear up to three places
//! before/after it, script/diacritic characteristics, compact context MinHashes,
//! phrase evidence, and bounded duplicate-safe samples.
//!
//! Every application gets its own library by default. The durable lexical DHT
//! contains statistical language/search knowledge only; actual app objects stay
//! in the app's own authoritative DHTs. While nodes are online, the existing
//! daemon gossip engine carries small lexical summaries and posting hints. A
//! search therefore uses gossip for speed and DHT snapshots for persistence,
//! then applications still verify interesting objects from their authoritative
//! records before treating anything as true.
//!
//! Add-only sketches are divided into 24-hour epochs. A seven-day union is the
//! default search-statistics window. When an old epoch leaves that window its
//! observations stop affecting rarity automatically, which is our deletion /
//! stale-data mechanism without attempting distributed removals from sketches.

mod manager;
mod sketches;
mod storage;
mod tokenize;
pub mod types;

#[allow(unused_imports)] // Intentional lexical-library API re-export.
pub use manager::{derive_library_id, derive_phrase_id, LexicalError, LexicalLibraryManager};
#[allow(unused_imports)] // Intentional lexical-library API re-export.
pub use sketches::{DeterministicSample, EntityFingerprint, HllSketch, MentionStatistics, SamplePoint};
#[allow(unused_imports)] // Intentional lexical-library API re-export.
pub use tokenize::{
    accent_fold, canonicalize_word_v1, compare_words, derive_word_id, minhash_similarity,
    script_profile, transliteration_fold, visual_fold,
};
pub use types::*;
