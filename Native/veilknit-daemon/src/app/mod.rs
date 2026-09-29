//! Local application identity, authorization, signing, and daemon-owned storage.

pub(crate) mod directory;
pub(crate) mod discovery;
pub(crate) mod identity;
pub(crate) mod services;

/// User-controlled aliases returned to authenticated applications.
pub(crate) mod visible_names;
