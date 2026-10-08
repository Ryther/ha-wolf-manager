//! Temporary multi-file overlays, fully recoverable from per-file manifests.
use crate::transactions::{Grant, TransactionStore};
use std::{io, path::Path};
pub struct Overlay<'a> {
    pub grant: &'a Grant,
    pub relative: &'a str,
    pub bytes: Vec<u8>,
}
pub fn apply(
    store: &TransactionStore,
    overlays: &[Overlay<'_>],
    quiescent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    apply_inner(store, overlays, None, quiescent)
}
/// Bind each transformed overlay to the exact bytes used to produce it.
pub fn apply_expected(
    store: &TransactionStore,
    overlays: &[Overlay<'_>],
    expected: &[Vec<u8>],
    quiescent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    if overlays.len() != expected.len() {
        return Err(io::Error::other("overlay preimage count differs"));
    }
    apply_inner(store, overlays, Some(expected), quiescent)
}
fn apply_inner(
    store: &TransactionStore,
    overlays: &[Overlay<'_>],
    expected: Option<&[Vec<u8>]>,
    quiescent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let _lock = store.hook_lock()?;
    quiescent()?;
    if !store.active()?.is_empty() {
        return Err(io::Error::other("previous overlay requires restore"));
    }
    // Parse/transform work happened before this call; validate every target before writes.
    let mut changed = Vec::new();
    for (index, overlay) in overlays.iter().enumerate() {
        let before = overlay.grant.read(overlay.relative)?;
        if expected.is_some_and(|expected| expected[index] != before) {
            return Err(io::Error::other("target differs from transformed preimage"));
        }
        if before != overlay.bytes {
            changed.push((overlay, before));
        }
    }
    let mut applied = Vec::new();
    for (overlay, before) in changed {
        let result = quiescent().and_then(|()| {
            store.apply_expected(overlay.grant, overlay.relative, &before, &overlay.bytes)
        });
        match result {
            Ok(id) => applied.push((overlay.grant, id)),
            Err(error) => {
                // Restore only verified known postimages; any conflict retains evidence and data.
                for (grant, id) in applied.into_iter().rev() {
                    if quiescent().is_err() {
                        break;
                    }
                    let _ = store.restore(grant, &id);
                }
                return Err(error);
            }
        }
    }
    Ok(())
}
pub fn restore(
    store: &TransactionStore,
    grants: &[(&Path, u32, u32)],
    quiescent: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let _lock = store.hook_lock()?;
    quiescent()?;
    // Reconstruct after crashes from verified manifests, never from UI-supplied paths.
    let active = store.active()?;
    for transaction in active {
        let Some((root, uid, gid)) = grants.iter().find(|(root, uid, gid)| {
            *root == transaction.root && *uid == transaction.uid && *gid == transaction.gid
        }) else {
            return Err(io::Error::other("recovery grant no longer authorized"));
        };
        let grant = Grant::for_owner(root, *uid, *gid)?;
        quiescent()?;
        store.restore(&grant, &transaction.id)?;
    }
    Ok(())
}
