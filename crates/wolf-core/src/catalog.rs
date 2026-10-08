use crate::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogAttributes {
    pub version: u8,
    pub pc_id: PcId,
    pub app_id: AppId,
    pub name: String,
    pub cover_url: String,
    pub library_id: String,
    pub catalog_generation: u64,
    pub observed_at_ms: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogManifest {
    pub version: u8,
    pub pc_id: PcId,
    pub catalog_generation: u64,
    pub app_ids: Vec<AppId>,
    pub observed_at_ms: i64,
    pub complete: bool,
}
impl CatalogManifest {
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.version != 1
            || !self.complete
            || self.app_ids.len() > 10000
            || self.observed_at_ms < 0
            || !self.app_ids.windows(2).all(|w| w[0] < w[1])
            || canonical_json(self)?.len() > 2 * 1024 * 1024
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
}

impl CatalogAttributes {
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.version != 1
            || self.name.is_empty()
            || self.name.len() > 1024
            || self.library_id.is_empty()
            || self.library_id.len() > 256
            || self.observed_at_ms < 0
            || self.cover_url != steam_cover_url(&self.app_id)
        {
            return Err(SafeError::validation());
        }
        Ok(())
    }
}
pub fn steam_cover_url(app: &AppId) -> String {
    format!(
        "https://shared.fastly.steamstatic.com/store_item_assets/steam/apps/{app}/library_600x900.jpg"
    )
}
/// Validate one complete generation without mutating the previous projection.
/// The caller owns bounded buffering, timeout and durable atomic commit.
pub fn validate_catalog_generation(
    pc: &PcId,
    manifest: &CatalogManifest,
    attributes: &[CatalogAttributes],
    previous: Option<(
        &CatalogManifest,
        &std::collections::BTreeMap<AppId, CatalogAttributes>,
    )>,
) -> Result<std::collections::BTreeMap<AppId, CatalogAttributes>, SafeError> {
    manifest.validate()?;
    if &manifest.pc_id != pc
        || attributes.len() != manifest.app_ids.len()
        || canonical_json(&attributes)?.len() > 16 * 1024 * 1024
    {
        return Err(SafeError::validation());
    }
    let mut entries = std::collections::BTreeMap::new();
    for attribute in attributes {
        attribute.validate()?;
        if &attribute.pc_id != pc
            || attribute.catalog_generation != manifest.catalog_generation
            || entries
                .insert(attribute.app_id.clone(), attribute.clone())
                .is_some()
        {
            return Err(SafeError::validation());
        }
    }
    if entries.keys().ne(manifest.app_ids.iter()) {
        return Err(SafeError::validation());
    }
    if let Some((old_manifest, old_entries)) = previous
        && (old_manifest.pc_id != *pc
            || manifest.catalog_generation < old_manifest.catalog_generation
            || (manifest.catalog_generation == old_manifest.catalog_generation
                && (manifest != old_manifest || &entries != old_entries)))
    {
        return Err(SafeError::new("catalog_generation_conflict"));
    }
    Ok(entries)
}
