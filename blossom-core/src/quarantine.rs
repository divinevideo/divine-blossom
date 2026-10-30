//! Independent, non-expiring media review holds.
use crate::conditional_update::ConditionalJsonMutation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_HOLDS: usize = 128;
pub const HOLD_VERSION_CONFLICT: &str =
    "A quarantine hold version cannot represent conflicting actions";
pub const HOLD_CAPACITY_EXCEEDED: &str =
    "The quarantine hold record already contains 128 distinct hold IDs";
const MAX_SAFE_VERSION: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuarantineAction {
    Hold,
    Release,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineHolds {
    pub version: u32,
    pub holds: BTreeMap<String, QuarantineHold>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineHold {
    pub version: u64,
    pub active: bool,
}

impl Default for QuarantineHolds {
    fn default() -> Self {
        Self {
            version: 1,
            holds: BTreeMap::new(),
        }
    }
}

pub fn validate_hold_version(version: u64) -> Result<(), String> {
    if version == 0 || version > MAX_SAFE_VERSION {
        return Err("version must be a positive JavaScript-safe integer".into());
    }
    Ok(())
}

pub fn validate_hold_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_-".contains(&b))
    {
        return Err(
            "hold_id must contain 1–128 ASCII letters, digits, colons, underscores or hyphens"
                .into(),
        );
    }
    Ok(())
}

impl QuarantineHolds {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.holds.len() > MAX_HOLDS {
            return Err("Invalid quarantine holds record".into());
        }
        for (id, hold) in &self.holds {
            validate_hold_id(id)?;
            validate_hold_version(hold.version)?;
        }
        Ok(())
    }

    pub fn active_ids(&self) -> Vec<String> {
        self.holds
            .iter()
            .filter(|(_, hold)| hold.active)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

pub fn mutate_holds(
    current: Option<QuarantineHolds>,
    id: &str,
    version: u64,
    action: QuarantineAction,
) -> Result<ConditionalJsonMutation<QuarantineHolds, QuarantineHolds>, String> {
    validate_hold_id(id)?;
    validate_hold_version(version)?;
    let mut holds = current.unwrap_or_default();
    holds.validate()?;
    let active = matches!(action, QuarantineAction::Hold);
    if let Some(current) = holds.holds.get(id) {
        if version < current.version || (version == current.version && active == current.active) {
            return Ok(ConditionalJsonMutation::Complete(holds));
        }
        if version == current.version {
            return Err(HOLD_VERSION_CONFLICT.into());
        }
    } else if holds.holds.len() == MAX_HOLDS {
        return Err(HOLD_CAPACITY_EXCEEDED.into());
    }
    // Inactive entries retain ordering so a delayed hold cannot undo a release.
    holds
        .holds
        .insert(id.into(), QuarantineHold { version, active });
    holds.validate()?;
    Ok(ConditionalJsonMutation::Write {
        value: holds.clone(),
        result: holds,
        time_to_live: None,
    })
}
