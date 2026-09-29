use serde::{Deserialize, Serialize};

pub const WALK_SETTINGS_STORE_KEY: &str = "walk_settings";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalkMode {
    Normal,
    Mail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkModeSettings {
    pub minimum_hops: usize,
    pub maximum_hops: usize,
    pub minimum_interval_secs: u64,
    pub target_interval_secs: u64,
    pub maximum_interval_secs: u64,
}

impl WalkModeSettings {
    pub fn sanitized(self) -> Self {
        let minimum_hops = self.minimum_hops.clamp(1, 10_000);
        let maximum_hops = self.maximum_hops.clamp(minimum_hops, 10_000);
        let minimum_interval_secs = self.minimum_interval_secs.clamp(30, 24 * 60 * 60);
        let maximum_interval_secs = self
            .maximum_interval_secs
            .clamp(minimum_interval_secs, 7 * 24 * 60 * 60);
        let target_interval_secs = self
            .target_interval_secs
            .clamp(minimum_interval_secs, maximum_interval_secs);

        Self {
            minimum_hops,
            maximum_hops,
            minimum_interval_secs,
            target_interval_secs,
            maximum_interval_secs,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkSettings {
    pub normal: WalkModeSettings,
    pub mail: WalkModeSettings,
    pub mail_mode_enabled: bool,
}

impl WalkSettings {
    pub fn sanitized(self) -> Self {
        Self {
            normal: self.normal.sanitized(),
            mail: self.mail.sanitized(),
            mail_mode_enabled: self.mail_mode_enabled,
        }
    }

    pub fn for_mode(self, mode: WalkMode) -> WalkModeSettings {
        match mode {
            WalkMode::Normal => self.normal,
            WalkMode::Mail => self.mail,
        }
        .sanitized()
    }
}

impl Default for WalkSettings {
    fn default() -> Self {
        Self {
            normal: WalkModeSettings {
                minimum_hops: 5,
                maximum_hops: 100,
                minimum_interval_secs: 5 * 60,
                target_interval_secs: 30 * 60,
                maximum_interval_secs: 2 * 60 * 60,
            },
            mail: WalkModeSettings {
                minimum_hops: 7,
                maximum_hops: 135,
                minimum_interval_secs: 2 * 60,
                target_interval_secs: 150,
                maximum_interval_secs: 10 * 60,
            },
            mail_mode_enabled: false,
        }
    }
}
