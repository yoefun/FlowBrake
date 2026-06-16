use std::fs;
use std::path::PathBuf;

const SPEED_UNIT_BITS_KEY: &str = "speed_unit_bits";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSettings {
    pub speed_unit_bits: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            speed_unit_bits: true,
        }
    }
}

impl AppSettings {
    pub fn load() -> Self {
        let Some(path) = settings_path() else {
            return Self::default();
        };
        let Ok(contents) = fs::read_to_string(path) else {
            return Self::default();
        };

        let mut settings = Self::default();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == SPEED_UNIT_BITS_KEY {
                settings.speed_unit_bits = matches!(value.trim(), "1" | "true" | "yes");
            }
        }
        settings
    }

    pub fn save(&self) -> Result<(), String> {
        let path = settings_path().ok_or_else(|| "APPDATA is unavailable".to_string())?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let value = if self.speed_unit_bits { "true" } else { "false" };
        fs::write(path, format!("{SPEED_UNIT_BITS_KEY}={value}\n")).map_err(|err| err.to_string())
    }
}

fn settings_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|appdata| {
        PathBuf::from(appdata)
            .join("FlowBrake")
            .join("settings.ini")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_isp_bit_units() {
        let settings = AppSettings::default();
        assert!(settings.speed_unit_bits);
    }
}
