use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use flowbrake_core::ProcessRule;
use slint::{LogicalPosition, LogicalSize, Window};

pub const DEFAULT_WINDOW_WIDTH: f32 = 1180.0;
pub const DEFAULT_WINDOW_HEIGHT: f32 = 700.0;
pub const MIN_WINDOW_WIDTH: f32 = 900.0;
pub const MIN_WINDOW_HEIGHT: f32 = 500.0;

const SPEED_UNIT_BITS_KEY: &str = "speed_unit_bits";
const IPV6_ENABLED_KEY: &str = "ipv6_enabled";
const WINDOW_WIDTH_KEY: &str = "window_width";
const WINDOW_HEIGHT_KEY: &str = "window_height";
const WINDOW_X_KEY: &str = "window_x";
const WINDOW_Y_KEY: &str = "window_y";
const WINDOW_MAXIMIZED_KEY: &str = "window_maximized";
const EXPANDED_KEY: &str = "expanded";

#[derive(Debug, Clone, PartialEq)]
pub struct AppSettings {
    pub speed_unit_bits: bool,
    pub ipv6_enabled: bool,
    pub window_width: f32,
    pub window_height: f32,
    pub window_x: f32,
    pub window_y: f32,
    pub window_maximized: bool,
    pub global_rule: ProcessRule,
    pub name_rules: HashMap<String, ProcessRule>,
    pub expanded: HashSet<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            speed_unit_bits: true,
            ipv6_enabled: true,
            window_width: DEFAULT_WINDOW_WIDTH,
            window_height: DEFAULT_WINDOW_HEIGHT,
            window_x: -1.0,
            window_y: -1.0,
            window_maximized: false,
            global_rule: ProcessRule::default(),
            name_rules: HashMap::new(),
            expanded: HashSet::new(),
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
        let mut rule_entries: HashMap<String, HashMap<String, String>> = HashMap::new();

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            match key {
                SPEED_UNIT_BITS_KEY => {
                    settings.speed_unit_bits = parse_bool(value);
                }
                IPV6_ENABLED_KEY => {
                    settings.ipv6_enabled = parse_bool(value);
                }
                WINDOW_WIDTH_KEY => {
                    if let Some(width) = parse_f32(value) {
                        settings.window_width = width.clamp(MIN_WINDOW_WIDTH, 10_000.0);
                    }
                }
                WINDOW_HEIGHT_KEY => {
                    if let Some(height) = parse_f32(value) {
                        settings.window_height = height.clamp(MIN_WINDOW_HEIGHT, 10_000.0);
                    }
                }
                WINDOW_X_KEY => {
                    if let Some(x) = parse_f32(value) {
                        settings.window_x = x;
                    }
                }
                WINDOW_Y_KEY => {
                    if let Some(y) = parse_f32(value) {
                        settings.window_y = y;
                    }
                }
                WINDOW_MAXIMIZED_KEY => {
                    settings.window_maximized = parse_bool(value);
                }
                EXPANDED_KEY => {
                    settings.expanded = value
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_lowercase)
                        .collect();
                }
                _ if key.starts_with("global.") => {
                    let field = key.strip_prefix("global.").unwrap_or_default();
                    rule_entries
                        .entry("global".to_string())
                        .or_default()
                        .insert(field.to_string(), value.to_string());
                }
                _ if key.starts_with("rule.") => {
                    let remainder = key.strip_prefix("rule.").unwrap_or_default();
                    let Some((name, field)) = remainder.split_once('.') else {
                        continue;
                    };
                    let name = name.trim().to_lowercase();
                    if name.is_empty() {
                        continue;
                    }
                    rule_entries
                        .entry(name)
                        .or_default()
                        .insert(field.trim().to_string(), value.to_string());
                }
                _ => {}
            }
        }

        if let Some(global_fields) = rule_entries.remove("global") {
            settings.global_rule = parse_rule_fields(&global_fields);
        }
        settings.name_rules = rule_entries
            .into_iter()
            .map(|(name, fields)| (name, parse_rule_fields(&fields)))
            .filter(|(_, rule)| rule.has_any_rule())
            .collect();

        settings
    }

    pub fn save(&self) -> Result<(), String> {
        let path = settings_path().ok_or_else(|| "APPDATA is unavailable".to_string())?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }

        let mut lines = Vec::new();
        lines.push("# FlowBrake settings".to_string());
        lines.push(format!(
            "{SPEED_UNIT_BITS_KEY}={}",
            bool_text(self.speed_unit_bits)
        ));
        lines.push(format!(
            "{IPV6_ENABLED_KEY}={}",
            bool_text(self.ipv6_enabled)
        ));
        lines.push(format!("{WINDOW_WIDTH_KEY}={}", self.window_width));
        lines.push(format!("{WINDOW_HEIGHT_KEY}={}", self.window_height));
        lines.push(format!("{WINDOW_X_KEY}={}", self.window_x));
        lines.push(format!("{WINDOW_Y_KEY}={}", self.window_y));
        lines.push(format!(
            "{WINDOW_MAXIMIZED_KEY}={}",
            bool_text(self.window_maximized)
        ));

        if !self.expanded.is_empty() {
            let mut expanded: Vec<_> = self.expanded.iter().cloned().collect();
            expanded.sort_unstable();
            lines.push(format!("{EXPANDED_KEY}={}", expanded.join(",")));
        }

        append_rule_lines(&mut lines, "global", &self.global_rule);
        let mut names: Vec<_> = self.name_rules.keys().cloned().collect();
        names.sort_unstable();
        for name in names {
            if let Some(rule) = self.name_rules.get(&name) {
                append_rule_lines(&mut lines, &format!("rule.{name}"), rule);
            }
        }

        fs::write(path, lines.join("\n") + "\n").map_err(|err| err.to_string())
    }

    pub fn capture_window(&mut self, window: &Window) {
        self.window_maximized = window.is_maximized();
        if self.window_maximized {
            return;
        }

        let size = window.size();
        self.window_width = (size.width as f32).clamp(MIN_WINDOW_WIDTH, 10_000.0);
        self.window_height = (size.height as f32).clamp(MIN_WINDOW_HEIGHT, 10_000.0);

        let position = window.position();
        self.window_x = position.x as f32;
        self.window_y = position.y as f32;
    }

    pub fn apply_window(&self, window: &Window) {
        if self.window_maximized {
            window.set_maximized(true);
            return;
        }

        window.set_maximized(false);
        window.set_size(LogicalSize::new(
            self.window_width.clamp(MIN_WINDOW_WIDTH, 10_000.0),
            self.window_height.clamp(MIN_WINDOW_HEIGHT, 10_000.0),
        ));

        if self.window_x >= 0.0 && self.window_y >= 0.0 {
            window.set_position(LogicalPosition::new(self.window_x, self.window_y));
        }
    }
}

fn settings_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|appdata| {
        PathBuf::from(appdata)
            .join("FlowBrake")
            .join("settings.ini")
    })
}

fn parse_bool(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes")
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn parse_f32(value: &str) -> Option<f32> {
    value.parse().ok()
}

fn parse_u32(value: &str) -> Option<u32> {
    value.parse().ok()
}

fn parse_rule_fields(fields: &HashMap<String, String>) -> ProcessRule {
    ProcessRule {
        block_all: fields
            .get("block_all")
            .is_some_and(|value| parse_bool(value)),
        limit_download: fields
            .get("limit_download")
            .is_some_and(|value| parse_bool(value)),
        download_kbps: fields
            .get("download_kbps")
            .and_then(|value| parse_u32(value))
            .unwrap_or(0),
        limit_upload: fields
            .get("limit_upload")
            .is_some_and(|value| parse_bool(value)),
        upload_kbps: fields
            .get("upload_kbps")
            .and_then(|value| parse_u32(value))
            .unwrap_or(0),
        adaptive: fields
            .get("adaptive")
            .is_some_and(|value| parse_bool(value)),
        adjusted_dl_bps: 0.0,
        adjusted_ul_bps: 0.0,
    }
}

fn append_rule_lines(lines: &mut Vec<String>, prefix: &str, rule: &ProcessRule) {
    if !rule.has_any_rule() && prefix != "global" {
        return;
    }

    lines.push(format!("{prefix}.block_all={}", bool_text(rule.block_all)));
    lines.push(format!(
        "{prefix}.limit_download={}",
        bool_text(rule.limit_download)
    ));
    lines.push(format!("{prefix}.download_kbps={}", rule.download_kbps));
    lines.push(format!(
        "{prefix}.limit_upload={}",
        bool_text(rule.limit_upload)
    ));
    lines.push(format!("{prefix}.upload_kbps={}", rule.upload_kbps));
    lines.push(format!("{prefix}.adaptive={}", bool_text(rule.adaptive)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_isp_bit_units() {
        let settings = AppSettings::default();
        assert!(settings.speed_unit_bits);
        assert!(settings.ipv6_enabled);
        assert_eq!(settings.window_width, DEFAULT_WINDOW_WIDTH);
        assert_eq!(settings.window_height, DEFAULT_WINDOW_HEIGHT);
    }

    #[test]
    fn parses_rule_fields() {
        let mut fields = HashMap::new();
        fields.insert("limit_download".to_string(), "true".to_string());
        fields.insert("download_kbps".to_string(), "256".to_string());
        let rule = parse_rule_fields(&fields);
        assert!(rule.limit_download);
        assert_eq!(rule.download_kbps, 256);
        assert_eq!(rule.adjusted_dl_bps, 0.0);
    }
}
