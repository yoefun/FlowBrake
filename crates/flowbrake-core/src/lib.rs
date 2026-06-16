use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessRule {
    pub block_all: bool,
    pub limit_download: bool,
    pub download_kbps: u32,
    pub limit_upload: bool,
    pub upload_kbps: u32,
    pub adaptive: bool,
    pub adjusted_dl_bps: f64,
    pub adjusted_ul_bps: f64,
}

impl Default for ProcessRule {
    fn default() -> Self {
        Self {
            block_all: false,
            limit_download: false,
            download_kbps: 0,
            limit_upload: false,
            upload_kbps: 0,
            adaptive: false,
            adjusted_dl_bps: 0.0,
            adjusted_ul_bps: 0.0,
        }
    }
}

impl ProcessRule {
    pub fn has_any_rule(&self) -> bool {
        self.block_all
            || self.limit_download
            || self.download_kbps > 0
            || self.limit_upload
            || self.upload_kbps > 0
            || self.adaptive
    }

    pub fn target_bps(&self, direction: Direction) -> Option<f64> {
        match direction {
            Direction::Download if self.limit_download && self.download_kbps > 0 => {
                Some(self.download_kbps as f64 * 1024.0)
            }
            Direction::Upload if self.limit_upload && self.upload_kbps > 0 => {
                Some(self.upload_kbps as f64 * 1024.0)
            }
            _ => None,
        }
    }

    pub fn effective_bps(&self, direction: Direction) -> Option<f64> {
        let target = self.target_bps(direction)?;
        if !self.adaptive {
            return Some(target);
        }

        let adjusted = match direction {
            Direction::Download => self.adjusted_dl_bps,
            Direction::Upload => self.adjusted_ul_bps,
        };

        Some(if adjusted > 0.0 { adjusted } else { target })
    }
}

pub type GlobalRule = ProcessRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub fn is_upload(self) -> bool {
        matches!(self, Self::Upload)
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    rate_bps: f64,
}

impl TokenBucket {
    pub fn new(rate_bps: f64) -> Self {
        let burst = (rate_bps * 2.0).max(0.0);
        Self {
            tokens: burst,
            max_tokens: burst,
            rate_bps: rate_bps.max(0.0),
        }
    }

    pub fn rate_bps(&self) -> f64 {
        self.rate_bps
    }

    pub fn set_rate(&mut self, rate_bps: f64) {
        self.rate_bps = rate_bps.max(0.0);
        self.max_tokens = self.rate_bps * 2.0;
        if self.tokens > self.max_tokens {
            self.tokens = self.max_tokens;
        }
    }

    pub fn try_consume(&mut self, bytes: usize, elapsed: Duration) -> bool {
        self.refill(elapsed);
        let bytes = bytes as f64;
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, elapsed: Duration) {
        self.tokens = (self.tokens + self.rate_bps * elapsed.as_secs_f64()).min(self.max_tokens);
    }
}

#[derive(Debug, Clone)]
pub struct RollingAverage {
    window: usize,
    samples: VecDeque<f64>,
}

impl RollingAverage {
    pub fn new(window: usize) -> Self {
        Self {
            window: window.max(1),
            samples: VecDeque::new(),
        }
    }

    pub fn push(&mut self, sample: f64) {
        self.samples.push_back(sample.max(0.0));
        while self.samples.len() > self.window {
            self.samples.pop_front();
        }
    }

    pub fn average(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f64>() / self.samples.len() as f64
    }
}

pub fn compute_adaptive_rate(current_rate: f64, measured_avg: f64, target: f64) -> f64 {
    if target <= 0.0 {
        return 0.0;
    }

    let current_rate = if current_rate <= 0.0 {
        target
    } else {
        current_rate
    };

    if measured_avg < 100.0 {
        return current_rate;
    }

    let ratio = measured_avg / target;
    let new_rate = if ratio > 1.02 {
        let correction = target / measured_avg;
        current_rate * (0.3 + 0.7 * correction)
    } else if ratio < 0.90 {
        current_rate * 1.15
    } else if ratio < 0.98 {
        current_rate * 1.05
    } else {
        return current_rate;
    };

    new_rate.clamp(target * 0.05, target)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpeedUnit {
    #[default]
    Bits,
    Bytes,
}

impl SpeedUnit {
    pub fn from_bits_mode(bits_mode: bool) -> Self {
        if bits_mode {
            Self::Bits
        } else {
            Self::Bytes
        }
    }

    pub fn is_bits(self) -> bool {
        matches!(self, Self::Bits)
    }
}

pub fn format_speed(bytes_per_sec: f64, unit: SpeedUnit) -> String {
    match unit {
        SpeedUnit::Bytes => format_speed_bytes(bytes_per_sec),
        SpeedUnit::Bits => format_speed_bits(bytes_per_sec * 8.0),
    }
}

fn format_speed_bytes(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        return "0 B/s".to_string();
    }
    if bytes_per_sec < 1024.0 {
        return format!("{bytes_per_sec:.0} B/s");
    }
    let kb = bytes_per_sec / 1024.0;
    if kb < 1024.0 {
        return format!("{kb:.1} KB/s");
    }
    format!("{:.2} MB/s", kb / 1024.0)
}

fn format_speed_bits(bits_per_sec: f64) -> String {
    if bits_per_sec < 1.0 {
        return "0 b/s".to_string();
    }
    if bits_per_sec < 1000.0 {
        return format!("{bits_per_sec:.0} b/s");
    }
    let kb = bits_per_sec / 1000.0;
    if kb < 1000.0 {
        return format!("{kb:.1} Kb/s");
    }
    format!("{:.2} Mb/s", kb / 1000.0)
}

pub fn format_limit_kibps(kibps: u32, unit: SpeedUnit) -> String {
    match unit {
        SpeedUnit::Bytes => kibps.to_string(),
        SpeedUnit::Bits => {
            let kbps = kibps as f64 * 1024.0 * 8.0 / 1000.0;
            format!("{:.0}", kbps.round())
        }
    }
}

pub fn parse_limit_input(text: &str, unit: SpeedUnit) -> Option<u32> {
    let text = text.trim();
    if text.is_empty() {
        return Some(0);
    }

    match unit {
        SpeedUnit::Bytes => text.parse::<u32>().ok(),
        SpeedUnit::Bits => {
            let kbps: f64 = text.parse().ok()?;
            let kibps = (kbps * 1000.0 / 8.0 / 1024.0).round();
            if !(0.0..=u32::MAX as f64).contains(&kibps) {
                return None;
            }
            Some(kibps as u32)
        }
    }
}

pub fn format_limit_summary(kibps: u32, unit: SpeedUnit) -> String {
    if kibps == 0 {
        return "Off".to_string();
    }
    match unit {
        SpeedUnit::Bytes => format!("{kibps} KB/s"),
        SpeedUnit::Bits => format_speed(kibps as f64 * 1024.0, SpeedUnit::Bits),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RowKind {
    Global,
    Group {
        process_name: String,
        pids: Vec<u32>,
        expanded: bool,
    },
    Child {
        process_name: String,
        pid: u32,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessRow {
    pub kind: RowKind,
    pub dl_bps: f64,
    pub ul_bps: f64,
    pub rule: ProcessRule,
}

impl ProcessRow {
    pub fn global(rule: GlobalRule) -> Self {
        Self {
            kind: RowKind::Global,
            dl_bps: 0.0,
            ul_bps: 0.0,
            rule,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Process,
    Pid,
    DownloadSpeed,
    UploadSpeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

pub fn build_process_rows(
    processes: &[ProcessInfo],
    expanded_names: &HashSet<String>,
    rules: &HashMap<u32, ProcessRule>,
    speeds: &HashMap<u32, (f64, f64)>,
    global_rule: GlobalRule,
    sort_column: SortColumn,
    sort_direction: SortDirection,
) -> Vec<ProcessRow> {
    let mut groups: HashMap<String, (String, Vec<u32>)> = HashMap::new();
    for process in processes {
        groups
            .entry(process.name.to_lowercase())
            .or_insert_with(|| (process.name.clone(), Vec::new()))
            .1
            .push(process.pid);
    }

    let mut groups: Vec<(String, Vec<u32>)> = groups.into_values().collect();
    for (_, pids) in &mut groups {
        pids.sort_unstable();
    }

    groups.sort_by(|a, b| compare_groups(a, b, speeds, sort_column, sort_direction));

    let mut rows = vec![ProcessRow::global(global_rule)];
    for (name, pids) in groups {
        let expanded = expanded_names.contains(&name.to_lowercase());
        let rule = first_existing_rule(&pids, rules);
        rows.push(ProcessRow {
            kind: RowKind::Group {
                process_name: name.clone(),
                pids: pids.clone(),
                expanded,
            },
            dl_bps: sum_speed(&pids, speeds, Direction::Download),
            ul_bps: sum_speed(&pids, speeds, Direction::Upload),
            rule,
        });

        if pids.len() > 1 && expanded {
            for pid in pids {
                let rule = rules.get(&pid).cloned().unwrap_or_default();
                let (dl_bps, ul_bps) = speeds.get(&pid).copied().unwrap_or_default();
                rows.push(ProcessRow {
                    kind: RowKind::Child {
                        process_name: name.clone(),
                        pid,
                    },
                    dl_bps,
                    ul_bps,
                    rule,
                });
            }
        }
    }

    rows
}

fn compare_groups(
    a: &(String, Vec<u32>),
    b: &(String, Vec<u32>),
    speeds: &HashMap<u32, (f64, f64)>,
    sort_column: SortColumn,
    sort_direction: SortDirection,
) -> Ordering {
    let ordering = match sort_column {
        SortColumn::Process => a.0.to_lowercase().cmp(&b.0.to_lowercase()),
        SortColumn::Pid => a.1.iter().min().cmp(&b.1.iter().min()),
        SortColumn::DownloadSpeed => sum_speed(&a.1, speeds, Direction::Download)
            .partial_cmp(&sum_speed(&b.1, speeds, Direction::Download))
            .unwrap_or(Ordering::Equal),
        SortColumn::UploadSpeed => sum_speed(&a.1, speeds, Direction::Upload)
            .partial_cmp(&sum_speed(&b.1, speeds, Direction::Upload))
            .unwrap_or(Ordering::Equal),
    };

    match sort_direction {
        SortDirection::Ascending => ordering,
        SortDirection::Descending => ordering.reverse(),
    }
}

fn first_existing_rule(pids: &[u32], rules: &HashMap<u32, ProcessRule>) -> ProcessRule {
    pids.iter()
        .find_map(|pid| rules.get(pid).cloned())
        .unwrap_or_default()
}

fn sum_speed(pids: &[u32], speeds: &HashMap<u32, (f64, f64)>, direction: Direction) -> f64 {
    pids.iter()
        .map(|pid| {
            let (dl, ul) = speeds.get(pid).copied().unwrap_or_default();
            match direction {
                Direction::Download => dl,
                Direction::Upload => ul,
            }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_reports_only_meaningful_limits() {
        let mut rule = ProcessRule {
            limit_download: true,
            download_kbps: 0,
            ..Default::default()
        };
        assert!(rule.has_any_rule());
        assert_eq!(rule.target_bps(Direction::Download), None);

        rule.download_kbps = 128;
        assert!(rule.has_any_rule());
        assert_eq!(rule.target_bps(Direction::Download), Some(131_072.0));
        assert_eq!(rule.effective_bps(Direction::Download), Some(131_072.0));
    }

    #[test]
    fn rule_preserves_draft_limit_value_without_enabling_limit() {
        let rule = ProcessRule {
            download_kbps: 128,
            ..Default::default()
        };
        assert!(rule.has_any_rule());
        assert_eq!(rule.target_bps(Direction::Download), None);
        assert_eq!(rule.effective_bps(Direction::Download), None);
    }

    #[test]
    fn adaptive_rule_uses_adjusted_rate_when_available() {
        let rule = ProcessRule {
            limit_upload: true,
            upload_kbps: 100,
            adaptive: true,
            adjusted_ul_bps: 30_000.0,
            ..Default::default()
        };
        assert_eq!(rule.effective_bps(Direction::Upload), Some(30_000.0));
    }

    #[test]
    fn token_bucket_allows_initial_burst_then_refill() {
        let mut bucket = TokenBucket::new(100.0);
        assert!(bucket.try_consume(200, Duration::ZERO));
        assert!(!bucket.try_consume(1, Duration::ZERO));
        assert!(bucket.try_consume(50, Duration::from_millis(500)));
    }

    #[test]
    fn token_bucket_rate_change_clamps_tokens() {
        let mut bucket = TokenBucket::new(1000.0);
        bucket.set_rate(100.0);
        assert!(bucket.try_consume(200, Duration::ZERO));
        assert!(!bucket.try_consume(1, Duration::ZERO));
    }

    #[test]
    fn rolling_average_keeps_bounded_window() {
        let mut avg = RollingAverage::new(3);
        avg.push(10.0);
        avg.push(20.0);
        avg.push(30.0);
        avg.push(40.0);
        assert_eq!(avg.average(), 30.0);
    }

    #[test]
    fn adaptive_rate_matches_csharp_controller_shape() {
        let target = 1000.0;
        assert_eq!(compute_adaptive_rate(0.0, 0.0, target), target);
        assert!(compute_adaptive_rate(target, 2000.0, target) < target);
        assert_eq!(compute_adaptive_rate(target, 800.0, target), target);
        assert_eq!(compute_adaptive_rate(10.0, 10_000.0, target), 50.0);
    }

    #[test]
    fn speed_format_matches_byte_display() {
        assert_eq!(format_speed(0.0, SpeedUnit::Bytes), "0 B/s");
        assert_eq!(format_speed(512.0, SpeedUnit::Bytes), "512 B/s");
        assert_eq!(format_speed(1536.0, SpeedUnit::Bytes), "1.5 KB/s");
        assert_eq!(
            format_speed(2.0 * 1024.0 * 1024.0, SpeedUnit::Bytes),
            "2.00 MB/s"
        );
    }

    #[test]
    fn speed_format_matches_isp_bit_display() {
        assert_eq!(format_speed(0.0, SpeedUnit::Bits), "0 b/s");
        assert_eq!(format_speed(125.0, SpeedUnit::Bits), "1.0 Kb/s");
        assert_eq!(format_speed(125_000.0, SpeedUnit::Bits), "1.00 Mb/s");
    }

    #[test]
    fn limit_input_round_trips_between_units() {
        assert_eq!(parse_limit_input("128", SpeedUnit::Bytes), Some(128));
        assert_eq!(format_limit_kibps(128, SpeedUnit::Bytes), "128");
        assert_eq!(parse_limit_input("1049", SpeedUnit::Bits), Some(128));
        assert_eq!(format_limit_kibps(128, SpeedUnit::Bits), "1049");
    }

    #[test]
    fn process_rows_group_case_insensitively() {
        let processes = vec![
            ProcessInfo {
                pid: 2,
                name: "chrome".into(),
            },
            ProcessInfo {
                pid: 1,
                name: "Chrome".into(),
            },
            ProcessInfo {
                pid: 5,
                name: "curl".into(),
            },
        ];
        let expanded = HashSet::from(["chrome".to_string()]);
        let speeds = HashMap::from([(1, (10.0, 1.0)), (2, (20.0, 2.0)), (5, (5.0, 50.0))]);

        let rows = build_process_rows(
            &processes,
            &expanded,
            &HashMap::new(),
            &speeds,
            GlobalRule::default(),
            SortColumn::Process,
            SortDirection::Ascending,
        );

        assert!(matches!(rows[0].kind, RowKind::Global));
        assert_eq!(rows.len(), 5);
        assert!(matches!(
            &rows[1].kind,
            RowKind::Group {
                process_name,
                pids,
                expanded: true
            } if process_name == "chrome" && pids == &vec![1, 2]
        ));
        assert_eq!(rows[1].dl_bps, 30.0);
        assert_eq!(rows[1].ul_bps, 3.0);
    }

    #[test]
    fn expanded_state_matches_lowercase_keys() {
        let processes = vec![
            ProcessInfo {
                pid: 1,
                name: "Chrome.exe".into(),
            },
            ProcessInfo {
                pid: 2,
                name: "chrome.exe".into(),
            },
        ];
        let expanded = HashSet::from(["chrome.exe".to_string()]);
        let speeds = HashMap::from([(1, (10.0, 1.0)), (2, (20.0, 2.0))]);

        let rows = build_process_rows(
            &processes,
            &expanded,
            &HashMap::new(),
            &speeds,
            GlobalRule::default(),
            SortColumn::Process,
            SortDirection::Ascending,
        );

        assert!(matches!(
            &rows[1].kind,
            RowKind::Group { expanded: true, .. }
        ));
        assert_eq!(rows.len(), 4);
    }
}
