#![cfg_attr(all(not(test), target_os = "windows"), windows_subsystem = "windows")]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use flowbrake_core::{
    Direction, GlobalRule, ProcessRow as CoreProcessRow, ProcessRule, RollingAverage, RowKind,
    SortColumn, SortDirection, SpeedUnit, TcpConnection, TcpConnectionKey, build_process_rows,
    compute_adaptive_rate, format_delay_ms, format_limit_kibps, format_limit_summary,
    format_loss_percent, format_speed, parse_delay_ms, parse_limit_input, parse_loss_percent,
};
use flowbrake_windows::{
    EngineCommand, NetworkEngine, ProcessMetadataCache, RelaunchResult, close_tcp_connection,
    close_tcp_connections_for_pids, computer_name, get_network_processes, is_elevated,
    list_tcp_connections, process_icon, relaunch_as_admin, show_admin_required_message,
};
use slint::{
    CloseRequestResponse, ComponentHandle, Image, Model, ModelRc, Rgba8Pixel, SharedPixelBuffer,
    SharedString, Timer, TimerMode, VecModel,
};
use std::rc::Rc as StdRc;
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
};

mod i18n;
mod process_search;
mod settings;
mod window_chrome;

use process_search::{ProcessSearchLocate, locate_in_rows};

use i18n::LanguagePreference;
use settings::AppSettings;

slint::include_modules!();

const MAX_VISIBLE_CONNECTIONS: usize = 200;

struct AppState {
    engine: NetworkEngine,
    expanded: HashSet<String>,
    rules: HashMap<u32, ProcessRule>,
    name_rules: HashMap<String, ProcessRule>,
    global_rule: GlobalRule,
    rows: Vec<CoreProcessRow>,
    dl_history: HashMap<u32, RollingAverage>,
    ul_history: HashMap<u32, RollingAverage>,
    speeds: HashMap<u32, (f64, f64)>,
    global_dl_history: RollingAverage,
    global_ul_history: RollingAverage,
    global_dl_bps: f64,
    global_ul_bps: f64,
    tray: Option<TrayController>,
    suppress_table_refresh_until: Option<Instant>,
    limit_editing: bool,
    loss_selection: Option<RowSelection>,
    loss_download_draft: Option<String>,
    loss_upload_draft: Option<String>,
    delay_download_draft: Option<String>,
    delay_upload_draft: Option<String>,
    selected: Option<RowSelection>,
    speed_unit: SpeedUnit,
    ipv6_enabled: bool,
    language: LanguagePreference,
    status: StatusMessage,
    last_row_click: Option<(i32, Instant)>,
    icon_cache: HashMap<String, Image>,
    process_cache: ProcessMetadataCache,
    table_fingerprint: TableFingerprint,
    ui_rows: Option<StdRc<VecModel<ProcessRow>>>,
    computer_name: String,
    /// Current process search query; updated by `locate_process_search`.
    #[allow(dead_code)]
    process_search: String,
    connections_by_pid: HashMap<u32, Vec<TcpConnection>>,
    all_connections: Vec<TcpConnection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TableFingerprint {
    pids: Vec<u32>,
    expanded: Vec<String>,
}

impl TableFingerprint {
    fn from_processes(
        processes: &[flowbrake_core::ProcessInfo],
        expanded: &HashSet<String>,
    ) -> Self {
        let mut pids: Vec<u32> = processes.iter().map(|process| process.pid).collect();
        pids.sort_unstable();
        let mut expanded: Vec<String> = expanded.iter().cloned().collect();
        expanded.sort_unstable();
        Self { pids, expanded }
    }
}

impl AppState {
    fn new(settings: AppSettings) -> Self {
        let engine = NetworkEngine::from_current_exe_dir();
        engine.set_ipv6_enabled(settings.ipv6_enabled);
        Self {
            engine,
            expanded: settings.expanded,
            rules: HashMap::new(),
            name_rules: settings.name_rules,
            global_rule: settings.global_rule,
            rows: Vec::new(),
            dl_history: HashMap::new(),
            ul_history: HashMap::new(),
            speeds: HashMap::new(),
            global_dl_history: RollingAverage::new(5),
            global_ul_history: RollingAverage::new(5),
            global_dl_bps: 0.0,
            global_ul_bps: 0.0,
            tray: None,
            suppress_table_refresh_until: None,
            limit_editing: false,
            loss_selection: None,
            loss_download_draft: None,
            loss_upload_draft: None,
            delay_download_draft: None,
            delay_upload_draft: None,
            selected: None,
            speed_unit: SpeedUnit::from_bits_mode(settings.speed_unit_bits),
            ipv6_enabled: settings.ipv6_enabled,
            language: settings.language,
            status: StatusMessage::Stopped,
            last_row_click: None,
            icon_cache: HashMap::new(),
            process_cache: ProcessMetadataCache::default(),
            table_fingerprint: TableFingerprint {
                pids: Vec::new(),
                expanded: Vec::new(),
            },
            ui_rows: None,
            computer_name: computer_name(),
            process_search: String::new(),
            connections_by_pid: HashMap::new(),
            all_connections: Vec::new(),
        }
    }

    fn refresh_connections(&mut self) {
        self.all_connections = list_tcp_connections(self.ipv6_enabled);
        self.connections_by_pid.clear();
        for connection in &self.all_connections {
            self.connections_by_pid
                .entry(connection.pid)
                .or_default()
                .push(connection.clone());
        }
    }

    fn connections_for_pids(&self, pids: &[u32]) -> Vec<TcpConnection> {
        let mut connections: Vec<TcpConnection> = pids
            .iter()
            .flat_map(|pid| {
                self.connections_by_pid
                    .get(pid)
                    .into_iter()
                    .flatten()
                    .cloned()
            })
            .collect();
        connections.sort_by(|left, right| {
            left.display_remote()
                .cmp(&right.display_remote())
                .then_with(|| left.pid.cmp(&right.pid))
        });
        connections
    }

    fn set_speed_unit(&mut self, unit: SpeedUnit) {
        self.speed_unit = unit;
    }

    fn to_settings(&self) -> AppSettings {
        AppSettings {
            speed_unit_bits: matches!(self.speed_unit, SpeedUnit::Bits),
            ipv6_enabled: self.ipv6_enabled,
            language: self.language,
            global_rule: self.global_rule.clone(),
            name_rules: self.name_rules.clone(),
            expanded: self.expanded.clone(),
            ..AppSettings::default()
        }
    }

    fn set_ipv6_enabled(&mut self, enabled: bool) -> bool {
        if self.ipv6_enabled == enabled {
            return false;
        }
        self.ipv6_enabled = enabled;
        self.engine.set_ipv6_enabled(enabled);
        true
    }

    fn restart_engine(&mut self) -> Result<(), String> {
        if !self.engine.is_running() {
            return Ok(());
        }
        self.engine.stop();
        self.push_all_rules();
        self.engine.start().map_err(|err| err.to_string())
    }

    fn fetch_processes(&mut self) -> Vec<flowbrake_core::ProcessInfo> {
        get_network_processes(
            self.rules.keys().copied(),
            self.ipv6_enabled,
            &mut self.process_cache,
        )
    }

    fn apply_name_rules_from(&mut self, processes: &[flowbrake_core::ProcessInfo]) {
        let added = inherit_name_rules(&mut self.rules, &self.name_rules, processes);

        if self.engine.is_running() {
            for (pid, rule) in added {
                self.engine
                    .apply(EngineCommand::UpdateRule(pid, runtime_rule(&rule)));
            }
        }
    }

    fn rebuild_rows_from(&mut self, processes: &[flowbrake_core::ProcessInfo]) {
        self.rows = build_process_rows(
            processes,
            &self.expanded,
            &self.rules,
            &self.speeds,
            self.global_rule.clone(),
            SortColumn::Process,
            SortDirection::Ascending,
        );
        self.refresh_row_speeds();
    }

    fn refresh_row_speeds(&mut self) {
        if let Some(global) = self.rows.first_mut() {
            global.dl_bps = self.global_dl_bps;
            global.ul_bps = self.global_ul_bps;
        }

        for row in self.rows.iter_mut().skip(1) {
            match &mut row.kind {
                RowKind::Group { pids, .. } => {
                    row.dl_bps = sum_group_speed(pids, &self.speeds, Direction::Download);
                    row.ul_bps = sum_group_speed(pids, &self.speeds, Direction::Upload);
                }
                RowKind::Child { pid, .. } => {
                    let (dl_bps, ul_bps) = self.speeds.get(pid).copied().unwrap_or_default();
                    row.dl_bps = dl_bps;
                    row.ul_bps = ul_bps;
                }
                RowKind::Global => {}
            }
        }
    }

    fn rebuild_rows(&mut self) {
        let processes = self.fetch_processes();
        self.apply_name_rules_from(&processes);
        self.rebuild_rows_from(&processes);
        self.table_fingerprint = TableFingerprint::from_processes(&processes, &self.expanded);
    }

    fn start(&mut self) -> Result<(), String> {
        self.engine.set_ipv6_enabled(self.ipv6_enabled);
        self.push_all_rules();
        self.engine.start().map_err(|err| err.to_string())
    }

    fn stop(&mut self) {
        self.engine.stop();
        for rule in self.rules.values_mut() {
            rule.adjusted_dl_bps = 0.0;
            rule.adjusted_ul_bps = 0.0;
        }
        self.global_rule.adjusted_dl_bps = 0.0;
        self.global_rule.adjusted_ul_bps = 0.0;
    }

    fn full_exit(&mut self) {
        self.engine.apply(EngineCommand::ClearRules);
        self.rules.clear();
        self.global_rule = GlobalRule::default();
        self.stop();
        self.set_tray_visible(false);
    }

    fn set_tray_visible(&self, visible: bool) {
        if let Some(tray) = &self.tray {
            let _ = tray.icon.set_visible(visible);
        }
    }

    fn select_row(&mut self, row_index: i32) {
        self.selected = self
            .rows
            .get(row_index as usize)
            .map(|row| RowSelection::from(&row.kind));
    }

    fn handle_row_click(&mut self, row_index: i32) -> bool {
        let now = Instant::now();
        if let Some((last_index, last_time)) = self.last_row_click
            && last_index == row_index
            && now.duration_since(last_time) < Duration::from_millis(400)
        {
            self.last_row_click = None;
            return true;
        }
        self.last_row_click = Some((row_index, now));
        false
    }

    fn toggle_row_expanded(&mut self, row_index: i32) {
        let Some(row) = self.rows.get(row_index as usize).cloned() else {
            return;
        };
        let RowKind::Group {
            process_name,
            pids,
            expanded,
            ..
        } = &row.kind
        else {
            return;
        };
        if pids.len() <= 1 {
            return;
        }

        let key = process_name.to_lowercase();
        if *expanded {
            self.expanded.remove(&key);
            if let Some(RowSelection::Child(pid)) = &self.selected
                && pids.contains(pid)
            {
                self.selected = Some(RowSelection::Group(key));
            }
        } else {
            self.expanded.insert(key);
        }
    }

    fn clear_selection(&mut self) {
        self.selected = None;
    }

    fn edit_bool(&mut self, row_index: i32, field: &str, value: bool) {
        let Some(row) = self.rows.get(row_index as usize).cloned() else {
            return;
        };
        self.selected = Some(RowSelection::from(&row.kind));
        let mut rule = row.rule.clone();
        match field {
            "limit_dl" => rule.limit_download = value,
            "limit_ul" => rule.limit_upload = value,
            "block" => rule.block_all = value,
            "adaptive" => {
                rule.adaptive = value;
                if !value {
                    rule.adjusted_dl_bps = 0.0;
                    rule.adjusted_ul_bps = 0.0;
                }
            }
            _ => return,
        }
        self.apply_rule_to_row(&row.kind, rule);
    }

    fn edit_selected_bool(&mut self, field: &str, value: bool) {
        let Some(row) = self.selected_row().cloned() else {
            return;
        };
        let mut rule = row.rule.clone();
        match field {
            "limit_dl" => rule.limit_download = value,
            "limit_ul" => rule.limit_upload = value,
            "block" => rule.block_all = value,
            "adaptive" => {
                rule.adaptive = value;
                if !value {
                    rule.adjusted_dl_bps = 0.0;
                    rule.adjusted_ul_bps = 0.0;
                }
            }
            _ => return,
        }
        self.apply_rule_to_row(&row.kind, rule);
    }

    fn edit_selected_limit(&mut self, direction: &str, text: &str) {
        let Some(row) = self.selected_row().cloned() else {
            return;
        };
        let Some(kibps) = parse_limit_input(text, self.speed_unit) else {
            return;
        };
        self.suppress_table_refresh_until = Some(Instant::now() + Duration::from_secs(2));
        let mut rule = row.rule.clone();
        match direction {
            "dl" => rule.download_kbps = kibps,
            "ul" => rule.upload_kbps = kibps,
            _ => return,
        }
        self.apply_rule_to_row(&row.kind, rule);
    }

    fn edit_row_limit(&mut self, row_index: i32, direction: &str, text: &str) {
        let Some(row) = self.rows.get(row_index as usize).cloned() else {
            return;
        };
        let Some(kibps) = parse_limit_input(text, self.speed_unit) else {
            return;
        };
        self.selected = Some(RowSelection::from(&row.kind));
        self.suppress_table_refresh_until = Some(Instant::now() + Duration::from_secs(2));
        let mut rule = row.rule.clone();
        match direction {
            "dl" => rule.download_kbps = kibps,
            "ul" => rule.upload_kbps = kibps,
            _ => return,
        }
        self.apply_rule_to_row(&row.kind, rule);
    }

    fn set_limit_editing(&mut self, editing: bool) {
        self.limit_editing = editing;
        if editing {
            self.suppress_table_refresh_until = None;
        }
    }

    fn edit_selected_loss(&mut self, direction: &str, text: &str) -> bool {
        let Some(row) = self.selected_row().cloned() else {
            return false;
        };
        let draft = match direction {
            "dl" => &mut self.loss_download_draft,
            "ul" => &mut self.loss_upload_draft,
            _ => return false,
        };
        let value = match parse_loss_percent(text) {
            Ok(value) => {
                *draft = None;
                value
            }
            Err(_) => {
                *draft = Some(text.to_string());
                return false;
            }
        };
        let mut rule = row.rule;
        match direction {
            "dl" => rule.download_loss_basis_points = value,
            "ul" => rule.upload_loss_basis_points = value,
            _ => unreachable!(),
        }
        self.apply_rule_to_row(&row.kind, rule);
        true
    }

    fn edit_selected_delay(&mut self, direction: &str, text: &str) -> bool {
        let Some(row) = self.selected_row().cloned() else {
            return false;
        };
        let draft = match direction {
            "dl" => &mut self.delay_download_draft,
            "ul" => &mut self.delay_upload_draft,
            _ => return false,
        };
        let value = match parse_delay_ms(text) {
            Ok(value) => {
                *draft = None;
                value
            }
            Err(_) => {
                *draft = Some(text.to_string());
                return false;
            }
        };
        let mut rule = row.rule;
        match direction {
            "dl" => rule.download_delay_ms = value,
            "ul" => rule.upload_delay_ms = value,
            _ => unreachable!(),
        }
        self.apply_rule_to_row(&row.kind, rule);
        true
    }

    fn tick(&mut self) -> bool {
        let snapshot = self.engine.snapshot_and_reset();
        let seen_pids: HashSet<u32> = snapshot.per_pid.keys().copied().collect();
        for (pid, (download, upload)) in snapshot.per_pid {
            self.dl_history
                .entry(pid)
                .or_insert_with(|| RollingAverage::new(5))
                .push(download as f64);
            self.ul_history
                .entry(pid)
                .or_insert_with(|| RollingAverage::new(5))
                .push(upload as f64);
        }

        let known_pids: Vec<u32> = self
            .dl_history
            .keys()
            .chain(self.ul_history.keys())
            .chain(self.rules.keys())
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        self.speeds.clear();
        for pid in known_pids {
            let dl = self
                .dl_history
                .entry(pid)
                .or_insert_with(|| RollingAverage::new(5));
            let ul = self
                .ul_history
                .entry(pid)
                .or_insert_with(|| RollingAverage::new(5));
            if !seen_pids.contains(&pid) {
                dl.push(0.0);
                ul.push(0.0);
            }
            self.speeds.insert(pid, (dl.average(), ul.average()));
        }

        self.global_dl_history
            .push(snapshot.global_download_bytes as f64);
        self.global_ul_history
            .push(snapshot.global_upload_bytes as f64);
        self.global_dl_bps = self.global_dl_history.average();
        self.global_ul_bps = self.global_ul_history.average();

        if snapshot.running {
            self.run_adaptive_feedback();
        }

        self.status = StatusMessage::Running {
            running: snapshot.running,
            download: format_speed(self.global_dl_bps, self.speed_unit),
            upload: format_speed(self.global_ul_bps, self.speed_unit),
            packets: snapshot.packets_processed,
            blocked: snapshot.packets_blocked,
            lost: snapshot.packets_loss_dropped,
            loss_percent: if snapshot.packets_loss_eligible == 0 {
                0.0
            } else {
                snapshot.packets_loss_dropped as f64 * 100.0 / snapshot.packets_loss_eligible as f64
            },
            limited: snapshot.packets_rate_dropped,
            delayed: snapshot.packets_delayed,
            queue_packets: snapshot.delay_queue_packets,
            queue_bytes: snapshot.delay_queue_bytes,
            queue_dropped: snapshot.packets_queue_dropped,
            send_failed: snapshot.packets_send_failed,
            shutdown_dropped: snapshot.packets_shutdown_dropped,
            block_error: snapshot.block_error,
            engine_error: snapshot.engine_error,
        };
        snapshot.running
    }

    fn can_refresh_table(&self) -> bool {
        !self.limit_editing
            && self
                .suppress_table_refresh_until
                .is_none_or(|deadline| Instant::now() >= deadline)
    }

    fn run_adaptive_feedback(&mut self) {
        if self.global_rule.adaptive {
            self.adjust_global(Direction::Download, self.global_dl_bps);
            self.adjust_global(Direction::Upload, self.global_ul_bps);
        }

        let pids: Vec<u32> = self.rules.keys().copied().collect();
        for pid in pids {
            let Some(rule) = self.rules.get(&pid) else {
                continue;
            };
            if !rule.adaptive {
                continue;
            }
            let (dl_bps, ul_bps) = self.speeds.get(&pid).copied().unwrap_or_default();
            self.adjust_pid(pid, Direction::Download, dl_bps);
            self.adjust_pid(pid, Direction::Upload, ul_bps);
        }
    }

    fn adjust_global(&mut self, direction: Direction, measured_bps: f64) {
        let Some(target) = self.global_rule.target_bps(direction) else {
            return;
        };
        let current = match direction {
            Direction::Download => self.global_rule.adjusted_dl_bps,
            Direction::Upload => self.global_rule.adjusted_ul_bps,
        };
        let adjusted = compute_adaptive_rate(current, measured_bps, target);
        match direction {
            Direction::Download => self.global_rule.adjusted_dl_bps = adjusted,
            Direction::Upload => self.global_rule.adjusted_ul_bps = adjusted,
        }
        self.engine
            .apply(EngineCommand::SetGlobalRule(self.global_rule.clone()));
    }

    fn adjust_pid(&mut self, pid: u32, direction: Direction, measured_bps: f64) {
        let Some(rule) = self.rules.get_mut(&pid) else {
            return;
        };
        let Some(target) = rule.target_bps(direction) else {
            return;
        };
        let current = match direction {
            Direction::Download => rule.adjusted_dl_bps,
            Direction::Upload => rule.adjusted_ul_bps,
        };
        let adjusted = compute_adaptive_rate(current, measured_bps, target);
        match direction {
            Direction::Download => rule.adjusted_dl_bps = adjusted,
            Direction::Upload => rule.adjusted_ul_bps = adjusted,
        }
        self.engine
            .apply(EngineCommand::UpdateRule(pid, rule.clone()));
    }

    fn apply_rule_to_row(&mut self, kind: &RowKind, rule: ProcessRule) {
        match kind {
            RowKind::Global => {
                self.global_rule = rule.clone();
                self.engine
                    .apply(EngineCommand::SetGlobalRule(runtime_rule(&rule)));
            }
            RowKind::Group {
                process_name, pids, ..
            } => {
                let key = process_name.to_lowercase();
                if rule.has_any_rule() {
                    self.name_rules.insert(key, rule.clone());
                } else {
                    self.name_rules.remove(&key);
                }
                for pid in pids {
                    self.update_pid_rule(*pid, rule.clone());
                }
                self.engine.apply(EngineCommand::UpdateRuleForPids(
                    pids.clone(),
                    runtime_rule(&rule),
                ));
            }
            RowKind::Child { pid, .. } => {
                self.update_pid_rule(*pid, rule.clone());
                self.engine
                    .apply(EngineCommand::UpdateRule(*pid, runtime_rule(&rule)));
            }
        }
    }

    fn push_all_rules(&self) {
        self.engine.apply(EngineCommand::SetGlobalRule(runtime_rule(
            &self.global_rule,
        )));
        for (pid, rule) in &self.rules {
            self.engine
                .apply(EngineCommand::UpdateRule(*pid, runtime_rule(rule)));
        }
    }

    fn update_pid_rule(&mut self, pid: u32, rule: ProcessRule) {
        if rule.has_any_rule() {
            self.rules.insert(pid, rule);
        } else {
            self.rules.remove(&pid);
        }
    }

    fn selected_row(&self) -> Option<&CoreProcessRow> {
        let selected = self.selected.as_ref()?;
        self.rows
            .iter()
            .find(|row| RowSelection::from(&row.kind) == *selected)
    }

    fn selected_row_index(&self) -> i32 {
        let Some(selected) = &self.selected else {
            return -1;
        };
        self.rows
            .iter()
            .position(|row| RowSelection::from(&row.kind) == *selected)
            .map(|index| index as i32)
            .unwrap_or(-1)
    }

    /// Locates the first process row for `query` without filtering the table.
    /// If `needs_row_rebuild` is set, call `rebuild_rows()` then `complete_process_search_locate()`.
    #[allow(dead_code)]
    fn locate_process_search(&mut self, query: impl AsRef<str>) -> ProcessSearchLocate {
        self.process_search = query.as_ref().to_string();
        let locate = locate_in_rows(&self.rows, &self.process_search, &self.computer_name);
        if locate.needs_row_rebuild {
            for group in process_search::groups_to_expand_for_search(
                &self.rows,
                self.process_search.trim(),
                &self.computer_name,
            ) {
                self.expanded.insert(group);
            }
            return ProcessSearchLocate {
                needs_row_rebuild: true,
                ..ProcessSearchLocate::default()
            };
        }

        if let Some(index) = locate.matched_row_index {
            self.selected = Some(RowSelection::from(&self.rows[index].kind));
        }
        locate
    }

    #[allow(dead_code)]
    fn complete_process_search_locate(&mut self) -> ProcessSearchLocate {
        let locate = locate_in_rows(&self.rows, &self.process_search, &self.computer_name);
        if let Some(index) = locate.matched_row_index {
            self.selected = Some(RowSelection::from(&self.rows[index].kind));
        }
        locate
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RowSelection {
    Global,
    Group(String),
    Child(u32),
}

impl From<&RowKind> for RowSelection {
    fn from(kind: &RowKind) -> Self {
        match kind {
            RowKind::Global => Self::Global,
            RowKind::Group { process_name, .. } => Self::Group(process_name.to_lowercase()),
            RowKind::Child { pid, .. } => Self::Child(*pid),
        }
    }
}

fn inherit_name_rules(
    rules: &mut HashMap<u32, ProcessRule>,
    name_rules: &HashMap<String, ProcessRule>,
    processes: &[flowbrake_core::ProcessInfo],
) -> Vec<(u32, ProcessRule)> {
    let mut added = Vec::new();
    for process in processes {
        let Some(rule) = name_rules.get(&process.name.to_lowercase()) else {
            continue;
        };
        if let std::collections::hash_map::Entry::Vacant(entry) = rules.entry(process.pid) {
            entry.insert(rule.clone());
            added.push((process.pid, rule.clone()));
        }
    }
    added
}

fn runtime_rule(rule: &ProcessRule) -> ProcessRule {
    let mut runtime = rule.clone();
    if !runtime.limit_download {
        runtime.download_kbps = 0;
        runtime.adjusted_dl_bps = 0.0;
    }
    if !runtime.limit_upload {
        runtime.upload_kbps = 0;
        runtime.adjusted_ul_bps = 0.0;
    }
    if runtime.target_bps(Direction::Download).is_none()
        && runtime.target_bps(Direction::Upload).is_none()
    {
        runtime.adaptive = false;
        runtime.adjusted_dl_bps = 0.0;
        runtime.adjusted_ul_bps = 0.0;
    }
    runtime
}

#[derive(Debug)]
enum StatusMessage {
    Stopped,
    Started,
    AdminRequired,
    SaveFailed(String),
    EngineFailed(String),
    DisconnectFailed(String),
    DisconnectPartial(usize),
    LanguageFailed(String),
    Running {
        running: bool,
        download: String,
        upload: String,
        packets: u64,
        blocked: u64,
        lost: u64,
        loss_percent: f64,
        limited: u64,
        delayed: u64,
        queue_packets: u64,
        queue_bytes: u64,
        queue_dropped: u64,
        send_failed: u64,
        shutdown_dropped: u64,
        block_error: Option<String>,
        engine_error: Option<String>,
    },
}
impl StatusMessage {
    fn text(&self, app: &AppWindow) -> SharedString {
        let tr = app.global::<Translations>();
        match self {
            Self::Stopped => tr.invoke_stopped(),
            Self::Started => tr.invoke_started(),
            Self::AdminRequired => tr.invoke_admin_required(),
            Self::SaveFailed(e) => tr.invoke_save_failed(e.as_str().into()),
            Self::EngineFailed(e) => tr.invoke_engine_failed(e.as_str().into()),
            Self::DisconnectFailed(e) => tr.invoke_disconnect_failed(e.as_str().into()),
            Self::DisconnectPartial(n) => tr.invoke_disconnect_partial(n.to_string().into()),
            Self::LanguageFailed(e) => tr.invoke_language_failed(e.as_str().into()),
            Self::Running {
                running,
                download,
                upload,
                packets,
                blocked,
                lost,
                loss_percent,
                limited,
                delayed,
                queue_packets,
                queue_bytes,
                queue_dropped,
                send_failed,
                shutdown_dropped,
                block_error,
                engine_error,
            } => {
                let mut text = tr
                    .invoke_running(
                        download.as_str().into(),
                        upload.as_str().into(),
                        packets.to_string().into(),
                        blocked.to_string().into(),
                        lost.to_string().into(),
                        format!("{loss_percent:.2}").into(),
                        limited.to_string().into(),
                        if *running {
                            tr.invoke_started()
                        } else {
                            tr.invoke_stopped()
                        },
                    )
                    .to_string();
                text.push_str("   |   ");
                text.push_str(
                    tr.invoke_delay_status(
                        delayed.to_string().into(),
                        queue_packets.to_string().into(),
                        queue_bytes.to_string().into(),
                        queue_dropped.to_string().into(),
                        send_failed.to_string().into(),
                        shutdown_dropped.to_string().into(),
                    )
                    .as_str(),
                );
                if let Some(error) = block_error {
                    text.push_str("   |   ");
                    text.push_str(tr.invoke_block_degraded(error.as_str().into()).as_str());
                }
                if let Some(error) = engine_error {
                    text.push_str("   |   ");
                    text.push_str(tr.invoke_engine_error(error.as_str().into()).as_str());
                }
                text.into()
            }
        }
    }
}
fn set_status(app: &AppWindow, state: &Rc<RefCell<AppState>>, status: StatusMessage) {
    app.set_status_text(status.text(app));
    state.borrow_mut().status = status;
}

struct TrayController {
    icon: TrayIcon,
    open_id: MenuId,
    exit_id: MenuId,
    open: MenuItem,
    exit: MenuItem,
}

enum TrayAction {
    Open,
    Exit,
}

impl TrayController {
    fn new(app: &AppWindow) -> Result<Self, Box<dyn std::error::Error>> {
        let menu = Menu::new();
        let tr = app.global::<Translations>();
        let open = MenuItem::new(tr.invoke_tray_open(), true, None);
        let exit = MenuItem::new(tr.invoke_tray_exit(), true, None);
        let separator = PredefinedMenuItem::separator();
        menu.append_items(&[&open, &separator, &exit])?;

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("FlowBrake")
            .with_icon(make_tray_icon()?)
            .build()?;
        icon.set_visible(false)?;

        Ok(Self {
            icon,
            open_id: open.id().clone(),
            exit_id: exit.id().clone(),
            open,
            exit,
        })
    }

    fn update_language(&self, app: &AppWindow) {
        let tr = app.global::<Translations>();
        self.open.set_text(tr.invoke_tray_open());
        self.exit.set_text(tr.invoke_tray_exit());
    }

    fn poll_action(&self) -> Option<TrayAction> {
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if matches!(event, TrayIconEvent::DoubleClick { .. }) {
                return Some(TrayAction::Open);
            }
        }

        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id() == &self.open_id {
                return Some(TrayAction::Open);
            }
            if event.id() == &self.exit_id {
                return Some(TrayAction::Exit);
            }
        }

        None
    }
}

fn make_tray_icon() -> Result<Icon, tray_icon::BadIcon> {
    let width = 32;
    let height = 32;
    let mut rgba = vec![0u8; width * height * 4];
    let center = 15.5f32;
    for y in 0..height {
        for x in 0..width {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let i = (y * width + x) * 4;
            if (dx * dx + dy * dy).sqrt() <= 15.0 {
                rgba[i] = 40;
                rgba[i + 1] = 90;
                rgba[i + 2] = 180;
                rgba[i + 3] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, width as u32, height as u32)
}

fn persist_settings(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let mut settings = state.borrow().to_settings();
    settings.capture_window(app.window());
    if let Err(err) = settings.save() {
        set_status(app, state, StatusMessage::SaveFailed(err));
    }
}

fn apply_language(app: &AppWindow, state: &Rc<RefCell<AppState>>, choice: i32) {
    if change_language(app, state, choice) {
        persist_settings(app, state);
    }
}

fn change_language(app: &AppWindow, state: &Rc<RefCell<AppState>>, choice: i32) -> bool {
    let preference = LanguagePreference::from_choice(choice);
    if let Err(error) = slint::select_bundled_translation(preference.resolve().slint_locale()) {
        app.set_language_choice(state.borrow().language.choice());
        set_status(app, state, StatusMessage::LanguageFailed(error.to_string()));
        return false;
    }
    {
        let mut state = state.borrow_mut();
        state.language = preference;
        if let Some(tray) = &state.tray {
            tray.update_language(app);
        }
        app.set_status_text(state.status.text(app));
    }
    app.set_language_choice(preference.choice());
    refresh_language_text(app, &state.borrow());
    true
}

// Update existing models and text properties without rebuilding controls or input drafts.
fn refresh_language_text(app: &AppWindow, state: &AppState) {
    let tr = app.global::<Translations>();
    if let Some(model) = &state.ui_rows {
        for (index, row) in state.rows.iter().enumerate() {
            if let Some(mut ui_row) = model.row_data(index) {
                ui_row.dl_limit = limit_display_text(
                    app,
                    row.rule.limit_download,
                    row.rule.download_kbps,
                    state.speed_unit,
                );
                ui_row.ul_limit = limit_display_text(
                    app,
                    row.rule.limit_upload,
                    row.rule.upload_kbps,
                    state.speed_unit,
                );
                model.set_row_data(index, ui_row);
            }
        }
    }
    update_summary_panel(app, state);
    if let Some(row) = state.selected_row() {
        let global = matches!(row.kind, RowKind::Global);
        app.set_selected_kind(match &row.kind {
            RowKind::Global => tr.invoke_computer(),
            RowKind::Group { pids, .. } if pids.len() > 1 => tr.invoke_process_group(),
            RowKind::Group { .. } => tr.invoke_process(),
            RowKind::Child { .. } => tr.invoke_process_instance(),
        });
        if global {
            app.set_selected_pids(tr.invoke_all_traffic());
        }
        app.set_selected_loss_hint(if global {
            tr.invoke_loss_off_hint()
        } else {
            tr.invoke_loss_inherit_hint()
        });
        app.set_selected_dl_loss_error(if state.loss_download_draft.is_some() {
            tr.invoke_loss_invalid()
        } else {
            "".into()
        });
        app.set_selected_ul_loss_error(if state.loss_upload_draft.is_some() {
            tr.invoke_loss_invalid()
        } else {
            "".into()
        });
        app.set_selected_dl_delay_error(if state.delay_download_draft.is_some() {
            tr.invoke_delay_invalid()
        } else {
            "".into()
        });
        app.set_selected_ul_delay_error(if state.delay_upload_draft.is_some() {
            tr.invoke_delay_invalid()
        } else {
            "".into()
        });
        if !global {
            let count = state
                .connections_for_pids(&pids_for_row_kind(&row.kind))
                .len();
            app.set_selected_connections_summary(connections_summary(app, count).into());
            app.set_selected_connections_tab_title(connections_tab_title(app, count).into());
        } else {
            app.set_selected_connections_tab_title(tr.invoke_connections());
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let settings = AppSettings::load();
    let language = settings.language.resolve();
    if !is_elevated() {
        match relaunch_as_admin(&[]) {
            RelaunchResult::Started => return Ok(()),
            RelaunchResult::Cancelled => {
                show_admin_required_message(i18n::bootstrap_admin_required(language));
                return Ok(());
            }
            RelaunchResult::Failed(err) => {
                show_admin_required_message(&i18n::bootstrap_admin_failed(
                    language,
                    &err.to_string(),
                ));
                return Ok(());
            }
        }
    }

    let window_settings = settings.clone();
    let app = AppWindow::new()?;
    if let Err(error) = slint::select_bundled_translation(language.slint_locale()) {
        eprintln!("Could not select translation: {error}");
        let _ = slint::select_bundled_translation("");
    }
    app.set_language_choice(settings.language.choice());
    app.set_window_maximized(window_settings.window_maximized);
    app.set_speed_unit_bits(settings.speed_unit_bits);
    app.set_ipv6_enabled(settings.ipv6_enabled);
    let state = Rc::new(RefCell::new(AppState::new(settings)));
    state.borrow_mut().tray = TrayController::new(&app).ok();

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_language_changed(move |choice| {
            let app = app_weak.unwrap();
            apply_language(&app, &state, choice);
        });
    }

    render_rows(&app, &state);

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.window().on_close_requested(move || {
            let app = app_weak.unwrap();
            handle_close_request(&app, &state)
        });
    }

    {
        let app_weak = app.as_weak();
        app.on_window_drag_requested(move || {
            let app = app_weak.unwrap();
            let _ = window_chrome::start_window_drag(app.window());
        });
    }

    {
        let app_weak = app.as_weak();
        app.on_window_minimize_requested(move || {
            let app = app_weak.unwrap();
            app.window().set_minimized(true);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_window_maximize_toggle_requested(move || {
            let app = app_weak.unwrap();
            let next_maximized = !app.window().is_maximized();
            app.window().set_maximized(next_maximized);
            app.set_window_maximized(next_maximized);
            let mut appearance_sync = window_chrome::WindowAppearanceSync::new(app.window());
            let _ = appearance_sync.force(app.window());
            {
                let mut settings = state.borrow().to_settings();
                settings.window_maximized = next_maximized;
                if !next_maximized {
                    settings.capture_window(app.window());
                }
                if let Err(err) = settings.save() {
                    set_status(&app, &state, StatusMessage::SaveFailed(err));
                }
            }
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_window_close_requested(move || {
            let app = app_weak.unwrap();
            let _ = handle_close_request(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_row_clicked(move |row_index| {
            let app = app_weak.unwrap();
            let is_double_click = state.borrow_mut().handle_row_click(row_index);
            if is_double_click {
                state.borrow_mut().toggle_row_expanded(row_index);
                persist_settings(&app, &state);
            } else {
                let previous = state.borrow().selected.clone();
                state.borrow_mut().select_row(row_index);
                if previous != state.borrow().selected {
                    app.set_selected_sidebar_tab(0);
                }
            }
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_selection_cleared(move || {
            let app = app_weak.unwrap();
            state.borrow_mut().clear_selection();
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_bool_rule_edited(move |row_index, field, value| {
            let app = app_weak.unwrap();
            state
                .borrow_mut()
                .edit_bool(row_index, field.as_str(), value);
            render_rows(&app, &state);
            persist_settings(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_row_limit_submitted(move |row_index, direction, value| {
            let app = app_weak.unwrap();
            state
                .borrow_mut()
                .edit_row_limit(row_index, direction.as_str(), value.as_str());
            render_rows(&app, &state);
            persist_settings(&app, &state);
        });
    }

    {
        let state = Rc::clone(&state);
        app.on_row_limit_focus_changed(move |focused| {
            state.borrow_mut().set_limit_editing(focused);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_selected_limit_submitted(move |direction, value| {
            let app = app_weak.unwrap();
            state
                .borrow_mut()
                .edit_selected_limit(direction.as_str(), value.as_str());
            update_selected_sidebar(&app, &state);
            persist_settings(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_selected_loss_submitted(move |direction, value| {
            let app = app_weak.unwrap();
            let applied = state
                .borrow_mut()
                .edit_selected_loss(direction.as_str(), value.as_str());
            if applied {
                render_rows(&app, &state);
                persist_settings(&app, &state);
            } else {
                update_selected_sidebar(&app, &state);
            }
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_selected_delay_submitted(move |direction, value| {
            let app = app_weak.unwrap();
            let applied = state
                .borrow_mut()
                .edit_selected_delay(direction.as_str(), value.as_str());
            if applied {
                render_rows(&app, &state);
                persist_settings(&app, &state);
            } else {
                update_selected_sidebar(&app, &state);
            }
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_selected_bool_rule_edited(move |field, value| {
            let app = app_weak.unwrap();
            state.borrow_mut().edit_selected_bool(field.as_str(), value);
            render_rows(&app, &state);
            persist_settings(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_sidebar_focus_changed(move |focused| {
            let app = app_weak.unwrap();
            state.borrow_mut().set_limit_editing(focused);
            if !focused {
                render_rows(&app, &state);
            }
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_speed_unit_bits_changed(move |bits_mode| {
            let app = app_weak.unwrap();
            state
                .borrow_mut()
                .set_speed_unit(SpeedUnit::from_bits_mode(bits_mode));
            app.set_speed_unit_bits(bits_mode);
            persist_settings(&app, &state);
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_ipv6_enabled_changed(move |enabled| {
            let app = app_weak.unwrap();
            let needs_restart = {
                let mut state_ref = state.borrow_mut();
                if !state_ref.set_ipv6_enabled(enabled) {
                    return;
                }
                state_ref.engine.is_running()
            };
            if needs_restart {
                let result = state.borrow_mut().restart_engine();
                if let Err(err) = result {
                    set_status(&app, &state, StatusMessage::EngineFailed(err));
                }
            }
            app.set_ipv6_enabled(enabled);
            app.set_running(state.borrow().engine.is_running());
            persist_settings(&app, &state);
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_connection_disconnect_requested(move |key| {
            let app = app_weak.unwrap();
            if let Some(conn_key) = TcpConnectionKey::decode_id(key.as_str())
                && let Err(error) = close_tcp_connection(&conn_key)
            {
                set_status(
                    &app,
                    &state,
                    StatusMessage::DisconnectFailed(error.to_string()),
                );
            }
            state.borrow_mut().refresh_connections();
            update_selected_sidebar(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_disconnect_all_tcp_requested(move || {
            let app = app_weak.unwrap();
            let (pids, connections) = {
                let state_ref = state.borrow();
                let pids = state_ref
                    .selected_row()
                    .map(|row| pids_for_row_kind(&row.kind))
                    .unwrap_or_default();
                (pids, state_ref.all_connections.clone())
            };
            if !pids.is_empty() {
                let expected = connections
                    .iter()
                    .filter(|connection| {
                        pids.contains(&connection.pid)
                            && connection.state.is_disconnectable()
                            && !connection.key.ipv6
                    })
                    .count();
                let closed = close_tcp_connections_for_pids(&pids, &connections);
                let failed = expected.saturating_sub(closed);
                if failed > 0 {
                    set_status(&app, &state, StatusMessage::DisconnectPartial(failed));
                }
            }
            state.borrow_mut().refresh_connections();
            update_selected_sidebar(&app, &state);
        });
    }

    let init_window_timer = Timer::default();
    {
        let app_weak = app.as_weak();
        let mut appearance_sync = window_chrome::WindowAppearanceSync::new(app.window());
        init_window_timer.start(TimerMode::SingleShot, Duration::from_millis(0), move || {
            let Some(app) = app_weak.upgrade() else {
                return;
            };
            window_settings.apply_window(app.window());
            app.set_window_maximized(app.window().is_maximized());
            let _ = appearance_sync.force(app.window());
        });
    }

    let init_window_appearance_timer = Timer::default();
    {
        let app_weak = app.as_weak();
        init_window_appearance_timer.start(
            TimerMode::SingleShot,
            Duration::from_millis(100),
            move || {
                let Some(app) = app_weak.upgrade() else {
                    return;
                };
                let mut appearance_sync = window_chrome::WindowAppearanceSync::new(app.window());
                let _ = appearance_sync.force(app.window());
            },
        );
    }

    let appearance_timer = Timer::default();
    {
        let app_weak = app.as_weak();
        let mut appearance_sync = window_chrome::WindowAppearanceSync::new(app.window());
        appearance_timer.start(TimerMode::Repeated, Duration::from_millis(250), move || {
            let Some(app) = app_weak.upgrade() else {
                return;
            };
            if app.window().is_minimized() {
                return;
            }
            let _ = appearance_sync.sync_if_changed(app.window());
        });
    }

    let auto_start_timer = Timer::default();
    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        auto_start_timer.start(TimerMode::SingleShot, Duration::from_millis(0), move || {
            let Some(app) = app_weak.upgrade() else {
                return;
            };
            apply_engine_start(&app, &state);
        });
    }

    let timer = Timer::default();
    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        timer.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            let app = app_weak.unwrap();
            let Ok(mut state_ref) = state.try_borrow_mut() else {
                return;
            };
            let running = state_ref.tick();
            app.set_window_maximized(app.window().is_maximized());
            app.set_running(running);
            app.set_status_text(state_ref.status.text(&app));
            let refresh_table = state_ref.can_refresh_table();
            drop(state_ref);
            if refresh_table {
                refresh_table_on_tick(&app, &state);
            }
        });
    }

    let tray_timer = Timer::default();
    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        tray_timer.start(TimerMode::Repeated, Duration::from_millis(200), move || {
            let app = app_weak.unwrap();
            let action = state.try_borrow().ok().and_then(|state_ref| {
                state_ref
                    .tray
                    .as_ref()
                    .and_then(TrayController::poll_action)
            });
            match action {
                Some(TrayAction::Open) => {
                    if let Ok(state_ref) = state.try_borrow() {
                        state_ref.set_tray_visible(false);
                    }
                    let _ = app.show();
                    app.set_window_maximized(app.window().is_maximized());
                    let mut appearance_sync =
                        window_chrome::WindowAppearanceSync::new(app.window());
                    let _ = appearance_sync.force(app.window());
                }
                Some(TrayAction::Exit) => {
                    persist_settings(&app, &state);
                    apply_engine_stop(&app, &state);
                    if let Ok(mut state_ref) = state.try_borrow_mut() {
                        state_ref.full_exit();
                    }
                    let _ = app.hide();
                    slint::quit_event_loop().ok();
                }
                None => {}
            }
        });
    }

    app.run()
}

fn apply_engine_start(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    if !is_elevated() {
        app.set_running(false);
        set_status(app, state, StatusMessage::AdminRequired);
        return;
    }

    let result = state.borrow_mut().start();
    match result {
        Ok(()) => {
            app.set_running(true);
            set_status(app, state, StatusMessage::Started);
        }
        Err(err) => {
            app.set_running(false);
            set_status(app, state, StatusMessage::EngineFailed(err));
        }
    }
}

fn apply_engine_stop(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    state.borrow_mut().stop();
    state.borrow().set_tray_visible(false);
    app.set_running(false);
    set_status(app, state, StatusMessage::Stopped);
    render_rows(app, state);
}

fn handle_close_request(app: &AppWindow, state: &Rc<RefCell<AppState>>) -> CloseRequestResponse {
    persist_settings(app, state);
    if state.borrow().engine.is_running() {
        state.borrow_mut().set_tray_visible(true);
        let _ = app.hide();
        CloseRequestResponse::HideWindow
    } else {
        apply_engine_stop(app, state);
        state.borrow_mut().full_exit();
        let _ = app.hide();
        slint::quit_event_loop().ok();
        CloseRequestResponse::HideWindow
    }
}

fn sum_group_speed(pids: &[u32], speeds: &HashMap<u32, (f64, f64)>, direction: Direction) -> f64 {
    pids.iter()
        .map(|pid| {
            let (dl_bps, ul_bps) = speeds.get(pid).copied().unwrap_or_default();
            match direction {
                Direction::Download => dl_bps,
                Direction::Upload => ul_bps,
            }
        })
        .sum()
}

fn refresh_table_on_tick(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let mut state_ref = state.borrow_mut();
    state_ref.refresh_connections();
    let processes = state_ref.fetch_processes();
    state_ref.apply_name_rules_from(&processes);
    let fingerprint = TableFingerprint::from_processes(&processes, &state_ref.expanded);

    if fingerprint != state_ref.table_fingerprint {
        state_ref.table_fingerprint = fingerprint;
        state_ref.rebuild_rows_from(&processes);
        publish_full_table(app, &mut state_ref);
    } else {
        state_ref.refresh_row_speeds();
        publish_speed_updates(app, &state_ref);
    }

    update_summary_panel(app, &state_ref);
    drop(state_ref);
    update_selected_sidebar(app, state);
}

fn publish_full_table(app: &AppWindow, state: &mut AppState) {
    let speed_unit = state.speed_unit;
    let rows: Vec<ProcessRow> = state
        .rows
        .iter()
        .map(|row| {
            to_ui_row(
                app,
                row,
                speed_unit,
                &mut state.icon_cache,
                &state.computer_name,
            )
        })
        .collect();
    let model = StdRc::new(VecModel::from(rows));
    app.set_rows(ModelRc::from(model.clone()));
    state.ui_rows = Some(model);
    app.set_selected_row(state.selected_row_index());
}

fn publish_speed_updates(app: &AppWindow, state: &AppState) {
    let Some(model) = &state.ui_rows else {
        return;
    };

    if model.row_count() != state.rows.len() {
        return;
    }

    let unit = state.speed_unit;
    for (index, core_row) in state.rows.iter().enumerate() {
        let Some(mut ui_row) = model.row_data(index) else {
            continue;
        };
        ui_row.dl_speed = SharedString::from(format_speed(core_row.dl_bps, unit));
        ui_row.ul_speed = SharedString::from(format_speed(core_row.ul_bps, unit));
        model.set_row_data(index, ui_row);
    }
    app.set_selected_row(state.selected_row_index());
}

fn render_rows(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let mut state_ref = state.borrow_mut();
    state_ref.refresh_connections();
    state_ref.rebuild_rows();
    publish_full_table(app, &mut state_ref);
    update_summary_panel(app, &state_ref);
    drop(state_ref);
    update_selected_sidebar(app, state);
}

fn update_summary_panel(app: &AppWindow, state: &AppState) {
    let process_limits = state
        .rules
        .values()
        .filter(|rule| {
            rule.target_bps(Direction::Download).is_some()
                || rule.target_bps(Direction::Upload).is_some()
        })
        .count();
    let blocked = state.rules.values().filter(|rule| rule.block_all).count()
        + usize::from(state.global_rule.block_all);
    let adaptive = state.rules.values().filter(|rule| rule.adaptive).count()
        + usize::from(state.global_rule.adaptive);

    app.set_summary_throughput(app.global::<Translations>().invoke_speed_summary(
        format_speed(state.global_dl_bps, state.speed_unit).into(),
        format_speed(state.global_ul_bps, state.speed_unit).into(),
    ));
    app.set_summary_global_limit(
        global_limit_summary(app, &state.global_rule, state.speed_unit).into(),
    );
    app.set_summary_process_limits(process_limits.to_string().into());
    app.set_summary_blocked(blocked.to_string().into());
    app.set_summary_adaptive(adaptive.to_string().into());
}

fn update_selected_sidebar(app: &AppWindow, state_rc: &Rc<RefCell<AppState>>) {
    let mut state = state_rc.borrow_mut();
    let selection_changed = state.loss_selection != state.selected;
    if selection_changed {
        state.loss_selection = state.selected.clone();
        state.loss_download_draft = None;
        state.loss_upload_draft = None;
        state.delay_download_draft = None;
        state.delay_upload_draft = None;
    }
    let Some(row) = state.selected_row() else {
        drop(state);
        app.set_sidebar_open(false);
        app.set_selected_title("".into());
        app.set_selected_kind("".into());
        app.set_selected_pid("".into());
        app.set_selected_pids("".into());
        app.set_selected_dl_speed("".into());
        app.set_selected_ul_speed("".into());
        app.set_selected_limit_dl(false);
        app.set_selected_dl_limit("".into());
        app.set_selected_limit_ul(false);
        app.set_selected_ul_limit("".into());
        app.set_selected_dl_loss("".into());
        app.set_selected_ul_loss("".into());
        app.set_selected_dl_loss_error("".into());
        app.set_selected_ul_loss_error("".into());
        app.set_selected_loss_hint("".into());
        app.set_selected_dl_delay("".into());
        app.set_selected_ul_delay("".into());
        app.set_selected_dl_delay_error("".into());
        app.set_selected_ul_delay_error("".into());
        app.set_selected_block(false);
        app.set_selected_adaptive(false);
        clear_connections_sidebar(app);
        return;
    };

    let show_connections = !matches!(row.kind, RowKind::Global);

    let (title, kind, pid, pids) = match &row.kind {
        RowKind::Global => (
            state.computer_name.clone(),
            app.global::<Translations>().invoke_computer().to_string(),
            "-".to_string(),
            app.global::<Translations>()
                .invoke_all_traffic()
                .to_string(),
        ),
        RowKind::Group {
            display_name, pids, ..
        } => (
            display_name.clone(),
            if pids.len() > 1 {
                app.global::<Translations>()
                    .invoke_process_group()
                    .to_string()
            } else {
                app.global::<Translations>().invoke_process().to_string()
            },
            if pids.len() == 1 {
                pids[0].to_string()
            } else {
                "-".to_string()
            },
            join_pids(pids),
        ),
        RowKind::Child {
            display_name, pid, ..
        } => (
            display_name.clone(),
            app.global::<Translations>()
                .invoke_process_instance()
                .to_string(),
            pid.to_string(),
            pid.to_string(),
        ),
    };

    app.set_sidebar_open(true);
    app.set_selected_title(title.into());
    app.set_selected_kind(kind.into());
    app.set_selected_pid(pid.into());
    app.set_selected_pids(pids.into());
    app.set_selected_dl_speed(format_speed(row.dl_bps, state.speed_unit).into());
    app.set_selected_ul_speed(format_speed(row.ul_bps, state.speed_unit).into());
    app.set_selected_limit_dl(row.rule.limit_download);
    if !state.limit_editing || selection_changed {
        app.set_selected_dl_limit(limit_text(row.rule.download_kbps, state.speed_unit));
        app.set_selected_ul_limit(limit_text(row.rule.upload_kbps, state.speed_unit));
    }
    app.set_selected_limit_ul(row.rule.limit_upload);
    if !state.limit_editing || selection_changed {
        let download = state
            .loss_download_draft
            .clone()
            .unwrap_or_else(|| format_loss_percent(row.rule.download_loss_basis_points));
        let upload = state
            .loss_upload_draft
            .clone()
            .unwrap_or_else(|| format_loss_percent(row.rule.upload_loss_basis_points));
        app.set_selected_dl_loss(download.into());
        app.set_selected_ul_loss(upload.into());
        app.set_selected_dl_delay(
            state
                .delay_download_draft
                .clone()
                .unwrap_or_else(|| format_delay_ms(row.rule.download_delay_ms))
                .into(),
        );
        app.set_selected_ul_delay(
            state
                .delay_upload_draft
                .clone()
                .unwrap_or_else(|| format_delay_ms(row.rule.upload_delay_ms))
                .into(),
        );
    }
    let tr = app.global::<Translations>();
    app.set_selected_dl_loss_error(if state.loss_download_draft.is_some() {
        tr.invoke_loss_invalid()
    } else {
        "".into()
    });
    app.set_selected_ul_loss_error(if state.loss_upload_draft.is_some() {
        tr.invoke_loss_invalid()
    } else {
        "".into()
    });
    app.set_selected_dl_delay_error(if state.delay_download_draft.is_some() {
        tr.invoke_delay_invalid()
    } else {
        "".into()
    });
    app.set_selected_ul_delay_error(if state.delay_upload_draft.is_some() {
        tr.invoke_delay_invalid()
    } else {
        "".into()
    });
    app.set_selected_loss_hint(if show_connections {
        tr.invoke_loss_inherit_hint()
    } else {
        tr.invoke_loss_off_hint()
    });
    app.set_selected_block(row.rule.block_all);
    app.set_selected_adaptive(row.rule.adaptive);

    if show_connections {
        let pids = pids_for_row_kind(&row.kind);
        let connections = state.connections_for_pids(&pids);
        let total = connections.len();
        let visible = connections
            .iter()
            .take(MAX_VISIBLE_CONNECTIONS)
            .map(|connection| to_ui_connection_row(connection, pids.len() > 1))
            .collect::<Vec<_>>();
        let disconnectable = connections
            .iter()
            .any(|connection| connection.state.is_disconnectable() && !connection.key.ipv6);
        app.set_selected_show_connections(true);
        app.set_selected_connections_summary(connections_summary(app, total).into());
        app.set_selected_connections_tab_title(connections_tab_title(app, total).into());
        app.set_selected_can_disconnect_all(disconnectable);
        app.set_selected_connections(ModelRc::new(VecModel::from(visible)));
    } else {
        clear_connections_sidebar(app);
    }
}

fn clear_connections_sidebar(app: &AppWindow) {
    app.set_selected_show_connections(false);
    app.set_selected_connections_summary("".into());
    app.set_selected_connections_tab_title(app.global::<Translations>().invoke_connections());
    app.set_selected_sidebar_tab(0);
    app.set_selected_can_disconnect_all(false);
    app.set_selected_connections(ModelRc::new(VecModel::from(Vec::<ConnectionRow>::new())));
}

fn connections_tab_title(app: &AppWindow, total: usize) -> String {
    let tr = app.global::<Translations>();
    if total == 0 {
        tr.invoke_connections()
    } else {
        tr.invoke_connections_title(total.to_string().into())
    }
    .to_string()
}

fn pids_for_row_kind(kind: &RowKind) -> Vec<u32> {
    match kind {
        RowKind::Global => Vec::new(),
        RowKind::Group { pids, .. } => pids.clone(),
        RowKind::Child { pid, .. } => vec![*pid],
    }
}

fn connections_summary(app: &AppWindow, total: usize) -> String {
    let tr = app.global::<Translations>();
    if total == 0 {
        return tr.invoke_no_connections().to_string();
    }
    if total > MAX_VISIBLE_CONNECTIONS {
        return tr
            .invoke_connections_shown(
                MAX_VISIBLE_CONNECTIONS.to_string().into(),
                total.to_string().into(),
            )
            .to_string();
    }
    tr.invoke_connection_count(total as i32).to_string()
}

fn to_ui_connection_row(connection: &TcpConnection, show_pid: bool) -> ConnectionRow {
    let detail = if show_pid {
        format!("PID {} · {}", connection.pid, connection.state.label())
    } else {
        connection.state.label().to_string()
    };
    ConnectionRow {
        key: connection.key.encode_id().into(),
        label: connection.display_remote().into(),
        detail: detail.into(),
        disconnectable: connection.state.is_disconnectable() && !connection.key.ipv6,
    }
}

fn join_pids(pids: &[u32]) -> String {
    if pids.is_empty() {
        return "-".to_string();
    }
    pids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn icon_for_exe_path(icon_cache: &mut HashMap<String, Image>, exe_path: &str) -> Image {
    if exe_path.is_empty() {
        return Image::default();
    }

    let key = exe_path.to_ascii_lowercase();
    if let Some(icon) = icon_cache.get(&key) {
        return icon.clone();
    }

    let image = load_process_icon(exe_path);
    icon_cache.insert(key, image.clone());
    image
}

fn to_ui_row(
    app: &AppWindow,
    row: &CoreProcessRow,
    unit: SpeedUnit,
    icon_cache: &mut HashMap<String, Image>,
    computer_name: &str,
) -> ProcessRow {
    let (
        process,
        pid,
        is_global,
        is_group,
        depth,
        expandable,
        expanded,
        show_icon,
        use_computer_icon,
        exe_path,
    ) = match &row.kind {
        RowKind::Global => (
            SharedString::from(computer_name),
            SharedString::from(""),
            true,
            false,
            0,
            false,
            false,
            false,
            true,
            "",
        ),
        RowKind::Group {
            display_name,
            exe_path,
            pids,
            expanded,
            ..
        } => {
            let label = if pids.len() > 1 {
                format!("{display_name} ({})", pids.len())
            } else {
                display_name.clone()
            };
            (
                SharedString::from(label),
                SharedString::from(if pids.len() == 1 {
                    pids[0].to_string()
                } else {
                    String::new()
                }),
                false,
                true,
                0,
                pids.len() > 1,
                *expanded,
                true,
                false,
                exe_path.as_str(),
            )
        }
        RowKind::Child { pid, exe_path, .. } => (
            SharedString::from(format!("PID {pid}")),
            SharedString::from(pid.to_string()),
            false,
            false,
            1,
            false,
            false,
            true,
            false,
            exe_path.as_str(),
        ),
    };

    ProcessRow {
        process,
        pid,
        icon: icon_for_exe_path(icon_cache, exe_path),
        show_icon,
        use_computer_icon,
        expandable,
        expanded,
        dl_speed: SharedString::from(format_speed(row.dl_bps, unit)),
        ul_speed: SharedString::from(format_speed(row.ul_bps, unit)),
        limit_dl: row.rule.limit_download,
        dl_limit: limit_display_text(app, row.rule.limit_download, row.rule.download_kbps, unit),
        dl_limit_edit: limit_text(row.rule.download_kbps, unit),
        limit_ul: row.rule.limit_upload,
        ul_limit: limit_display_text(app, row.rule.limit_upload, row.rule.upload_kbps, unit),
        ul_limit_edit: limit_text(row.rule.upload_kbps, unit),
        block: row.rule.block_all,
        adaptive: row.rule.adaptive,
        is_global,
        is_group,
        depth,
    }
}

#[cfg(target_os = "windows")]
fn load_process_icon(exe_path: &str) -> Image {
    let path = std::path::Path::new(exe_path);
    let Some(icon) = process_icon(path) else {
        return Image::default();
    };
    let buffer =
        SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&icon.rgba, icon.width, icon.height);
    Image::from_rgba8(buffer)
}

#[cfg(not(target_os = "windows"))]
fn load_process_icon(_exe_path: &str) -> Image {
    Image::default()
}

fn limit_text(kibps: u32, unit: SpeedUnit) -> SharedString {
    if kibps > 0 {
        SharedString::from(format_limit_kibps(kibps, unit))
    } else {
        SharedString::from("")
    }
}

fn limit_display_text(app: &AppWindow, enabled: bool, kibps: u32, unit: SpeedUnit) -> SharedString {
    if enabled && kibps > 0 {
        SharedString::from(format_limit_kibps(kibps, unit))
    } else {
        app.global::<Translations>().invoke_off()
    }
}

fn global_limit_summary(app: &AppWindow, rule: &GlobalRule, unit: SpeedUnit) -> String {
    app.global::<Translations>()
        .invoke_speed_summary(
            limit_summary_text(app, rule.limit_download, rule.download_kbps, unit).into(),
            limit_summary_text(app, rule.limit_upload, rule.upload_kbps, unit).into(),
        )
        .to_string()
}
fn limit_summary_text(app: &AppWindow, enabled: bool, kibps: u32, unit: SpeedUnit) -> String {
    if enabled && kibps > 0 {
        format_limit_summary(kibps, unit)
    } else {
        app.global::<Translations>().invoke_off().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_switch_retranslates_existing_state_and_preserves_drafts() {
        use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
        struct TestPlatform(Rc<MinimalSoftwareWindow>);
        impl slint::platform::Platform for TestPlatform {
            fn create_window_adapter(
                &self,
            ) -> Result<Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError> {
                Ok(self.0.clone())
            }
        }
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(TestPlatform(window.clone()))).unwrap();
        let app = AppWindow::new().unwrap();
        slint::select_bundled_translation("").unwrap();
        let settings = AppSettings {
            language: LanguagePreference::English,
            global_rule: ProcessRule {
                block_all: true,
                download_loss_basis_points: Some(1250),
                download_delay_ms: Some(100),
                upload_delay_ms: Some(0),
                ..Default::default()
            },
            expanded: HashSet::from(["example.exe".to_string()]),
            ..Default::default()
        };
        let state = Rc::new(RefCell::new(AppState::new(settings)));
        {
            let mut state = state.borrow_mut();
            state.rows = vec![CoreProcessRow::global(state.global_rule.clone())];
            state.selected = Some(RowSelection::Global);
            state.loss_selection = state.selected.clone();
            state.loss_download_draft = Some("101.25".to_string());
            state.delay_download_draft = Some("5001".to_string());
            state.delay_upload_draft = Some("-1".to_string());
            state.limit_editing = true;
            state.process_search = "example.exe".to_string();
            state.status = StatusMessage::SaveFailed("error 5".to_string());
            publish_full_table(&app, &mut state);
        }
        update_selected_sidebar(&app, &state);
        app.set_selected_dl_limit("123.45".into());
        app.set_selected_dl_loss("101.25".into());
        app.set_selected_dl_delay("5001".into());
        app.set_selected_ul_delay("-1".into());
        app.set_selected_sidebar_tab(0);
        app.set_running(true);
        let model = state.borrow().ui_rows.clone().unwrap();
        let original_rule = state.borrow().global_rule.clone();
        let tr = app.global::<Translations>();
        assert_eq!(connections_summary(&app, 1), "1 TCP connection");
        assert_eq!(connections_summary(&app, 2), "2 TCP connections");
        assert!(change_language(&app, &state, 1));
        assert_eq!(tr.invoke_off(), "关闭");
        assert_eq!(connections_summary(&app, 1), "1 个 TCP 连接");
        assert_eq!(connections_summary(&app, 2), "2 个 TCP 连接");
        assert_eq!(
            connections_summary(&app, 0),
            tr.invoke_no_connections().to_string()
        );
        assert_eq!(
            connections_summary(&app, 201),
            tr.invoke_connections_shown("200".into(), "201".into())
                .to_string()
        );
        assert_eq!(
            app.get_status_text(),
            tr.invoke_save_failed("error 5".into())
        );
        assert_eq!(app.get_selected_kind(), tr.invoke_computer());
        assert_eq!(app.get_selected_dl_loss_error(), tr.invoke_loss_invalid());
        assert_eq!(app.get_selected_dl_delay_error(), tr.invoke_delay_invalid());
        assert_eq!(app.get_selected_ul_delay_error(), tr.invoke_delay_invalid());
        assert_eq!(model.row_data(0).unwrap().dl_limit, tr.invoke_off());
        assert!(change_language(&app, &state, 2));
        assert_eq!(tr.invoke_off(), "Off");
        assert_eq!(app.get_status_text(), "Failed to save settings: error 5");
        assert_eq!(app.get_selected_kind(), "Computer");
        assert_eq!(app.get_selected_dl_limit(), "123.45");
        assert_eq!(app.get_selected_dl_loss(), "101.25");
        assert_eq!(app.get_selected_dl_delay(), "5001");
        assert_eq!(app.get_selected_ul_delay(), "-1");
        assert_eq!(app.get_selected_sidebar_tab(), 0);
        assert!(app.get_running());
        let current = state.borrow();
        assert_eq!(current.global_rule, original_rule);
        assert_eq!(current.selected, Some(RowSelection::Global));
        assert_eq!(current.loss_download_draft.as_deref(), Some("101.25"));
        assert_eq!(current.delay_download_draft.as_deref(), Some("5001"));
        assert_eq!(current.delay_upload_draft.as_deref(), Some("-1"));
        assert_eq!(current.process_search, "example.exe");
        assert!(current.expanded.contains("example.exe"));
        assert!(!current.engine.is_running());
        assert!(Rc::ptr_eq(&model, current.ui_rows.as_ref().unwrap()));
        drop(current);

        let status = StatusMessage::Running {
            running: false,
            download: "1 Kb/s".into(),
            upload: "2 Kb/s".into(),
            packets: 101,
            blocked: 102,
            lost: 103,
            loss_percent: 10.0,
            limited: 104,
            delayed: 105,
            queue_packets: 106,
            queue_bytes: 107,
            queue_dropped: 108,
            send_failed: 109,
            shutdown_dropped: 110,
            block_error: Some("block error 5".into()),
            engine_error: Some("send error 6".into()),
        };
        for choice in [1, 2] {
            assert!(change_language(&app, &state, choice));
            let text = status.text(&app);
            for value in 101..=110 {
                assert!(text.contains(&value.to_string()), "{text}");
            }
            assert!(text.contains(tr.invoke_stopped().as_str()));
            assert!(text.contains(tr.invoke_block_degraded("block error 5".into()).as_str()));
            assert!(text.contains(tr.invoke_engine_error("send error 6".into()).as_str()));
        }
        state.borrow_mut().status = status;
        state.borrow_mut().limit_editing = false;

        if let Ok(output) = std::env::var("FLOWBRAKE_I18N_PREVIEW_DIR") {
            std::fs::create_dir_all(&output).unwrap();
            app.set_settings_open(false);
            app.show().unwrap();
            let render_preview = |filename: &str| {
                let size = window.size();
                let mut pixels =
                    vec![slint::Rgb8Pixel::default(); (size.width * size.height) as usize];
                window.request_redraw();
                assert!(window.draw_if_needed(|renderer| {
                    renderer.render(&mut pixels, size.width as usize);
                }));
                assert!(pixels.iter().any(|pixel| pixel != &pixels[0]));
                let mut ppm = format!("P6\n{} {}\n255\n", size.width, size.height).into_bytes();
                for pixel in &pixels {
                    ppm.extend_from_slice(&[pixel.r, pixel.g, pixel.b]);
                }
                std::fs::write(std::path::Path::new(&output).join(filename), ppm).unwrap();
                pixels
            };
            for (choice, locale) in [(1, "zh-CN"), (2, "en")] {
                assert!(change_language(&app, &state, choice));
                for invalid in [false, true] {
                    {
                        let mut state = state.borrow_mut();
                        state.loss_download_draft = invalid.then(|| "101.25".to_string());
                        state.loss_upload_draft = invalid.then(|| "-1".to_string());
                        state.delay_download_draft = invalid.then(|| "5001".to_string());
                        state.delay_upload_draft = invalid.then(|| "-1".to_string());
                    }
                    update_selected_sidebar(&app, &state);
                    let mode = if invalid { "invalid" } else { "normal" };
                    for scale in [1.0_f32, 1.25, 1.5, 2.0] {
                        window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
                            scale_factor: scale,
                        });
                        for (width, height) in [(900, 500), (1180, 700)] {
                            window.set_size(slint::LogicalSize::new(width as f32, height as f32));
                            let mut top_pixels = Vec::new();
                            for (scroll, delta_y) in
                                [("top", 2000.0), ("bottom", -2000.0), ("settings", 0.0)]
                            {
                                app.set_settings_open(scroll == "settings");
                                window.dispatch_event(
                                    slint::platform::WindowEvent::PointerScrolled {
                                        position: slint::LogicalPosition::new(
                                            width as f32 - 150.0,
                                            height as f32 / 2.0,
                                        ),
                                        delta_x: 0.0,
                                        delta_y,
                                    },
                                );
                                let pixels = render_preview(&format!(
                                    "{locale}-{mode}-{width}-{}-{scroll}.ppm",
                                    (scale * 100.0) as u32,
                                ));
                                if scroll == "top" {
                                    top_pixels = pixels;
                                } else if scroll == "bottom" {
                                    assert_ne!(pixels, top_pixels, "sidebar must scroll");
                                }
                            }
                        }
                    }
                }
            }
            {
                let mut state = state.borrow_mut();
                let group_rule = ProcessRule {
                    upload_delay_ms: Some(200),
                    ..Default::default()
                };
                let child_rule = ProcessRule {
                    download_delay_ms: Some(0),
                    ..Default::default()
                };
                state.rows = vec![
                    CoreProcessRow::global(state.global_rule.clone()),
                    CoreProcessRow {
                        kind: RowKind::Group {
                            process_name: "preview.worker.exe".into(),
                            display_name: "Preview Worker.exe".into(),
                            exe_path: String::new(),
                            pids: vec![42001, 42002],
                            expanded: true,
                        },
                        dl_bps: 0.0,
                        ul_bps: 0.0,
                        rule: group_rule,
                    },
                    CoreProcessRow {
                        kind: RowKind::Child {
                            process_name: "preview.worker.exe".into(),
                            display_name: "Preview Worker.exe".into(),
                            exe_path: String::new(),
                            pid: 42002,
                        },
                        dl_bps: 0.0,
                        ul_bps: 0.0,
                        rule: child_rule,
                    },
                ];
                state.connections_by_pid = [42001, 42002]
                    .into_iter()
                    .map(|pid| {
                        let connection = TcpConnection {
                            key: TcpConnectionKey::decode_id(&format!(
                                "4|192.0.2.10|{pid}|198.51.100.20|443",
                            ))
                            .unwrap(),
                            pid,
                            state: flowbrake_core::TcpConnectionState::Established,
                        };
                        (pid, vec![connection])
                    })
                    .collect();
            }
            app.set_settings_open(false);
            app.set_selected_sidebar_tab(0);
            for (row_index, scope) in [(1, "group"), (2, "pid")] {
                state.borrow_mut().select_row(row_index);
                {
                    let mut state = state.borrow_mut();
                    publish_full_table(&app, &mut state);
                }
                update_selected_sidebar(&app, &state);
                for (choice, locale) in [(1, "zh-CN"), (2, "en")] {
                    assert!(change_language(&app, &state, choice));
                    for invalid in [false, true] {
                        {
                            let mut state = state.borrow_mut();
                            state.loss_download_draft = None;
                            state.loss_upload_draft = None;
                            state.delay_download_draft = invalid.then(|| "5001".to_string());
                            state.delay_upload_draft = invalid.then(|| "-1".to_string());
                        }
                        update_selected_sidebar(&app, &state);
                        assert!(app.get_selected_show_connections());
                        assert!(app.get_selected_can_disconnect_all());
                        assert_eq!(app.get_selected_loss_hint(), tr.invoke_loss_inherit_hint());
                        let mode = if invalid { "invalid" } else { "normal" };
                        for (width, height, scale) in [(900, 500, 1.0_f32), (1180, 700, 2.0)] {
                            window.dispatch_event(
                                slint::platform::WindowEvent::ScaleFactorChanged {
                                    scale_factor: scale,
                                },
                            );
                            window.set_size(slint::LogicalSize::new(width as f32, height as f32));
                            let mut top_pixels = Vec::new();
                            for (scroll, delta_y) in [("top", 2000.0), ("bottom", -2000.0)] {
                                window.dispatch_event(
                                    slint::platform::WindowEvent::PointerScrolled {
                                        position: slint::LogicalPosition::new(
                                            width as f32 - 150.0,
                                            height as f32 / 2.0,
                                        ),
                                        delta_x: 0.0,
                                        delta_y,
                                    },
                                );
                                let pixels = render_preview(&format!(
                                    "{locale}-{scope}-{mode}-{width}-{}-{scroll}.ppm",
                                    (scale * 100.0) as u32,
                                ));
                                if scroll == "top" {
                                    top_pixels = pixels;
                                } else {
                                    assert_ne!(pixels, top_pixels, "{scope} sidebar must scroll");
                                }
                            }
                        }
                    }
                }
            }
        }
        state.borrow_mut().selected = None;
        update_selected_sidebar(&app, &state);
        assert!(state.borrow().delay_download_draft.is_none());
        assert!(state.borrow().delay_upload_draft.is_none());
        assert_eq!(app.get_selected_dl_delay(), "");
        assert_eq!(app.get_selected_ul_delay_error(), "");
    }

    #[test]
    fn name_rule_refresh_preserves_child_loss_override_and_inherits_for_new_pid() {
        let group_rule = ProcessRule {
            download_loss_basis_points: Some(2500),
            upload_loss_basis_points: Some(1000),
            download_delay_ms: Some(100),
            upload_delay_ms: Some(200),
            ..Default::default()
        };
        let child_rule = ProcessRule {
            download_loss_basis_points: Some(0),
            upload_loss_basis_points: Some(500),
            download_delay_ms: Some(0),
            upload_delay_ms: Some(5000),
            ..Default::default()
        };
        let name_rules = HashMap::from([("example.exe".to_string(), group_rule.clone())]);
        let mut rules = HashMap::from([(10, child_rule.clone())]);
        let processes = [
            flowbrake_core::ProcessInfo::new(10, "Example.exe"),
            flowbrake_core::ProcessInfo::new(20, "Example.exe"),
        ];

        let added = inherit_name_rules(&mut rules, &name_rules, &processes);
        assert_eq!(rules.get(&10), Some(&child_rule));
        assert_eq!(rules.get(&20), Some(&group_rule));
        assert_eq!(added, vec![(20, group_rule)]);
        assert!(inherit_name_rules(&mut rules, &name_rules, &processes).is_empty());
        assert_eq!(rules.get(&10), Some(&child_rule));
    }

    #[test]
    fn runtime_rule_retains_loss_overrides_without_speed_limits() {
        let rule = ProcessRule {
            download_loss_basis_points: Some(0),
            upload_loss_basis_points: Some(125),
            ..Default::default()
        };
        let runtime = runtime_rule(&rule);
        assert_eq!(runtime.download_loss_basis_points, Some(0));
        assert_eq!(runtime.upload_loss_basis_points, Some(125));
        assert!(runtime.has_any_rule());
    }

    #[test]
    fn runtime_rule_retains_delay_only_and_explicit_zero_without_speed_limits() {
        for value in [0, 100, 5000] {
            let rule = ProcessRule {
                download_delay_ms: Some(value),
                upload_delay_ms: Some(value),
                ..Default::default()
            };
            let runtime = runtime_rule(&rule);
            assert_eq!(runtime.download_delay_ms, Some(value));
            assert_eq!(runtime.upload_delay_ms, Some(value));
            assert!(runtime.has_any_rule());
            assert_eq!(runtime.target_bps(Direction::Download), None);
            assert_eq!(runtime.target_bps(Direction::Upload), None);
        }
    }

    #[test]
    fn delay_edits_validate_before_changing_active_or_saved_rules() {
        let mut state = AppState::new(AppSettings {
            global_rule: ProcessRule {
                download_delay_ms: Some(100),
                upload_delay_ms: Some(200),
                ..Default::default()
            },
            ..Default::default()
        });
        state.selected = Some(RowSelection::Global);
        state.rows = vec![CoreProcessRow::global(state.global_rule.clone())];
        let saved = state.to_settings();
        for (direction, value) in [("dl", "5001"), ("ul", "-1"), ("dl", "1.5"), ("ul", "+1")] {
            assert!(!state.edit_selected_delay(direction, value));
            assert_eq!(state.to_settings(), saved);
        }
        assert_eq!(state.delay_download_draft.as_deref(), Some("1.5"));
        assert_eq!(state.delay_upload_draft.as_deref(), Some("+1"));
        assert!(!state.edit_selected_delay("invalid", "100"));
        assert!(state.edit_selected_delay("dl", "0"));
        assert_eq!(state.global_rule.download_delay_ms, Some(0));
        assert_eq!(state.global_rule.upload_delay_ms, Some(200));
        assert!(state.delay_download_draft.is_none());
        state.rows = vec![CoreProcessRow::global(state.global_rule.clone())];
        assert!(state.edit_selected_delay("ul", " 5000 "));
        assert_eq!(state.global_rule.upload_delay_ms, Some(5000));
        assert!(state.delay_upload_draft.is_none());
        state.rows = vec![CoreProcessRow::global(state.global_rule.clone())];
        assert!(state.edit_selected_delay("dl", ""));
        assert_eq!(state.global_rule.download_delay_ms, None);
        assert_eq!(state.to_settings().global_rule.upload_delay_ms, Some(5000));
        state.selected = None;
        assert!(!state.edit_selected_delay("ul", "0"));
    }

    #[test]
    fn delay_group_edits_update_current_pids_but_child_edits_do_not_change_template() {
        let mut state = AppState::new(AppSettings::default());
        let group = RowKind::Group {
            process_name: "example.exe".into(),
            display_name: "Example.exe".into(),
            exe_path: String::new(),
            pids: vec![10, 20],
            expanded: true,
        };
        state.selected = Some(RowSelection::from(&group));
        state.rows = vec![CoreProcessRow {
            kind: group,
            dl_bps: 0.0,
            ul_bps: 0.0,
            rule: ProcessRule::default(),
        }];
        assert!(state.edit_selected_delay("dl", "100"));
        assert_eq!(state.rules[&10].download_delay_ms, Some(100));
        assert_eq!(state.rules[&20].download_delay_ms, Some(100));
        let saved = state.to_settings();
        assert_eq!(saved.name_rules["example.exe"].download_delay_ms, Some(100));
        let child = RowKind::Child {
            process_name: "example.exe".into(),
            display_name: "Example.exe".into(),
            exe_path: String::new(),
            pid: 10,
        };
        state.selected = Some(RowSelection::from(&child));
        state.rows = vec![CoreProcessRow {
            kind: child,
            dl_bps: 0.0,
            ul_bps: 0.0,
            rule: state.rules[&10].clone(),
        }];
        assert!(state.edit_selected_delay("dl", "0"));
        assert_eq!(state.rules[&10].download_delay_ms, Some(0));
        assert_eq!(state.rules[&20].download_delay_ms, Some(100));
        assert_eq!(state.to_settings(), saved);
    }

    #[test]
    fn runtime_rule_ignores_draft_limit_values_until_checkbox_is_enabled() {
        let draft = ProcessRule {
            download_kbps: 128,
            upload_kbps: 64,
            ..Default::default()
        };

        let runtime = runtime_rule(&draft);
        assert_eq!(runtime.download_kbps, 0);
        assert_eq!(runtime.upload_kbps, 0);
        assert_eq!(runtime.target_bps(Direction::Download), None);
        assert_eq!(runtime.target_bps(Direction::Upload), None);
    }

    #[test]
    fn runtime_rule_keeps_enabled_limit_values() {
        let draft = ProcessRule {
            limit_download: true,
            download_kbps: 128,
            upload_kbps: 64,
            ..Default::default()
        };

        let runtime = runtime_rule(&draft);
        assert_eq!(runtime.download_kbps, 128);
        assert_eq!(runtime.upload_kbps, 0);
        assert_eq!(runtime.target_bps(Direction::Download), Some(131_072.0));
        assert_eq!(runtime.target_bps(Direction::Upload), None);
    }
}
