#![cfg_attr(all(not(test), target_os = "windows"), windows_subsystem = "windows")]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use flowbrake_core::{
    Direction, GlobalRule, ProcessRow as CoreProcessRow, ProcessRule, RollingAverage, RowKind,
    SortColumn, SortDirection, SpeedUnit, TcpConnection, TcpConnectionKey, build_process_rows,
    compute_adaptive_rate, format_limit_kibps, format_limit_summary, format_speed,
    parse_limit_input,
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

mod process_search;
mod settings;
mod window_chrome;

use process_search::{ProcessSearchLocate, locate_in_rows};

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
    selected: Option<RowSelection>,
    speed_unit: SpeedUnit,
    ipv6_enabled: bool,
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
            tray: TrayController::new().ok(),
            suppress_table_refresh_until: None,
            limit_editing: false,
            selected: None,
            speed_unit: SpeedUnit::from_bits_mode(settings.speed_unit_bits),
            ipv6_enabled: settings.ipv6_enabled,
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
        let mut added = Vec::new();
        for process in processes {
            let key = process.name.to_lowercase();
            let Some(rule) = self.name_rules.get(&key).cloned() else {
                continue;
            };
            if self.rules.insert(process.pid, rule.clone()).is_none() {
                added.push((process.pid, rule));
            }
        }

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

    fn tick(&mut self) -> TickStatus {
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

        TickStatus {
            running: snapshot.running,
            text: if snapshot.running {
                format!(
                    "Interceptor running   v {}   ^ {}   |   Packets: {}   Dropped: {}",
                    format_speed(self.global_dl_bps, self.speed_unit),
                    format_speed(self.global_ul_bps, self.speed_unit),
                    snapshot.packets_processed,
                    snapshot.packets_dropped
                )
            } else {
                "Interceptor stopped".to_string()
            },
        }
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

struct TickStatus {
    running: bool,
    text: String,
}

struct TrayController {
    icon: TrayIcon,
    open_id: MenuId,
    exit_id: MenuId,
}

enum TrayAction {
    Open,
    Exit,
}

impl TrayController {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let menu = Menu::new();
        let open = MenuItem::new("Open FlowBrake", true, None);
        let exit = MenuItem::new("Exit", true, None);
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
        })
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
        app.set_status_text(format!("Failed to save settings: {err}").into());
    }
}

fn main() -> Result<(), slint::PlatformError> {
    if !is_elevated() {
        match relaunch_as_admin(&[]) {
            RelaunchResult::Started => return Ok(()),
            RelaunchResult::Cancelled => {
                show_admin_required_message(
                    "FlowBrake needs administrator approval to intercept network traffic.\n\
                     Please run it again and choose Yes on the UAC prompt.",
                );
                return Ok(());
            }
            RelaunchResult::Failed(err) => {
                show_admin_required_message(&format!(
                    "FlowBrake could not request administrator privileges.\n{err}"
                ));
                return Ok(());
            }
        }
    }

    let settings = AppSettings::load();
    let window_settings = settings.clone();
    let app = AppWindow::new()?;
    app.set_window_maximized(window_settings.window_maximized);
    app.set_speed_unit_bits(settings.speed_unit_bits);
    app.set_ipv6_enabled(settings.ipv6_enabled);
    let state = Rc::new(RefCell::new(AppState::new(settings)));

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
                    app.set_status_text(format!("Failed to save settings: {err}").into());
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
            if needs_restart
                && let Err(err) = state.borrow_mut().restart_engine()
            {
                app.set_status_text(err.into());
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
            if let Some(conn_key) = TcpConnectionKey::decode_id(key.as_str()) {
                let _ = close_tcp_connection(&conn_key);
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
                close_tcp_connections_for_pids(&pids, &connections);
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
            let status = state_ref.tick();
            app.set_window_maximized(app.window().is_maximized());
            app.set_running(status.running);
            app.set_status_text(status.text.into());
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
        app.set_status_text(
            "Administrator privileges are required to start the interceptor.".into(),
        );
        return;
    }

    match state.borrow_mut().start() {
        Ok(()) => {
            app.set_running(true);
            app.set_status_text("Interceptor running".into());
        }
        Err(err) => {
            app.set_running(false);
            app.set_status_text(err.into());
        }
    }
}

fn apply_engine_stop(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    state.borrow_mut().stop();
    state.borrow().set_tray_visible(false);
    app.set_running(false);
    app.set_status_text("Interceptor stopped".into());
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
        .map(|row| to_ui_row(row, speed_unit, &mut state.icon_cache, &state.computer_name))
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

    app.set_summary_throughput(
        format!(
            "DL {} / UL {}",
            format_speed(state.global_dl_bps, state.speed_unit),
            format_speed(state.global_ul_bps, state.speed_unit)
        )
        .into(),
    );
    app.set_summary_global_limit(global_limit_summary(&state.global_rule, state.speed_unit).into());
    app.set_summary_process_limits(process_limits.to_string().into());
    app.set_summary_blocked(blocked.to_string().into());
    app.set_summary_adaptive(adaptive.to_string().into());
}

fn update_selected_sidebar(app: &AppWindow, state_rc: &Rc<RefCell<AppState>>) {
    let state = state_rc.borrow();
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
        app.set_selected_block(false);
        app.set_selected_adaptive(false);
        clear_connections_sidebar(app);
        return;
    };

    let show_connections = !matches!(row.kind, RowKind::Global);

    let (title, kind, pid, pids) = match &row.kind {
        RowKind::Global => (
            state.computer_name.clone(),
            "Computer".to_string(),
            "-".to_string(),
            "All traffic".to_string(),
        ),
        RowKind::Group {
            display_name, pids, ..
        } => (
            display_name.clone(),
            if pids.len() > 1 {
                "Process group".to_string()
            } else {
                "Process".to_string()
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
            "Process instance".to_string(),
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
    app.set_selected_dl_limit(limit_text(row.rule.download_kbps, state.speed_unit));
    app.set_selected_limit_ul(row.rule.limit_upload);
    app.set_selected_ul_limit(limit_text(row.rule.upload_kbps, state.speed_unit));
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
        app.set_selected_connections_summary(connections_summary(total).into());
        app.set_selected_connections_tab_title(connections_tab_title(total).into());
        app.set_selected_can_disconnect_all(disconnectable);
        app.set_selected_connections(ModelRc::new(VecModel::from(visible)));
    } else {
        clear_connections_sidebar(app);
    }
}

fn clear_connections_sidebar(app: &AppWindow) {
    app.set_selected_show_connections(false);
    app.set_selected_connections_summary("".into());
    app.set_selected_connections_tab_title("Connections".into());
    app.set_selected_sidebar_tab(0);
    app.set_selected_can_disconnect_all(false);
    app.set_selected_connections(ModelRc::new(VecModel::from(Vec::<ConnectionRow>::new())));
}

fn connections_tab_title(total: usize) -> String {
    if total == 0 {
        "Connections".to_string()
    } else {
        format!("Connections ({total})")
    }
}

fn pids_for_row_kind(kind: &RowKind) -> Vec<u32> {
    match kind {
        RowKind::Global => Vec::new(),
        RowKind::Group { pids, .. } => pids.clone(),
        RowKind::Child { pid, .. } => vec![*pid],
    }
}

fn connections_summary(total: usize) -> String {
    if total == 0 {
        return "No active TCP connections".to_string();
    }
    if total > MAX_VISIBLE_CONNECTIONS {
        return format!("Showing {MAX_VISIBLE_CONNECTIONS} of {total} TCP connections");
    }
    format!(
        "{total} TCP connection{}",
        if total == 1 { "" } else { "s" }
    )
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
        dl_limit: limit_display_text(row.rule.limit_download, row.rule.download_kbps, unit),
        dl_limit_edit: limit_text(row.rule.download_kbps, unit),
        limit_ul: row.rule.limit_upload,
        ul_limit: limit_display_text(row.rule.limit_upload, row.rule.upload_kbps, unit),
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

fn limit_display_text(enabled: bool, kibps: u32, unit: SpeedUnit) -> SharedString {
    if enabled && kibps > 0 {
        SharedString::from(format_limit_kibps(kibps, unit))
    } else {
        SharedString::from("Off")
    }
}

fn global_limit_summary(rule: &GlobalRule, unit: SpeedUnit) -> String {
    format!(
        "DL {} / UL {}",
        limit_summary_text(rule.limit_download, rule.download_kbps, unit),
        limit_summary_text(rule.limit_upload, rule.upload_kbps, unit)
    )
}

fn limit_summary_text(enabled: bool, kibps: u32, unit: SpeedUnit) -> String {
    if enabled && kibps > 0 {
        format_limit_summary(kibps, unit)
    } else {
        "Off".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
