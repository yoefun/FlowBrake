#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use flowbrake_core::{
    build_process_rows, compute_adaptive_rate, format_speed, Direction, GlobalRule,
    ProcessRow as CoreProcessRow, ProcessRule, RollingAverage, RowKind, SortColumn, SortDirection,
};
use flowbrake_windows::{get_network_processes, EngineCommand, NetworkEngine};
use slint::{
    CloseRequestResponse, ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel,
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
};

slint::include_modules!();

struct AppState {
    engine: NetworkEngine,
    expanded: HashSet<String>,
    rules: HashMap<u32, ProcessRule>,
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
}

impl AppState {
    fn new() -> Self {
        Self {
            engine: NetworkEngine::from_current_exe_dir(),
            expanded: HashSet::new(),
            rules: HashMap::new(),
            global_rule: GlobalRule::default(),
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
        }
    }

    fn rebuild_rows(&mut self) {
        let processes = get_network_processes(self.rules.keys().copied());
        self.rows = build_process_rows(
            &processes,
            &self.expanded,
            &self.rules,
            &self.speeds,
            self.global_rule.clone(),
            SortColumn::Process,
            SortDirection::Ascending,
        );
        if let Some(global) = self.rows.first_mut() {
            global.dl_bps = self.global_dl_bps;
            global.ul_bps = self.global_ul_bps;
        }
    }

    fn start(&mut self) -> Result<(), String> {
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

    fn expand_all(&mut self) {
        for process in get_network_processes(self.rules.keys().copied()) {
            self.expanded.insert(process.name);
        }
    }

    fn collapse_all(&mut self) {
        self.expanded.clear();
    }

    fn select_row(&mut self, row_index: i32) {
        self.selected = self
            .rows
            .get(row_index as usize)
            .map(|row| RowSelection::from(&row.kind));
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
        let Some(kbps) = parse_kbps(text) else {
            return;
        };
        self.suppress_table_refresh_until = Some(Instant::now() + Duration::from_secs(2));
        let mut rule = row.rule.clone();
        match direction {
            "dl" => rule.download_kbps = kbps,
            "ul" => rule.upload_kbps = kbps,
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
                    format_speed(self.global_dl_bps),
                    format_speed(self.global_ul_bps),
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
            RowKind::Group { pids, .. } => {
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

fn main() -> Result<(), slint::PlatformError> {
    let app = AppWindow::new()?;
    let state = Rc::new(RefCell::new(AppState::new()));

    render_rows(&app, &state);

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_start_requested(move || {
            let app = app_weak.unwrap();
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
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_stop_requested(move || {
            let app = app_weak.unwrap();
            state.borrow_mut().stop();
            state.borrow().set_tray_visible(false);
            app.set_running(false);
            app.set_status_text("Interceptor stopped".into());
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.window().on_close_requested(move || {
            let app = app_weak.unwrap();
            let mut state = state.borrow_mut();
            if state.engine.is_running() {
                state.set_tray_visible(true);
                CloseRequestResponse::HideWindow
            } else {
                state.full_exit();
                let _ = app.hide();
                slint::quit_event_loop().ok();
                CloseRequestResponse::HideWindow
            }
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_refresh_requested(move || {
            let app = app_weak.unwrap();
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_collapse_all_requested(move || {
            let app = app_weak.unwrap();
            state.borrow_mut().collapse_all();
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_expand_all_requested(move || {
            let app = app_weak.unwrap();
            state.borrow_mut().expand_all();
            render_rows(&app, &state);
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_row_clicked(move |row_index| {
            let app = app_weak.unwrap();
            state.borrow_mut().select_row(row_index);
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
        });
    }

    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        app.on_selected_bool_rule_edited(move |field, value| {
            let app = app_weak.unwrap();
            state.borrow_mut().edit_selected_bool(field.as_str(), value);
            render_rows(&app, &state);
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

    let timer = Timer::default();
    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        timer.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            let app = app_weak.unwrap();
            let status = state.borrow_mut().tick();
            app.set_running(status.running);
            app.set_status_text(status.text.into());
            if state.borrow().can_refresh_table() {
                render_rows(&app, &state);
            }
        });
    }

    let tray_timer = Timer::default();
    {
        let app_weak = app.as_weak();
        let state = Rc::clone(&state);
        tray_timer.start(TimerMode::Repeated, Duration::from_millis(200), move || {
            let app = app_weak.unwrap();
            let action = state
                .borrow()
                .tray
                .as_ref()
                .and_then(TrayController::poll_action);
            match action {
                Some(TrayAction::Open) => {
                    state.borrow().set_tray_visible(false);
                    let _ = app.show();
                }
                Some(TrayAction::Exit) => {
                    state.borrow_mut().full_exit();
                    let _ = app.hide();
                    slint::quit_event_loop().ok();
                }
                None => {}
            }
        });
    }

    app.run()
}

fn render_rows(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let mut state_ref = state.borrow_mut();
    state_ref.rebuild_rows();
    let rows: Vec<ProcessRow> = state_ref.rows.iter().map(to_ui_row).collect();
    let selected_row_index = state_ref.selected_row_index();
    update_summary_panel(app, &state_ref);
    app.set_rows(ModelRc::new(VecModel::from(rows)));
    app.set_selected_row(selected_row_index);
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
            format_speed(state.global_dl_bps),
            format_speed(state.global_ul_bps)
        )
        .into(),
    );
    app.set_summary_global_limit(global_limit_summary(&state.global_rule).into());
    app.set_summary_process_limits(process_limits.to_string().into());
    app.set_summary_blocked(blocked.to_string().into());
    app.set_summary_adaptive(adaptive.to_string().into());
}

fn update_selected_sidebar(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let state = state.borrow();
    let Some(row) = state.selected_row() else {
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
        return;
    };

    let (title, kind, pid, pids) = match &row.kind {
        RowKind::Global => (
            "GLOBAL (all traffic)".to_string(),
            "Global rule".to_string(),
            "-".to_string(),
            "All traffic".to_string(),
        ),
        RowKind::Group {
            process_name, pids, ..
        } => (
            process_name.clone(),
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
        RowKind::Child { process_name, pid } => (
            process_name.clone(),
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
    app.set_selected_dl_speed(format_speed(row.dl_bps).into());
    app.set_selected_ul_speed(format_speed(row.ul_bps).into());
    app.set_selected_limit_dl(row.rule.limit_download);
    app.set_selected_dl_limit(limit_text(row.rule.download_kbps));
    app.set_selected_limit_ul(row.rule.limit_upload);
    app.set_selected_ul_limit(limit_text(row.rule.upload_kbps));
    app.set_selected_block(row.rule.block_all);
    app.set_selected_adaptive(row.rule.adaptive);
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

fn to_ui_row(row: &CoreProcessRow) -> ProcessRow {
    let (process, pid, is_global, is_group, depth) = match &row.kind {
        RowKind::Global => (
            SharedString::from("GLOBAL (all traffic)"),
            SharedString::from(""),
            true,
            false,
            0,
        ),
        RowKind::Group {
            process_name,
            pids,
            expanded,
        } => {
            let label = if pids.len() > 1 {
                format!(
                    "{} {} ({})",
                    if *expanded { "v" } else { ">" },
                    process_name,
                    pids.len()
                )
            } else {
                process_name.clone()
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
            )
        }
        RowKind::Child { pid, .. } => (
            SharedString::from(format!("PID {pid}")),
            SharedString::from(pid.to_string()),
            false,
            false,
            1,
        ),
    };

    ProcessRow {
        process,
        pid,
        dl_speed: SharedString::from(format_speed(row.dl_bps)),
        ul_speed: SharedString::from(format_speed(row.ul_bps)),
        limit_dl: row.rule.limit_download,
        dl_limit: limit_display_text(row.rule.limit_download, row.rule.download_kbps),
        limit_ul: row.rule.limit_upload,
        ul_limit: limit_display_text(row.rule.limit_upload, row.rule.upload_kbps),
        block: row.rule.block_all,
        adaptive: row.rule.adaptive,
        is_global,
        is_group,
        depth,
    }
}

fn limit_text(kbps: u32) -> SharedString {
    if kbps > 0 {
        SharedString::from(kbps.to_string())
    } else {
        SharedString::from("")
    }
}

fn limit_display_text(enabled: bool, kbps: u32) -> SharedString {
    if enabled && kbps > 0 {
        SharedString::from(kbps.to_string())
    } else {
        SharedString::from("Off")
    }
}

fn global_limit_summary(rule: &GlobalRule) -> String {
    format!(
        "DL {} / UL {}",
        limit_summary_text(rule.limit_download, rule.download_kbps),
        limit_summary_text(rule.limit_upload, rule.upload_kbps)
    )
}

fn limit_summary_text(enabled: bool, kbps: u32) -> String {
    if enabled && kbps > 0 {
        format!("{kbps} KB/s")
    } else {
        "Off".to_string()
    }
}

fn parse_kbps(text: &str) -> Option<u32> {
    let text = text.trim();
    if text.is_empty() {
        return Some(0);
    }
    text.parse::<u32>().ok()
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
