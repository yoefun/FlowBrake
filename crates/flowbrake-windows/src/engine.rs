use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flowbrake_core::{Direction, GlobalRule, ProcessRule, TokenBucket};
use thiserror::Error;

use crate::ip_helper::PortPidMap;
use crate::packet::Ipv4Packet;
use crate::windivert::{WinDivert, WinDivertError};

const FILTER: &str = "ip and (tcp or udp)";
const BUF_SIZE: usize = 65_535;
const PORT_MAP_REFRESH: Duration = Duration::from_millis(1500);

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    WinDivert(#[from] WinDivertError),
    #[error("engine is already running")]
    AlreadyRunning,
}

#[derive(Debug, Clone)]
pub enum EngineCommand {
    UpdateRule(u32, ProcessRule),
    UpdateRuleForPids(Vec<u32>, ProcessRule),
    SetGlobalRule(GlobalRule),
    ClearRules,
}

#[derive(Debug, Default, Clone)]
pub struct EngineSnapshot {
    pub per_pid: HashMap<u32, (u64, u64)>,
    pub global_download_bytes: u64,
    pub global_upload_bytes: u64,
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub running: bool,
}

#[derive(Debug, Default)]
struct ByteCounters {
    download: u64,
    upload: u64,
}

#[derive(Debug, Default)]
struct EngineState {
    rules: RwLock<HashMap<u32, ProcessRule>>,
    global_rule: RwLock<GlobalRule>,
    counters: Mutex<HashMap<u32, ByteCounters>>,
    global_download: AtomicU64,
    global_upload: AtomicU64,
    packets_processed: AtomicU64,
    packets_dropped: AtomicU64,
}

pub struct NetworkEngine {
    exe_dir: PathBuf,
    state: Arc<EngineState>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    active_divert: Option<WinDivert>,
}

impl NetworkEngine {
    pub fn new(exe_dir: impl Into<PathBuf>) -> Self {
        Self {
            exe_dir: exe_dir.into(),
            state: Arc::new(EngineState::default()),
            stopping: Arc::new(AtomicBool::new(false)),
            worker: None,
            active_divert: None,
        }
    }

    pub fn from_current_exe_dir() -> Self {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        Self::new(exe_dir)
    }

    pub fn is_running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.is_running() {
            return Err(EngineError::AlreadyRunning);
        }

        let divert = WinDivert::open_from_dir(&self.exe_dir, FILTER)?;
        self.stopping.store(false, Ordering::Release);
        self.reset_runtime_counters();

        let state = Arc::clone(&self.state);
        let stopping = Arc::clone(&self.stopping);
        let worker_divert = divert.clone();
        self.worker = Some(
            thread::Builder::new()
                .name("FlowBrake-Recv".to_string())
                .spawn(move || recv_loop(worker_divert, state, stopping))
                .expect("failed to spawn packet worker"),
        );
        self.active_divert = Some(divert);

        Ok(())
    }

    pub fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(divert) = self.active_divert.take() {
            divert.close();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    pub fn apply(&self, command: EngineCommand) {
        match command {
            EngineCommand::UpdateRule(pid, rule) => self.update_rule(pid, rule),
            EngineCommand::UpdateRuleForPids(pids, rule) => {
                for pid in pids {
                    self.update_rule(pid, rule.clone());
                }
            }
            EngineCommand::SetGlobalRule(rule) => {
                *self
                    .state
                    .global_rule
                    .write()
                    .expect("global rule lock poisoned") = rule;
            }
            EngineCommand::ClearRules => {
                self.state
                    .rules
                    .write()
                    .expect("rules lock poisoned")
                    .clear();
                *self
                    .state
                    .global_rule
                    .write()
                    .expect("global rule lock poisoned") = GlobalRule::default();
            }
        }
    }

    pub fn active_rule_pids(&self) -> Vec<u32> {
        self.state
            .rules
            .read()
            .expect("rules lock poisoned")
            .keys()
            .copied()
            .collect()
    }

    pub fn snapshot_and_reset(&self) -> EngineSnapshot {
        let mut per_pid = HashMap::new();
        for (pid, counters) in self
            .state
            .counters
            .lock()
            .expect("counters lock poisoned")
            .iter_mut()
        {
            per_pid.insert(*pid, (counters.download, counters.upload));
            counters.download = 0;
            counters.upload = 0;
        }

        EngineSnapshot {
            per_pid,
            global_download_bytes: self.state.global_download.swap(0, Ordering::AcqRel),
            global_upload_bytes: self.state.global_upload.swap(0, Ordering::AcqRel),
            packets_processed: self.state.packets_processed.load(Ordering::Acquire),
            packets_dropped: self.state.packets_dropped.load(Ordering::Acquire),
            running: self.is_running(),
        }
    }

    fn update_rule(&self, pid: u32, rule: ProcessRule) {
        let mut rules = self.state.rules.write().expect("rules lock poisoned");
        if rule.has_any_rule() {
            rules.insert(pid, rule);
        } else {
            rules.remove(&pid);
        }
    }

    fn reset_runtime_counters(&self) {
        self.state
            .counters
            .lock()
            .expect("counters lock poisoned")
            .clear();
        self.state.global_download.store(0, Ordering::Release);
        self.state.global_upload.store(0, Ordering::Release);
        self.state.packets_processed.store(0, Ordering::Release);
        self.state.packets_dropped.store(0, Ordering::Release);
    }
}

impl Drop for NetworkEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn recv_loop(divert: WinDivert, state: Arc<EngineState>, stopping: Arc<AtomicBool>) {
    let mut packet_buffer = vec![0u8; BUF_SIZE];
    let mut port_pid = PortPidMap::refresh();
    let mut last_map_refresh = Instant::now();
    let mut buckets: HashMap<(u32, Direction), (TokenBucket, Instant)> = HashMap::new();
    let mut global_dl_bucket: Option<(TokenBucket, Instant)> = None;
    let mut global_ul_bucket: Option<(TokenBucket, Instant)> = None;

    while !stopping.load(Ordering::Acquire) {
        let Some((read_len, mut address)) = divert.recv(&mut packet_buffer) else {
            break;
        };

        state.packets_processed.fetch_add(1, Ordering::AcqRel);

        if address.is_ipv6() {
            let _ = divert.send(&packet_buffer[..read_len], &mut address);
            continue;
        }

        if last_map_refresh.elapsed() >= PORT_MAP_REFRESH {
            port_pid = PortPidMap::refresh();
            last_map_refresh = Instant::now();
        }

        let direction = if address.is_outbound() {
            Direction::Upload
        } else {
            Direction::Download
        };
        let Some(packet) = Ipv4Packet::parse(&packet_buffer[..read_len]) else {
            let _ = divert.send(&packet_buffer[..read_len], &mut address);
            continue;
        };

        let pid = port_pid.pid_for(packet.protocol, packet.local_port(direction));
        let charge_len = packet.payload_len;

        if should_drop_global(
            &state,
            direction,
            charge_len,
            &mut global_dl_bucket,
            &mut global_ul_bucket,
        ) || should_drop_process(&state, pid, direction, charge_len, &mut buckets)
        {
            state.packets_dropped.fetch_add(1, Ordering::AcqRel);
            continue;
        }

        if charge_len > 0 {
            if let Some(pid) = pid {
                let mut counters = state.counters.lock().expect("counters lock poisoned");
                let counter = counters.entry(pid).or_default();
                match direction {
                    Direction::Download => counter.download += charge_len as u64,
                    Direction::Upload => counter.upload += charge_len as u64,
                }
            }

            match direction {
                Direction::Download => state
                    .global_download
                    .fetch_add(charge_len as u64, Ordering::AcqRel),
                Direction::Upload => state
                    .global_upload
                    .fetch_add(charge_len as u64, Ordering::AcqRel),
            };
        }

        let _ = divert.send(&packet_buffer[..read_len], &mut address);
    }
}

fn should_drop_global(
    state: &EngineState,
    direction: Direction,
    packet_len: usize,
    dl_bucket: &mut Option<(TokenBucket, Instant)>,
    ul_bucket: &mut Option<(TokenBucket, Instant)>,
) -> bool {
    if packet_len == 0 {
        return false;
    }
    let rule = state
        .global_rule
        .read()
        .expect("global rule lock poisoned")
        .clone();
    if rule.block_all {
        return true;
    }
    let Some(rate) = rule.effective_bps(direction) else {
        return false;
    };

    let slot = match direction {
        Direction::Download => dl_bucket,
        Direction::Upload => ul_bucket,
    };
    consume_bucket(slot, rate, packet_len)
}

fn should_drop_process(
    state: &EngineState,
    pid: Option<u32>,
    direction: Direction,
    packet_len: usize,
    buckets: &mut HashMap<(u32, Direction), (TokenBucket, Instant)>,
) -> bool {
    if packet_len == 0 {
        return false;
    }
    let Some(pid) = pid else {
        return false;
    };
    let rule = state
        .rules
        .read()
        .expect("rules lock poisoned")
        .get(&pid)
        .cloned();
    let Some(rule) = rule else {
        return false;
    };
    if rule.block_all {
        return true;
    }
    let Some(rate) = rule.effective_bps(direction) else {
        return false;
    };

    let slot = buckets
        .entry((pid, direction))
        .or_insert_with(|| (TokenBucket::new(rate), Instant::now()));
    consume_existing_bucket(slot, rate, packet_len)
}

fn consume_bucket(slot: &mut Option<(TokenBucket, Instant)>, rate: f64, packet_len: usize) -> bool {
    let slot = slot.get_or_insert_with(|| (TokenBucket::new(rate), Instant::now()));
    consume_existing_bucket(slot, rate, packet_len)
}

fn consume_existing_bucket(
    slot: &mut (TokenBucket, Instant),
    rate: f64,
    packet_len: usize,
) -> bool {
    let now = Instant::now();
    let elapsed = now.saturating_duration_since(slot.1);
    slot.1 = now;
    slot.0.set_rate(rate);
    !slot.0.try_consume(packet_len, elapsed)
}
