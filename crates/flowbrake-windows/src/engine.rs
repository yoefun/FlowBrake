use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flowbrake_core::{Direction, GlobalRule, ProcessRule, TokenBucket};
use thiserror::Error;

use crate::elevation::runtime_dir;
use crate::ip_helper::PortPidMap;
use crate::packet::IpPacket;
use crate::windivert::{WinDivert, WinDivertError};

// Block covers both IP families even when IPv6 statistics/limiting are disabled.
const NETWORK_FILTER: &str = "ip or ipv6";
const BUF_SIZE: usize = 40 + 65_535;
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
    pub block_error: Option<String>,
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
    block_revision: AtomicU64,
}

#[derive(Default)]
struct SocketBlock {
    active: Option<(String, WinDivert)>,
    error: Option<String>,
}

pub struct NetworkEngine {
    exe_dir: PathBuf,
    state: Arc<EngineState>,
    stopping: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    active_divert: Option<WinDivert>,
    socket_block: Mutex<SocketBlock>,
}

impl NetworkEngine {
    pub fn new(exe_dir: impl Into<PathBuf>) -> Self {
        Self {
            exe_dir: exe_dir.into(),
            state: Arc::new(EngineState::default()),
            stopping: Arc::new(AtomicBool::new(false)),
            ipv6_enabled: Arc::new(AtomicBool::new(true)),
            worker: None,
            active_divert: None,
            socket_block: Mutex::new(SocketBlock::default()),
        }
    }

    pub fn from_current_exe_dir() -> Self {
        Self::new(runtime_dir())
    }

    pub fn is_running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6_enabled.load(Ordering::Acquire)
    }

    pub fn set_ipv6_enabled(&self, enabled: bool) {
        self.ipv6_enabled.store(enabled, Ordering::Release);
    }

    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.is_running() {
            return Err(EngineError::AlreadyRunning);
        }

        let divert = WinDivert::open_from_dir(&self.exe_dir, NETWORK_FILTER)?;
        self.sync_socket_block()?;
        self.stopping.store(false, Ordering::Release);
        self.reset_runtime_counters();

        let state = Arc::clone(&self.state);
        let stopping = Arc::clone(&self.stopping);
        let ipv6_enabled = Arc::clone(&self.ipv6_enabled);
        let worker_divert = divert.clone();
        self.worker = Some(
            thread::Builder::new()
                .name("FlowBrake-Recv".to_string())
                .spawn(move || recv_loop(worker_divert, state, stopping, ipv6_enabled))
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
        *self
            .socket_block
            .lock()
            .expect("socket block lock poisoned") = SocketBlock::default();
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
                let mut current = self
                    .state
                    .global_rule
                    .write()
                    .expect("global rule lock poisoned");
                if current.block_all != rule.block_all {
                    self.state.block_revision.fetch_add(1, Ordering::AcqRel);
                }
                *current = rule;
            }
            EngineCommand::ClearRules => {
                self.state.block_revision.fetch_add(1, Ordering::AcqRel);
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
        if self.is_running() {
            // Packet blocking remains active; the UI reports socket-filter failures.
            let _ = self.sync_socket_block();
        } else {
            *self
                .socket_block
                .lock()
                .expect("socket block lock poisoned") = SocketBlock::default();
        }
    }

    fn sync_socket_block(&self) -> Result<(), EngineError> {
        let filter = socket_block_filter(
            &self
                .state
                .global_rule
                .read()
                .expect("global rule lock poisoned"),
            &self.state.rules.read().expect("rules lock poisoned"),
        );
        let mut block = self
            .socket_block
            .lock()
            .expect("socket block lock poisoned");
        let Some(filter) = filter else {
            *block = SocketBlock::default();
            return Ok(());
        };
        if block
            .active
            .as_ref()
            .is_some_and(|(current, _)| current == &filter)
        {
            return Ok(());
        }
        match WinDivert::open_socket_block_from_dir(&self.exe_dir, &filter) {
            Ok(handle) => {
                // Replace only after installation to avoid an unblock window.
                block.active = Some((filter, handle));
                block.error = None;
                Ok(())
            }
            Err(error) => {
                block.active = None;
                block.error = Some(error.to_string());
                Err(error.into())
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
        let running = self.is_running();
        let block_error = {
            let mut block = self
                .socket_block
                .lock()
                .expect("socket block lock poisoned");
            if !running {
                // An unexpected packet-worker exit must not leave invisible
                // connection filters active while the UI reports "stopped".
                block.active = None;
            }
            block.error.clone()
        };
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
            running,
            block_error,
        }
    }

    fn update_rule(&self, pid: u32, rule: ProcessRule) {
        let mut rules = self.state.rules.write().expect("rules lock poisoned");
        if rules.get(&pid).is_some_and(|current| current.block_all) != rule.block_all {
            self.state.block_revision.fetch_add(1, Ordering::AcqRel);
        }
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

fn recv_loop(
    divert: WinDivert,
    state: Arc<EngineState>,
    stopping: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
) {
    let mut packet_buffer = vec![0u8; BUF_SIZE];
    let mut port_pid = PortPidMap::refresh(true);
    let mut last_map_refresh = Instant::now();
    let mut block_revision = state.block_revision.load(Ordering::Acquire);
    let mut unresolved_ports = HashSet::new();
    let mut buckets: HashMap<(u32, Direction), (TokenBucket, Instant)> = HashMap::new();
    let mut global_dl_bucket: Option<(TokenBucket, Instant)> = None;
    let mut global_ul_bucket: Option<(TokenBucket, Instant)> = None;

    while !stopping.load(Ordering::Acquire) {
        let Some((read_len, mut address)) = divert.recv(&mut packet_buffer) else {
            break;
        };

        state.packets_processed.fetch_add(1, Ordering::AcqRel);

        let current_revision = state.block_revision.load(Ordering::Acquire);
        if last_map_refresh.elapsed() >= PORT_MAP_REFRESH || current_revision != block_revision {
            port_pid = PortPidMap::refresh(true);
            last_map_refresh = Instant::now();
            block_revision = current_revision;
            unresolved_ports.clear();
        }

        let is_ipv6 = address.is_ipv6();
        let is_loopback = address.is_loopback();
        // Global Block precedes parsing so ICMP, fragments and unsupported
        // transport headers cannot bypass it.
        if global_blocks_packet(&state, is_loopback) {
            state.packets_dropped.fetch_add(1, Ordering::AcqRel);
            continue;
        }
        let direction = if address.is_outbound() {
            Direction::Upload
        } else {
            Direction::Download
        };
        let Some(packet) = IpPacket::parse(&packet_buffer[..read_len], is_ipv6) else {
            let _ = divert.send(&packet_buffer[..read_len], &mut address);
            continue;
        };

        let local_port = packet.local_port(direction);
        let mut pid = port_pid.pid_for(packet.protocol, local_port, is_ipv6);
        if pid.is_none()
            && state
                .rules
                .read()
                .expect("rules lock poisoned")
                .values()
                .any(|rule| rule.block_all)
            && unresolved_ports.insert((packet.protocol, local_port, is_ipv6))
        {
            // Resolve newly created endpoints immediately, rather than waiting
            // for the periodic table refresh. Cache misses to bound table queries.
            port_pid = PortPidMap::refresh(true);
            pid = port_pid.pid_for(packet.protocol, local_port, is_ipv6);
        }
        let charge_len = if is_ipv6 && !ipv6_enabled.load(Ordering::Acquire) {
            0
        } else {
            packet.payload_len
        };

        if should_drop_global(
            &state,
            direction,
            charge_len,
            is_loopback,
            &mut global_dl_bucket,
            &mut global_ul_bucket,
        ) || should_drop_process(
            &state,
            pid,
            direction,
            charge_len,
            is_loopback,
            &mut buckets,
        ) {
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

fn global_blocks_packet(state: &EngineState, is_loopback: bool) -> bool {
    !is_loopback
        && state
            .global_rule
            .read()
            .expect("global rule lock poisoned")
            .block_all
}

fn should_drop_global(
    state: &EngineState,
    direction: Direction,
    packet_len: usize,
    is_loopback: bool,
    dl_bucket: &mut Option<(TokenBucket, Instant)>,
    ul_bucket: &mut Option<(TokenBucket, Instant)>,
) -> bool {
    let rule = state
        .global_rule
        .read()
        .expect("global rule lock poisoned")
        .clone();
    if rule.block_all && !is_loopback {
        return true;
    }
    if packet_len == 0 {
        return false;
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
    is_loopback: bool,
    buckets: &mut HashMap<(u32, Direction), (TokenBucket, Instant)>,
) -> bool {
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
    if rule.block_all && !is_loopback {
        return true;
    }
    if packet_len == 0 {
        return false;
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

fn socket_block_filter(global: &GlobalRule, rules: &HashMap<u32, ProcessRule>) -> Option<String> {
    let events = "!loopback and (event == CONNECT or event == ACCEPT)";
    if global.block_all {
        return Some(events.to_string());
    }
    let mut pids: Vec<_> = rules
        .iter()
        .filter_map(|(pid, rule)| rule.block_all.then_some(*pid))
        .collect();
    pids.sort_unstable();
    if pids.is_empty() {
        return None;
    }
    let processes = pids
        .iter()
        .map(|pid| format!("processId == {pid}"))
        .collect::<Vec<_>>()
        .join(" or ");
    Some(format!("{events} and ({processes})"))
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

#[cfg(test)]
mod tests {
    use super::*;

    // Run explicitly from an elevated terminal with a reachable external TCP
    // endpoint. Only this test process is blocked; other applications stay online.
    #[test]
    #[ignore = "requires administrator privileges and FLOWBRAKE_TEST_ENDPOINT=IP:port"]
    fn live_process_block_prevents_connect_and_restores_on_stop() {
        use std::net::{SocketAddr, TcpListener, TcpStream};
        assert!(
            crate::elevation::is_elevated(),
            "run this test as Administrator"
        );
        let endpoint: SocketAddr = std::env::var("FLOWBRAKE_TEST_ENDPOINT")
            .expect("set a reachable external IP:port")
            .parse()
            .unwrap();
        let timeout = Duration::from_secs(3);
        let connect = || TcpStream::connect_timeout(&endpoint, timeout);
        drop(connect().expect("endpoint must be reachable before the test"));
        let loopback = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut engine = NetworkEngine::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/windivert"),
        );
        engine.start().unwrap();
        engine.apply(EngineCommand::UpdateRule(
            std::process::id(),
            ProcessRule {
                block_all: true,
                ..ProcessRule::default()
            },
        ));
        assert!(engine.snapshot_and_reset().block_error.is_none());
        assert!(
            connect().is_err(),
            "Block must prevent a new external TCP connection"
        );
        drop(
            TcpStream::connect_timeout(&loopback.local_addr().unwrap(), timeout)
                .expect("Block must preserve loopback"),
        );
        engine.apply(EngineCommand::ClearRules);
        drop(connect().expect("clearing Block must restore connectivity"));
        engine.apply(EngineCommand::UpdateRule(
            std::process::id(),
            ProcessRule {
                block_all: true,
                ..ProcessRule::default()
            },
        ));
        assert!(connect().is_err());
        engine.stop();
        drop(connect().expect("stopping must remove socket protection"));
    }

    #[test]
    fn socket_filters_compile_with_bundled_windivert() {
        type CompileFilter = unsafe extern "C" fn(
            *const std::ffi::c_char,
            i32,
            *mut std::ffi::c_char,
            u32,
            *mut *const std::ffi::c_char,
            *mut u32,
        ) -> i32;
        let library = unsafe {
            libloading::Library::new(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../third_party/windivert/WinDivert.dll"),
            )
            .unwrap()
        };
        let compile: libloading::Symbol<CompileFilter> =
            unsafe { library.get(b"WinDivertHelperCompileFilter").unwrap() };
        let blocked = ProcessRule {
            block_all: true,
            ..ProcessRule::default()
        };
        let rules = HashMap::from([
            (42, blocked.clone()),
            (99, blocked.clone()),
            (7, ProcessRule::default()),
        ]);
        let process_filter = socket_block_filter(&GlobalRule::default(), &rules).unwrap();
        assert!(process_filter.contains("processId == 42 or processId == 99"));
        assert!(!process_filter.contains("processId == 7"));
        for (filter, layer) in [
            (process_filter, 3),
            (socket_block_filter(&blocked, &rules).unwrap(), 3),
            (NETWORK_FILTER.to_string(), 0),
        ] {
            let filter = std::ffi::CString::new(filter).unwrap();
            let mut error = std::ptr::null();
            let mut position = 0;
            let ok = unsafe {
                compile(
                    filter.as_ptr(),
                    layer,
                    std::ptr::null_mut(),
                    0,
                    &mut error,
                    &mut position,
                )
            };
            assert_ne!(ok, 0, "invalid filter {filter:?} at {position}");
        }
        assert!(socket_block_filter(&GlobalRule::default(), &HashMap::new()).is_none());
    }

    #[test]
    fn block_preserves_loopback_and_ends_when_rule_is_cleared() {
        let engine = NetworkEngine::new("missing-driver-directory");
        engine.apply(EngineCommand::SetGlobalRule(ProcessRule {
            block_all: true,
            ..ProcessRule::default()
        }));
        engine.apply(EngineCommand::UpdateRule(
            42,
            ProcessRule {
                block_all: true,
                ..ProcessRule::default()
            },
        ));
        assert!(global_blocks_packet(&engine.state, false));
        assert!(!global_blocks_packet(&engine.state, true));
        assert!(!should_drop_global(
            &engine.state,
            Direction::Upload,
            512,
            true,
            &mut None,
            &mut None
        ));
        assert!(!should_drop_process(
            &engine.state,
            Some(42),
            Direction::Upload,
            512,
            true,
            &mut HashMap::new()
        ));
        engine.apply(EngineCommand::ClearRules);
        assert!(!global_blocks_packet(&engine.state, false));
        assert!(!should_drop_process(
            &engine.state,
            Some(42),
            Direction::Upload,
            512,
            false,
            &mut HashMap::new()
        ));
    }

    #[test]
    fn socket_filter_failure_is_reported_and_stop_clears_it() {
        let mut engine = NetworkEngine::new("missing-driver-directory");
        engine.apply(EngineCommand::UpdateRule(
            42,
            ProcessRule {
                block_all: true,
                ..ProcessRule::default()
            },
        ));
        assert!(engine.sync_socket_block().is_err());
        assert!(engine.snapshot_and_reset().block_error.is_some());
        engine.stop();
        assert!(engine.snapshot_and_reset().block_error.is_none());
        assert!(engine.socket_block.lock().unwrap().active.is_none());
    }

    #[test]
    fn block_drops_empty_tcp_control_packets_in_both_directions() {
        let state = EngineState::default();
        let blocked = ProcessRule {
            block_all: true,
            ..ProcessRule::default()
        };
        *state.global_rule.write().unwrap() = blocked.clone();
        state.rules.write().unwrap().insert(42, blocked);
        for direction in [Direction::Upload, Direction::Download] {
            assert!(should_drop_global(
                &state, direction, 0, false, &mut None, &mut None
            ));
            assert!(should_drop_process(
                &state,
                Some(42),
                direction,
                0,
                false,
                &mut HashMap::new()
            ));
        }
    }

    #[test]
    fn limiting_keeps_empty_tcp_control_packets_unthrottled() {
        let state = EngineState::default();
        let limited = ProcessRule {
            limit_download: true,
            download_kbps: 1,
            limit_upload: true,
            upload_kbps: 1,
            ..ProcessRule::default()
        };
        *state.global_rule.write().unwrap() = limited.clone();
        state.rules.write().unwrap().insert(42, limited);
        for direction in [Direction::Upload, Direction::Download] {
            assert!(!should_drop_global(
                &state, direction, 0, false, &mut None, &mut None
            ));
            assert!(!should_drop_process(
                &state,
                Some(42),
                direction,
                0,
                false,
                &mut HashMap::new()
            ));
        }
    }
}
