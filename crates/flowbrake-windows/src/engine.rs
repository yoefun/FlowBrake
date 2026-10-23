use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flowbrake_core::{Direction, GlobalRule, MAX_DELAY_MS, ProcessRule, TokenBucket};
use thiserror::Error;

use crate::delay_queue::{DelayQueue, PendingPacket};
use crate::elevation::runtime_dir;
use crate::ip_helper::PortPidMap;
use crate::packet::IpPacket;
use crate::windivert::{WinDivert, WinDivertAddress, WinDivertError};

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
    #[error("failed to start packet worker: {0}")]
    WorkerSpawn(#[from] io::Error),
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
    pub packets_blocked: u64,
    pub packets_loss_dropped: u64,
    pub packets_rate_dropped: u64,
    pub packets_loss_eligible: u64,
    pub packets_delayed: u64,
    pub delay_queue_packets: u64,
    pub delay_queue_bytes: u64,
    pub packets_queue_dropped: u64,
    pub packets_send_failed: u64,
    pub packets_shutdown_dropped: u64,
    pub engine_error: Option<String>,
    pub running: bool,
    pub block_error: Option<String>,
}

#[derive(Debug, Default)]
struct ByteCounters {
    download: u64,
    upload: u64,
}

#[derive(Default)]
struct EngineState {
    rules: RwLock<HashMap<u32, ProcessRule>>,
    global_rule: RwLock<GlobalRule>,
    counters: Mutex<HashMap<u32, ByteCounters>>,
    global_download: AtomicU64,
    global_upload: AtomicU64,
    packets_processed: AtomicU64,
    packets_dropped: AtomicU64,
    packets_blocked: AtomicU64,
    packets_loss_dropped: AtomicU64,
    packets_rate_dropped: AtomicU64,
    packets_loss_eligible: AtomicU64,
    packets_delayed: AtomicU64,
    packets_queue_dropped: AtomicU64,
    packets_send_failed: AtomicU64,
    packets_shutdown_dropped: AtomicU64,
    error: Mutex<Option<String>>,
    aborted: AtomicBool,
    send_gate: Mutex<()>,
    delay: DelayRuntime,
    rule_revision: AtomicU64,
}

#[derive(Default)]
struct DelayRuntime {
    queue: Mutex<QueueState>,
    changed: Condvar,
}

#[derive(Default)]
struct QueueState {
    packets: DelayQueue,
    draining: bool,
    recv_done: bool,
}

trait PacketIo: Send + Sync {
    fn recv(&self, bytes: &mut [u8]) -> io::Result<(usize, WinDivertAddress)>;
    fn send(&self, bytes: &[u8], address: &mut WinDivertAddress) -> io::Result<()>;
    fn shutdown_recv(&self) -> io::Result<()>;
    fn close(&self);
}

impl PacketIo for WinDivert {
    fn recv(&self, bytes: &mut [u8]) -> io::Result<(usize, WinDivertAddress)> {
        self.recv_result(bytes)
    }

    fn send(&self, bytes: &[u8], address: &mut WinDivertAddress) -> io::Result<()> {
        self.send_result(bytes, address)
    }

    fn shutdown_recv(&self) -> io::Result<()> {
        WinDivert::shutdown_recv(self)
    }

    fn close(&self) {
        WinDivert::close(self);
    }
}

struct PacketWorker {
    io: Arc<dyn PacketIo>,
    state: Arc<EngineState>,
    stopping: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
    socket_block: Arc<Mutex<SocketBlock>>,
}

impl PacketWorker {
    fn request_stop(&self) {
        let already_stopping = self.stopping.swap(true, Ordering::AcqRel);
        {
            let mut queue = self
                .state
                .delay
                .queue
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            queue.draining = true;
            queue.packets.release_matching(Instant::now(), |_| true);
            self.state.delay.changed.notify_all();
        }
        if !already_stopping && let Err(error) = self.io.shutdown_recv() {
            self.fail(format!("Packet receive shutdown failed: {error}"));
        }
    }

    fn fail(&self, error: String) {
        *self.state.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
        self.state.aborted.store(true, Ordering::Release);
        self.stopping.store(true, Ordering::Release);
        self.io.close();
        *self.socket_block.lock().unwrap_or_else(|e| e.into_inner()) = SocketBlock::default();
        let mut queue = self
            .state
            .delay
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        queue.draining = true;
        queue.packets.release_matching(Instant::now(), |_| true);
        self.state.delay.changed.notify_all();
    }

    fn send(
        &self,
        bytes: &[u8],
        address: &mut WinDivertAddress,
        pid: Option<u32>,
        direction: Direction,
        charge_len: usize,
    ) {
        let _gate = self
            .state
            .send_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.state.aborted.load(Ordering::Acquire) {
            record_drop(&self.state, DropReason::Shutdown);
            return;
        }
        if global_blocks_packet(&self.state, address.is_loopback())
            || process_blocks_packet(&self.state, pid, address.is_loopback())
        {
            record_drop(&self.state, DropReason::Block);
            return;
        }
        match self.io.send(bytes, address) {
            Ok(()) => record_bytes(&self.state, pid, direction, charge_len),
            Err(error) => {
                record_drop(&self.state, DropReason::Send);
                let message = format!("Packet send failed: {error}");
                if matches!(error.raw_os_error(), Some(6 | 995)) {
                    self.fail(message);
                } else {
                    *self.state.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(message);
                }
            }
        }
    }
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
    sender: Option<JoinHandle<()>>,
    active_worker: Option<Arc<PacketWorker>>,
    socket_block: Arc<Mutex<SocketBlock>>,
}

impl NetworkEngine {
    pub fn new(exe_dir: impl Into<PathBuf>) -> Self {
        Self {
            exe_dir: exe_dir.into(),
            state: Arc::new(EngineState::default()),
            stopping: Arc::new(AtomicBool::new(false)),
            ipv6_enabled: Arc::new(AtomicBool::new(true)),
            worker: None,
            sender: None,
            active_worker: None,
            socket_block: Arc::new(Mutex::new(SocketBlock::default())),
        }
    }

    pub fn from_current_exe_dir() -> Self {
        Self::new(runtime_dir())
    }

    pub fn is_running(&self) -> bool {
        !self.stopping.load(Ordering::Acquire)
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
            && self
                .sender
                .as_ref()
                .is_some_and(|sender| !sender.is_finished())
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
        self.stop();
        let divert = WinDivert::open_from_dir(&self.exe_dir, NETWORK_FILTER)?;
        self.sync_socket_block()?;
        self.start_with_io(Arc::new(divert))
    }

    fn start_with_io(&mut self, io: Arc<dyn PacketIo>) -> Result<(), EngineError> {
        self.stopping.store(false, Ordering::Release);
        self.reset_runtime_counters();
        let context = Arc::new(PacketWorker {
            io,
            state: Arc::clone(&self.state),
            stopping: Arc::clone(&self.stopping),
            ipv6_enabled: Arc::clone(&self.ipv6_enabled),
            socket_block: Arc::clone(&self.socket_block),
        });
        self.active_worker = Some(Arc::clone(&context));
        let sender_context = Arc::clone(&context);
        match thread::Builder::new()
            .name("FlowBrake-Send".to_string())
            .spawn(move || run_worker(sender_context, false))
        {
            Ok(sender) => self.sender = Some(sender),
            Err(error) => {
                self.stop();
                return Err(error.into());
            }
        }
        match thread::Builder::new()
            .name("FlowBrake-Recv".to_string())
            .spawn(move || run_worker(context, true))
        {
            Ok(worker) => {
                self.worker = Some(worker);
                Ok(())
            }
            Err(error) => {
                self.state.delay.queue.lock().unwrap().recv_done = true;
                self.stop();
                Err(error.into())
            }
        }
    }

    pub fn stop(&mut self) {
        if let Some(context) = self.active_worker.as_ref() {
            context.request_stop();
        } else {
            self.stopping.store(true, Ordering::Release);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Some(sender) = self.sender.take() {
            let _ = sender.join();
        }
        if let Some(context) = self.active_worker.take() {
            context.io.close();
        }
        discard_pending(&self.state);
        *self
            .socket_block
            .lock()
            .expect("socket block lock poisoned") = SocketBlock::default();
    }

    pub fn apply(&self, command: EngineCommand) {
        let gate = self
            .state
            .send_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let revision = self.state.rule_revision.load(Ordering::Acquire);
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
                if current.block_all != rule.block_all
                    || current.download_delay_ms != rule.download_delay_ms
                    || current.upload_delay_ms != rule.upload_delay_ms
                {
                    self.state.rule_revision.fetch_add(1, Ordering::AcqRel);
                }
                *current = rule;
            }
            EngineCommand::ClearRules => {
                self.state.rule_revision.fetch_add(1, Ordering::AcqRel);
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
        if self.state.rule_revision.load(Ordering::Acquire) != revision {
            let mut queue = self
                .state
                .delay
                .queue
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            queue.packets.release_matching(Instant::now(), |packet| {
                global_blocks_packet(&self.state, false)
                    || process_blocks_packet(&self.state, packet.pid, false)
                    || effective_delay_ms(&self.state, packet.pid, packet.direction, false) == 0
            });
            self.state.delay.changed.notify_all();
        }
        drop(gate);
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

        let queue = self
            .state
            .delay
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        EngineSnapshot {
            per_pid,
            global_download_bytes: self.state.global_download.swap(0, Ordering::AcqRel),
            global_upload_bytes: self.state.global_upload.swap(0, Ordering::AcqRel),
            packets_processed: self.state.packets_processed.load(Ordering::Acquire),
            packets_dropped: self.state.packets_dropped.load(Ordering::Acquire),
            packets_blocked: self.state.packets_blocked.load(Ordering::Acquire),
            packets_loss_dropped: self.state.packets_loss_dropped.load(Ordering::Acquire),
            packets_rate_dropped: self.state.packets_rate_dropped.load(Ordering::Acquire),
            packets_loss_eligible: self.state.packets_loss_eligible.load(Ordering::Acquire),
            packets_delayed: self.state.packets_delayed.load(Ordering::Acquire),
            delay_queue_packets: queue.packets.packet_count() as u64,
            delay_queue_bytes: queue.packets.byte_count() as u64,
            packets_queue_dropped: self.state.packets_queue_dropped.load(Ordering::Acquire),
            packets_send_failed: self.state.packets_send_failed.load(Ordering::Acquire),
            packets_shutdown_dropped: self.state.packets_shutdown_dropped.load(Ordering::Acquire),
            engine_error: self
                .state
                .error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            running,
            block_error,
        }
    }

    fn update_rule(&self, pid: u32, rule: ProcessRule) {
        let mut rules = self.state.rules.write().expect("rules lock poisoned");
        let current = rules.get(&pid);
        if current.is_some_and(|current| current.block_all) != rule.block_all
            || current.and_then(|current| current.download_loss_basis_points)
                != rule.download_loss_basis_points
            || current.and_then(|current| current.upload_loss_basis_points)
                != rule.upload_loss_basis_points
            || current.and_then(|current| current.download_delay_ms) != rule.download_delay_ms
            || current.and_then(|current| current.upload_delay_ms) != rule.upload_delay_ms
        {
            self.state.rule_revision.fetch_add(1, Ordering::AcqRel);
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
        self.state.packets_blocked.store(0, Ordering::Release);
        self.state.packets_loss_dropped.store(0, Ordering::Release);
        self.state.packets_rate_dropped.store(0, Ordering::Release);
        self.state.packets_loss_eligible.store(0, Ordering::Release);
        self.state.packets_delayed.store(0, Ordering::Release);
        self.state.packets_queue_dropped.store(0, Ordering::Release);
        self.state.packets_send_failed.store(0, Ordering::Release);
        self.state
            .packets_shutdown_dropped
            .store(0, Ordering::Release);
        self.state.aborted.store(false, Ordering::Release);
        *self.state.error.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .state
            .delay
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = QueueState::default();
    }
}

impl Drop for NetworkEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_worker(context: Arc<PacketWorker>, receiving: bool) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if receiving {
            recv_loop(&context);
        } else {
            send_loop(&context);
        }
    }));
    if result.is_err() {
        context.fail(format!(
            "Packet {} worker panicked",
            if receiving { "receive" } else { "send" }
        ));
        if !receiving {
            let _gate = context
                .state
                .send_gate
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            discard_pending(&context.state);
        }
    }
    if receiving {
        let mut queue = context
            .state
            .delay
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        queue.recv_done = true;
        context.state.delay.changed.notify_all();
    }
}

fn send_loop(context: &PacketWorker) {
    let mut queue = context
        .state
        .delay
        .queue
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    loop {
        let now = Instant::now();
        if let Some(mut packet) = queue.packets.pop_due(now) {
            drop(queue);
            context.send(
                &packet.bytes,
                &mut packet.address,
                packet.pid,
                packet.direction,
                packet.charge_len,
            );
            queue = context
                .state
                .delay
                .queue
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            queue.packets.finish(&packet);
            continue;
        }
        if queue.recv_done && queue.packets.next_deadline().is_none() {
            break;
        }
        queue = match queue.packets.next_deadline() {
            Some(deadline) => {
                context
                    .state
                    .delay
                    .changed
                    .wait_timeout(queue, deadline.saturating_duration_since(now))
                    .unwrap_or_else(|e| e.into_inner())
                    .0
            }
            None => context
                .state
                .delay
                .changed
                .wait(queue)
                .unwrap_or_else(|e| e.into_inner()),
        };
    }
}

fn recv_loop(context: &PacketWorker) {
    let state = &context.state;
    let mut packet_buffer = vec![0u8; BUF_SIZE];
    let mut port_pid = PortPidMap::refresh(true);
    let mut last_map_refresh = Instant::now();
    let mut rule_revision = state.rule_revision.load(Ordering::Acquire);
    let mut unresolved_ports = HashSet::new();
    let mut buckets: HashMap<(u32, Direction), (TokenBucket, Instant)> = HashMap::new();
    let mut global_dl_bucket: Option<(TokenBucket, Instant)> = None;
    let mut global_ul_bucket: Option<(TokenBucket, Instant)> = None;
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ u64::from(std::process::id());
    let mut loss_sampler = LossSampler(seed);

    loop {
        let (read_len, mut address) = match context.io.recv(&mut packet_buffer) {
            Ok(packet) => packet,
            Err(error) => {
                if !state.aborted.load(Ordering::Acquire)
                    && !(context.stopping.load(Ordering::Acquire)
                        && error.raw_os_error() == Some(232))
                {
                    context.fail(format!("Packet receive failed: {error}"));
                }
                break;
            }
        };
        let received_at = Instant::now();

        state.packets_processed.fetch_add(1, Ordering::AcqRel);
        if state.aborted.load(Ordering::Acquire) {
            record_drop(state, DropReason::Shutdown);
            continue;
        }

        let current_revision = state.rule_revision.load(Ordering::Acquire);
        if last_map_refresh.elapsed() >= PORT_MAP_REFRESH || current_revision != rule_revision {
            port_pid = PortPidMap::refresh(true);
            last_map_refresh = Instant::now();
            rule_revision = current_revision;
            unresolved_ports.clear();
        }

        let is_ipv6 = address.is_ipv6();
        let is_loopback = address.is_loopback();
        // Global Block precedes parsing so ICMP, fragments and unsupported
        // transport headers cannot bypass it.
        if global_blocks_packet(state, is_loopback) {
            record_drop(state, DropReason::Block);
            continue;
        }
        let direction = if address.is_outbound() {
            Direction::Upload
        } else {
            Direction::Download
        };
        let Some(packet) = IpPacket::parse(&packet_buffer[..read_len], is_ipv6) else {
            context.send(&packet_buffer[..read_len], &mut address, None, direction, 0);
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
                .any(|rule| {
                    rule.block_all
                        || rule.download_loss_basis_points.is_some()
                        || rule.upload_loss_basis_points.is_some()
                        || rule.download_delay_ms.is_some()
                        || rule.upload_delay_ms.is_some()
                })
            && unresolved_ports.insert((packet.protocol, local_port, is_ipv6))
        {
            // Resolve newly created endpoints immediately, rather than waiting
            // for the periodic table refresh. Cache misses to bound table queries.
            port_pid = PortPidMap::refresh(true);
            pid = port_pid.pid_for(packet.protocol, local_port, is_ipv6);
        }
        if process_blocks_packet(state, pid, is_loopback) {
            record_drop(state, DropReason::Block);
            continue;
        }
        if should_drop_for_loss(state, pid, direction, is_loopback, &mut loss_sampler) {
            record_drop(state, DropReason::Loss);
            continue;
        }
        let charge_len = if is_ipv6 && !context.ipv6_enabled.load(Ordering::Acquire) {
            0
        } else {
            packet.payload_len
        };

        if let Some(reason) = should_drop_global(
            state,
            direction,
            charge_len,
            is_loopback,
            &mut global_dl_bucket,
            &mut global_ul_bucket,
        )
        .or_else(|| {
            should_drop_process(state, pid, direction, charge_len, is_loopback, &mut buckets)
        }) {
            record_drop(state, reason);
            continue;
        }

        let gate = state.send_gate.lock().unwrap_or_else(|e| e.into_inner());
        if state.aborted.load(Ordering::Acquire) {
            record_drop(state, DropReason::Shutdown);
            continue;
        }
        let delay_ms = effective_delay_ms(state, pid, direction, is_loopback);
        let mut queue = state.delay.queue.lock().unwrap_or_else(|e| e.into_inner());
        if !is_loopback && (delay_ms > 0 || queue.packets.has_flow(&packet.flow_key())) {
            let deadline = if queue.draining {
                received_at
            } else {
                received_at + Duration::from_millis(u64::from(delay_ms))
            };
            let pending = PendingPacket {
                bytes: packet_buffer[..read_len].to_vec(),
                address,
                pid,
                direction,
                charge_len,
                flow: packet.flow_key(),
            };
            if queue.packets.enqueue(pending, deadline) {
                state.packets_delayed.fetch_add(1, Ordering::AcqRel);
                state.delay.changed.notify_one();
            } else {
                record_drop(state, DropReason::Queue);
            }
        } else {
            drop(queue);
            drop(gate);
            context.send(
                &packet_buffer[..read_len],
                &mut address,
                pid,
                direction,
                charge_len,
            );
        }
    }
}

fn effective_delay_ms(
    state: &EngineState,
    pid: Option<u32>,
    direction: Direction,
    is_loopback: bool,
) -> u32 {
    if is_loopback {
        return 0;
    }
    let process_delay = pid.and_then(|pid| {
        state
            .rules
            .read()
            .expect("rules lock poisoned")
            .get(&pid)
            .and_then(|rule| rule.delay_ms(direction))
    });
    process_delay
        .unwrap_or_else(|| {
            state
                .global_rule
                .read()
                .expect("global rule lock poisoned")
                .delay_ms(direction)
                .unwrap_or(0)
        })
        .min(MAX_DELAY_MS)
}

fn record_bytes(state: &EngineState, pid: Option<u32>, direction: Direction, bytes: usize) {
    if bytes == 0 {
        return;
    }
    if let Some(pid) = pid {
        let mut counters = state.counters.lock().expect("counters lock poisoned");
        let counter = counters.entry(pid).or_default();
        match direction {
            Direction::Download => counter.download += bytes as u64,
            Direction::Upload => counter.upload += bytes as u64,
        }
    }
    match direction {
        Direction::Download => &state.global_download,
        Direction::Upload => &state.global_upload,
    }
    .fetch_add(bytes as u64, Ordering::AcqRel);
}

fn discard_pending(state: &EngineState) {
    let mut queue = state.delay.queue.lock().unwrap_or_else(|e| e.into_inner());
    let remaining = queue.packets.packet_count() as u64;
    state
        .packets_shutdown_dropped
        .fetch_add(remaining, Ordering::AcqRel);
    state.packets_dropped.fetch_add(remaining, Ordering::AcqRel);
    queue.packets = DelayQueue::default();
    state.delay.changed.notify_all();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropReason {
    Block,
    Loss,
    Rate,
    Queue,
    Send,
    Shutdown,
}

fn record_drop(state: &EngineState, reason: DropReason) {
    let counter = match reason {
        DropReason::Block => &state.packets_blocked,
        DropReason::Loss => &state.packets_loss_dropped,
        DropReason::Rate => &state.packets_rate_dropped,
        DropReason::Queue => &state.packets_queue_dropped,
        DropReason::Send => &state.packets_send_failed,
        DropReason::Shutdown => &state.packets_shutdown_dropped,
    };
    counter.fetch_add(1, Ordering::AcqRel);
    state.packets_dropped.fetch_add(1, Ordering::AcqRel);
}

// SplitMix64 supplies a worker-local stream for simulation, not cryptography.
// Fixed seeds make tests repeatable; production seeds differ between starts.
struct LossSampler(u64);

impl LossSampler {
    fn should_drop(&mut self, basis_points: u16) -> bool {
        if basis_points == 0 {
            return false;
        }
        if basis_points >= 10_000 {
            return true;
        }
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^= value >> 31;
        // Multiplication avoids a biased modulo reduction to 10,000 buckets.
        u128::from(value) * 10_000 < (u128::from(basis_points) << 64)
    }
}

fn process_blocks_packet(state: &EngineState, pid: Option<u32>, is_loopback: bool) -> bool {
    !is_loopback
        && pid.is_some_and(|pid| {
            state
                .rules
                .read()
                .expect("rules lock poisoned")
                .get(&pid)
                .is_some_and(|rule| rule.block_all)
        })
}

fn should_drop_for_loss(
    state: &EngineState,
    pid: Option<u32>,
    direction: Direction,
    is_loopback: bool,
    sampler: &mut LossSampler,
) -> bool {
    if is_loopback {
        return false;
    }
    let process_loss = pid.and_then(|pid| {
        state
            .rules
            .read()
            .expect("rules lock poisoned")
            .get(&pid)
            .and_then(|rule| rule.loss_basis_points(direction))
    });
    let loss = process_loss.unwrap_or_else(|| {
        state
            .global_rule
            .read()
            .expect("global rule lock poisoned")
            .loss_basis_points(direction)
            .unwrap_or(0)
    });
    if loss == 0 {
        return false;
    }
    state.packets_loss_eligible.fetch_add(1, Ordering::AcqRel);
    sampler.should_drop(loss)
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
) -> Option<DropReason> {
    let rule = state
        .global_rule
        .read()
        .expect("global rule lock poisoned")
        .clone();
    if rule.block_all && !is_loopback {
        return Some(DropReason::Block);
    }
    if packet_len == 0 {
        return None;
    }
    let rate = rule.effective_bps(direction)?;

    let slot = match direction {
        Direction::Download => dl_bucket,
        Direction::Upload => ul_bucket,
    };
    consume_bucket(slot, rate, packet_len).then_some(DropReason::Rate)
}

fn should_drop_process(
    state: &EngineState,
    pid: Option<u32>,
    direction: Direction,
    packet_len: usize,
    is_loopback: bool,
    buckets: &mut HashMap<(u32, Direction), (TokenBucket, Instant)>,
) -> Option<DropReason> {
    let pid = pid?;
    let rule = state
        .rules
        .read()
        .expect("rules lock poisoned")
        .get(&pid)
        .cloned();
    let rule = rule?;
    if rule.block_all && !is_loopback {
        return Some(DropReason::Block);
    }
    if packet_len == 0 {
        return None;
    }
    let rate = rule.effective_bps(direction)?;

    let slot = buckets
        .entry((pid, direction))
        .or_insert_with(|| (TokenBucket::new(rate), Instant::now()));
    consume_existing_bucket(slot, rate, packet_len).then_some(DropReason::Rate)
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
    use std::collections::VecDeque;
    use std::sync::mpsc::{self, Receiver, Sender};

    #[derive(Default)]
    struct FakeReceive {
        packets: VecDeque<(Vec<u8>, WinDivertAddress)>,
        shutdown: bool,
        closed: bool,
    }

    struct FakeIo {
        receive: Mutex<FakeReceive>,
        ready: Condvar,
        sent: Sender<Vec<u8>>,
        fail_next_send: AtomicU64,
        panic_next_send: AtomicBool,
    }

    impl FakeIo {
        fn new() -> (Arc<Self>, Receiver<Vec<u8>>) {
            let (sent, receiver) = mpsc::channel();
            (
                Arc::new(Self {
                    receive: Mutex::new(FakeReceive::default()),
                    ready: Condvar::new(),
                    sent,
                    fail_next_send: AtomicU64::new(0),
                    panic_next_send: AtomicBool::new(false),
                }),
                receiver,
            )
        }

        fn feed(&self, bytes: Vec<u8>) {
            self.feed_with_flags(bytes, 0x0002_0000);
        }

        fn feed_with_flags(&self, bytes: Vec<u8>, flags: u32) {
            let mut address = WinDivertAddress::default();
            address.flags = flags;
            self.receive
                .lock()
                .unwrap()
                .packets
                .push_back((bytes, address));
            self.ready.notify_all();
        }

        fn wait_closed(&self) {
            let (receive, _) = self
                .ready
                .wait_timeout_while(
                    self.receive.lock().unwrap(),
                    Duration::from_secs(3),
                    |receive| !receive.closed,
                )
                .unwrap();
            assert!(receive.closed, "fatal I/O error must close interception");
        }
    }

    impl PacketIo for FakeIo {
        fn recv(&self, bytes: &mut [u8]) -> io::Result<(usize, WinDivertAddress)> {
            let mut receive = self.receive.lock().unwrap();
            loop {
                if receive.closed {
                    return Err(io::Error::from_raw_os_error(6));
                }
                if let Some((packet, address)) = receive.packets.pop_front() {
                    bytes[..packet.len()].copy_from_slice(&packet);
                    return Ok((packet.len(), address));
                }
                if receive.shutdown {
                    return Err(io::Error::from_raw_os_error(232));
                }
                receive = self.ready.wait(receive).unwrap();
            }
        }

        fn send(&self, bytes: &[u8], _address: &mut WinDivertAddress) -> io::Result<()> {
            assert!(
                !self.panic_next_send.swap(false, Ordering::AcqRel),
                "injected send panic"
            );
            if self.receive.lock().unwrap().closed {
                return Err(io::Error::from_raw_os_error(6));
            }
            let error = self.fail_next_send.swap(0, Ordering::AcqRel);
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            self.sent.send(bytes.to_vec()).map_err(io::Error::other)
        }

        fn shutdown_recv(&self) -> io::Result<()> {
            self.receive.lock().unwrap().shutdown = true;
            self.ready.notify_all();
            Ok(())
        }

        fn close(&self) {
            self.receive.lock().unwrap().closed = true;
            self.ready.notify_all();
        }
    }

    fn udp_packet(source_port: u16, marker: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 29];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&29u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&9000u16.to_be_bytes());
        packet[24..26].copy_from_slice(&9u16.to_be_bytes());
        packet[28] = marker;
        packet
    }

    fn delayed_engine(delay_ms: u32) -> (NetworkEngine, Arc<FakeIo>, Receiver<Vec<u8>>) {
        let mut engine = NetworkEngine::new("missing-driver-directory");
        engine.apply(EngineCommand::SetGlobalRule(ProcessRule {
            upload_delay_ms: Some(delay_ms),
            ..Default::default()
        }));
        let (io, sent) = FakeIo::new();
        engine.start_with_io(io.clone()).unwrap();
        (engine, io, sent)
    }

    fn wait_for_queued(engine: &NetworkEngine, count: usize) {
        let (queue, _) = engine
            .state
            .delay
            .changed
            .wait_timeout_while(
                engine.state.delay.queue.lock().unwrap(),
                Duration::from_secs(3),
                |queue| queue.packets.packet_count() < count,
            )
            .unwrap();
        assert!(
            queue.packets.packet_count() >= count,
            "packets were not queued"
        );
    }

    fn wait_for_worker_exit(engine: &NetworkEngine) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !(engine.worker.as_ref().unwrap().is_finished()
            && engine.sender.as_ref().unwrap().is_finished())
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(engine.worker.as_ref().unwrap().is_finished());
        assert!(engine.sender.as_ref().unwrap().is_finished());
    }

    #[test]
    fn delay_inheritance_zero_override_and_loopback_are_independent() {
        let engine = NetworkEngine::new("missing-driver-directory");
        engine.apply(EngineCommand::SetGlobalRule(ProcessRule {
            download_delay_ms: Some(100),
            upload_delay_ms: Some(200),
            ..Default::default()
        }));
        engine.apply(EngineCommand::UpdateRule(
            42,
            ProcessRule {
                download_delay_ms: Some(0),
                ..Default::default()
            },
        ));
        assert_eq!(
            effective_delay_ms(&engine.state, None, Direction::Download, false),
            100
        );
        assert_eq!(
            effective_delay_ms(&engine.state, Some(99), Direction::Upload, false),
            200
        );
        assert_eq!(
            effective_delay_ms(&engine.state, Some(42), Direction::Download, false),
            0
        );
        assert_eq!(
            effective_delay_ms(&engine.state, Some(42), Direction::Upload, false),
            200
        );
        assert_eq!(
            effective_delay_ms(&engine.state, Some(42), Direction::Upload, true),
            0
        );
        assert_eq!(engine.active_rule_pids(), vec![42]);
        assert!(
            socket_block_filter(
                &engine.state.global_rule.read().unwrap(),
                &engine.state.rules.read().unwrap(),
            )
            .is_none()
        );
    }

    #[test]
    fn deadline_sends_without_another_received_packet() {
        let (mut engine, io, sent) = delayed_engine(30);
        let started = Instant::now();
        io.feed(udp_packet(49001, 1));
        assert_eq!(sent.recv_timeout(Duration::from_secs(3)).unwrap()[28], 1);
        assert!(started.elapsed() >= Duration::from_millis(30));
        engine.stop();
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.packets_delayed, 1);
        assert_eq!(snapshot.global_upload_bytes, 1);
        assert_eq!(snapshot.delay_queue_packets, 0);
        assert_eq!(snapshot.packets_dropped, 0);
    }

    #[test]
    fn earlier_deadline_wakes_sender_without_blocking_other_flows() {
        let (mut engine, io, sent) = delayed_engine(5000);
        io.feed(udp_packet(49001, 1));
        wait_for_queued(&engine, 1);
        engine.apply(EngineCommand::SetGlobalRule(ProcessRule {
            upload_delay_ms: Some(1),
            ..Default::default()
        }));
        io.feed(udp_packet(49002, 2));
        assert_eq!(sent.recv_timeout(Duration::from_secs(3)).unwrap()[28], 2);
        assert!(sent.try_recv().is_err());
        engine.apply(EngineCommand::ClearRules);
        assert_eq!(sent.recv_timeout(Duration::from_secs(3)).unwrap()[28], 1);
        engine.stop();
        assert_eq!(engine.snapshot_and_reset().packets_dropped, 0);
    }

    #[test]
    fn zero_delay_releases_pending_flow_in_capture_order() {
        let (mut engine, io, sent) = delayed_engine(5000);
        io.feed(udp_packet(49001, 1));
        io.feed(udp_packet(49001, 2));
        wait_for_queued(&engine, 2);
        assert_eq!(engine.snapshot_and_reset().global_upload_bytes, 0);
        engine.apply(EngineCommand::SetGlobalRule(ProcessRule {
            upload_delay_ms: Some(0),
            ..Default::default()
        }));
        io.feed(udp_packet(49001, 3));
        for marker in [1, 2, 3] {
            assert_eq!(
                sent.recv_timeout(Duration::from_secs(3)).unwrap()[28],
                marker
            );
        }
        engine.stop();
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.global_upload_bytes, 3);
        assert_eq!(snapshot.packets_dropped, 0);
        assert_eq!(snapshot.packets_loss_eligible, 0);
        assert_eq!(snapshot.delay_queue_packets, 0);
    }

    #[test]
    fn block_applies_to_previously_queued_packets() {
        let (mut engine, io, sent) = delayed_engine(5000);
        io.feed(udp_packet(49001, 1));
        io.feed(udp_packet(49001, 2));
        wait_for_queued(&engine, 2);
        engine.apply(EngineCommand::SetGlobalRule(ProcessRule {
            block_all: true,
            ..Default::default()
        }));
        engine.stop();
        assert!(sent.try_recv().is_err());
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.packets_blocked, 2);
        assert_eq!(snapshot.packets_dropped, 2);
        assert_eq!(snapshot.packets_delayed, 2);
        assert_eq!(snapshot.delay_queue_bytes, 0);
    }

    #[test]
    fn block_update_waits_for_the_final_send_gate() {
        let engine = NetworkEngine::new("missing-driver-directory");
        let gate = engine.state.send_gate.lock().unwrap();
        thread::scope(|scope| {
            let (done, finished) = mpsc::channel();
            let engine = &engine;
            scope.spawn(move || {
                engine.apply(EngineCommand::SetGlobalRule(ProcessRule {
                    block_all: true,
                    ..Default::default()
                }));
                done.send(()).unwrap();
            });
            assert!(finished.recv_timeout(Duration::from_millis(30)).is_err());
            drop(gate);
            finished.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        assert!(global_blocks_packet(&engine.state, false));
    }

    #[test]
    fn stop_drains_driver_and_user_queues_before_close_and_restart() {
        let (mut engine, io, sent) = delayed_engine(5000);
        io.feed(udp_packet(49001, 1));
        wait_for_queued(&engine, 1);
        io.feed(udp_packet(49001, 2));
        let started = Instant::now();
        engine.stop();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(sent.recv_timeout(Duration::from_secs(1)).unwrap()[28], 1);
        assert_eq!(sent.recv_timeout(Duration::from_secs(1)).unwrap()[28], 2);
        let snapshot = engine.snapshot_and_reset();
        assert!(!snapshot.running);
        assert_eq!(snapshot.delay_queue_packets, 0);
        assert_eq!(snapshot.packets_shutdown_dropped, 0);
        assert!(snapshot.engine_error.is_none());
        let (next_io, _) = FakeIo::new();
        engine.start_with_io(next_io).unwrap();
        assert!(engine.is_running());
        assert_eq!(engine.snapshot_and_reset().packets_delayed, 0);
        engine.stop();
    }

    #[test]
    fn isolated_send_failure_is_counted_without_stopping_the_engine() {
        let (mut engine, io, sent) = delayed_engine(0);
        io.fail_next_send.store(1234, Ordering::Release);
        io.feed(udp_packet(49001, 1));
        io.feed(udp_packet(49001, 2));
        assert_eq!(sent.recv_timeout(Duration::from_secs(3)).unwrap()[28], 2);
        assert!(engine.is_running());
        engine.stop();
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.packets_send_failed, 1);
        assert_eq!(snapshot.packets_dropped, 1);
        assert_eq!(snapshot.global_upload_bytes, 1);
        assert!(snapshot.engine_error.is_some());
    }

    #[test]
    fn fatal_send_failure_unblocks_receive_and_discards_the_remaining_queue() {
        let (mut engine, io, sent) = delayed_engine(5000);
        io.feed(udp_packet(49001, 1));
        io.feed(udp_packet(49001, 2));
        wait_for_queued(&engine, 2);
        io.fail_next_send.store(6, Ordering::Release);
        engine.apply(EngineCommand::ClearRules);
        io.wait_closed();
        engine.stop();
        let snapshot = engine.snapshot_and_reset();
        assert!(!snapshot.running);
        assert_eq!(snapshot.delay_queue_packets, 0);
        assert_eq!(snapshot.packets_send_failed, 1);
        assert_eq!(snapshot.packets_shutdown_dropped, 1);
        assert_eq!(snapshot.packets_dropped, 2);
        assert!(sent.try_recv().is_err());
    }

    #[test]
    fn sender_panic_clears_queue_and_accounting_without_waiting_for_explicit_stop() {
        let (mut engine, io, sent) = delayed_engine(5000);
        io.feed(udp_packet(49001, 1));
        io.feed(udp_packet(49001, 2));
        wait_for_queued(&engine, 2);
        io.panic_next_send.store(true, Ordering::Release);
        engine.apply(EngineCommand::ClearRules);
        wait_for_worker_exit(&engine);
        let snapshot = engine.snapshot_and_reset();
        assert!(!snapshot.running);
        assert_eq!(snapshot.delay_queue_packets, 0);
        assert_eq!(snapshot.delay_queue_bytes, 0);
        assert_eq!(snapshot.packets_shutdown_dropped, 2);
        assert_eq!(snapshot.packets_dropped, 2);
        assert!(snapshot.engine_error.unwrap().contains("panicked"));
        assert!(sent.try_recv().is_err());
        engine.stop();
        assert_eq!(engine.snapshot_and_reset().packets_shutdown_dropped, 2);
    }

    #[test]
    fn unexpected_receive_failure_discards_pending_and_exits_both_workers() {
        let (mut engine, io, _) = delayed_engine(5000);
        io.feed(udp_packet(49001, 1));
        wait_for_queued(&engine, 1);
        io.close();
        wait_for_worker_exit(&engine);
        let snapshot = engine.snapshot_and_reset();
        assert!(!snapshot.running);
        assert_eq!(snapshot.delay_queue_packets, 0);
        assert_eq!(snapshot.packets_shutdown_dropped, 1);
        assert!(snapshot.engine_error.unwrap().contains("receive"));
        engine.stop();
    }

    #[test]
    fn ipv6_control_packets_are_delayed_even_with_statistics_off_but_loopback_is_not() {
        let (mut engine, io, sent) = delayed_engine(5000);
        engine.set_ipv6_enabled(false);
        let mut tcp = vec![0u8; 60];
        tcp[0] = 0x60;
        tcp[4..6].copy_from_slice(&20u16.to_be_bytes());
        tcp[6] = 6;
        tcp[52] = 0x50;
        io.feed_with_flags(tcp, 0x0012_0000);
        wait_for_queued(&engine, 1);
        io.feed_with_flags(udp_packet(49001, 7), 0x0006_0000);
        assert_eq!(sent.recv_timeout(Duration::from_secs(3)).unwrap()[28], 7);
        engine.apply(EngineCommand::ClearRules);
        assert_eq!(sent.recv_timeout(Duration::from_secs(3)).unwrap().len(), 60);
        engine.stop();
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.packets_delayed, 1);
        assert_eq!(snapshot.packets_dropped, 0);
    }

    #[test]
    fn queue_overflow_is_visible_and_zero_delay_other_flows_still_pass() {
        let (mut engine, io, sent) = delayed_engine(5000);
        for _ in 0..4097 {
            io.feed(udp_packet(49001, 1));
        }
        io.feed(vec![0]);
        assert_eq!(sent.recv_timeout(Duration::from_secs(3)).unwrap(), vec![0]);
        let queued = engine.snapshot_and_reset();
        assert_eq!(queued.delay_queue_packets, 4096);
        assert_eq!(queued.packets_queue_dropped, 1);
        assert_eq!(queued.packets_dropped, 1);
        engine.stop();
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.delay_queue_packets, 0);
        assert_eq!(snapshot.global_upload_bytes, 4096);
        assert_eq!(snapshot.packets_send_failed, 0);
        assert_eq!(snapshot.packets_shutdown_dropped, 0);
    }

    #[test]
    fn loss_sampler_extremes_replay_and_distribution() {
        let mut sampler = LossSampler(42);
        for _ in 0..1000 {
            assert!(!sampler.should_drop(0));
            assert!(sampler.should_drop(10_000));
        }
        let mut replay = LossSampler(42);
        for _ in 0..1000 {
            assert_eq!(sampler.should_drop(2500), replay.should_drop(2500));
        }
        let trials = 200_000;
        for rate in [1, 1000, 5000, 9999] {
            let mut sampler = LossSampler(7);
            let dropped = (0..trials).filter(|_| sampler.should_drop(rate)).count();
            let probability = f64::from(rate) / 10_000.0;
            let expected = f64::from(trials) * probability;
            let tolerance = 6.0 * (expected * (1.0 - probability)).sqrt() + 1.0;
            assert!(
                (dropped as f64 - expected).abs() <= tolerance,
                "unexpected distribution at {rate}: {dropped}"
            );
        }
    }

    // The endpoint must echo each byte over an existing non-loopback TCP connection.
    #[test]
    #[ignore = "requires administrator privileges and FLOWBRAKE_DELAY_TEST_ENDPOINT=IP:port echo server"]
    fn live_process_delay() {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpStream};

        assert!(
            crate::elevation::is_elevated(),
            "run this test as Administrator"
        );
        let endpoint: SocketAddr = std::env::var("FLOWBRAKE_DELAY_TEST_ENDPOINT")
            .expect("set an external TCP byte-echo server IP:port")
            .parse()
            .unwrap();
        assert!(
            !endpoint.ip().is_loopback(),
            "loopback is intentionally not delayed"
        );
        let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5)).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut echo = || {
            let started = Instant::now();
            stream.write_all(&[42]).unwrap();
            let mut reply = [0u8];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(reply, [42]);
            started.elapsed()
        };
        let mut baseline = (0..5).map(|_| echo()).collect::<Vec<_>>();
        baseline.sort();
        let mut engine = NetworkEngine::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/windivert"),
        );
        engine.apply(EngineCommand::UpdateRule(
            std::process::id(),
            ProcessRule {
                download_delay_ms: Some(100),
                upload_delay_ms: Some(100),
                ..Default::default()
            },
        ));
        engine.start().unwrap();
        let mut delayed = (0..5).map(|_| echo()).collect::<Vec<_>>();
        delayed.sort();
        let extra = delayed[2].saturating_sub(baseline[2]);
        assert!(
            (Duration::from_millis(150)..=Duration::from_millis(250)).contains(&extra),
            "100 ms in each direction: baseline={:?}, delayed={:?}, extra={extra:?}",
            baseline[2],
            delayed[2],
        );
        assert!(engine.snapshot_and_reset().packets_delayed > 0);
        engine.apply(EngineCommand::UpdateRule(
            std::process::id(),
            ProcessRule {
                download_delay_ms: Some(5000),
                upload_delay_ms: Some(5000),
                ..Default::default()
            },
        ));
        stream.write_all(&[7]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while engine.snapshot_and_reset().delay_queue_packets == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(engine.snapshot_and_reset().delay_queue_packets > 0);
        let stopped = Instant::now();
        engine.stop();
        assert!(stopped.elapsed() < Duration::from_secs(2));
        let mut reply = [0u8];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [7]);
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.delay_queue_packets, 0);
        assert_eq!(snapshot.packets_shutdown_dropped, 0);
        assert!(snapshot.engine_error.is_none());
    }

    #[test]
    fn loss_inheritance_zero_override_direction_and_loopback() {
        let state = EngineState::default();
        *state.global_rule.write().unwrap() = ProcessRule {
            download_loss_basis_points: Some(10_000),
            upload_loss_basis_points: Some(0),
            ..ProcessRule::default()
        };
        state.rules.write().unwrap().insert(
            42,
            ProcessRule {
                download_loss_basis_points: Some(0),
                upload_loss_basis_points: Some(10_000),
                ..ProcessRule::default()
            },
        );
        let mut sampler = LossSampler(42);
        assert!(should_drop_for_loss(
            &state,
            None,
            Direction::Download,
            false,
            &mut sampler
        ));
        assert!(should_drop_for_loss(
            &state,
            Some(99),
            Direction::Download,
            false,
            &mut sampler
        ));
        assert!(!should_drop_for_loss(
            &state,
            Some(42),
            Direction::Download,
            false,
            &mut sampler
        ));
        assert!(!should_drop_for_loss(
            &state,
            None,
            Direction::Upload,
            false,
            &mut sampler
        ));
        assert!(should_drop_for_loss(
            &state,
            Some(42),
            Direction::Upload,
            false,
            &mut sampler
        ));
        assert!(!should_drop_for_loss(
            &state,
            Some(42),
            Direction::Upload,
            true,
            &mut sampler
        ));
        assert_eq!(state.packets_loss_eligible.load(Ordering::Acquire), 3);
        state
            .rules
            .write()
            .unwrap()
            .get_mut(&42)
            .unwrap()
            .download_loss_basis_points = None;
        assert!(should_drop_for_loss(
            &state,
            Some(42),
            Direction::Download,
            false,
            &mut sampler
        ));
    }

    #[test]
    fn drop_reasons_are_separate_and_restart_resets_counters() {
        let engine = NetworkEngine::new("missing-driver-directory");
        record_drop(&engine.state, DropReason::Block);
        record_drop(&engine.state, DropReason::Loss);
        record_drop(&engine.state, DropReason::Loss);
        record_drop(&engine.state, DropReason::Rate);
        engine
            .state
            .packets_loss_eligible
            .store(5, Ordering::Release);
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.packets_dropped, 4);
        assert_eq!(snapshot.packets_blocked, 1);
        assert_eq!(snapshot.packets_loss_dropped, 2);
        assert_eq!(snapshot.packets_rate_dropped, 1);
        assert_eq!(snapshot.packets_loss_eligible, 5);
        engine.reset_runtime_counters();
        let snapshot = engine.snapshot_and_reset();
        assert_eq!(snapshot.packets_dropped, 0);
        assert_eq!(
            snapshot.packets_blocked
                + snapshot.packets_loss_dropped
                + snapshot.packets_rate_dropped
                + snapshot.packets_loss_eligible,
            0
        );
    }

    // Run explicitly from an elevated terminal with a reachable external TCP
    // endpoint. Only this test process is blocked; other applications stay online.
    #[test]
    #[ignore = "requires administrator privileges and FLOWBRAKE_TEST_ENDPOINT=IP:port"]
    fn live_process_block_and_loss_restore_connectivity() {
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
        engine.apply(EngineCommand::UpdateRule(
            std::process::id(),
            ProcessRule {
                download_loss_basis_points: Some(10_000),
                upload_loss_basis_points: Some(10_000),
                ..ProcessRule::default()
            },
        ));
        engine.start().unwrap();
        assert!(
            engine.socket_block.lock().unwrap().active.is_none(),
            "loss must not install Socket Block"
        );
        assert!(
            connect().is_err(),
            "100% loss must blackhole connection attempts"
        );
        assert!(engine.snapshot_and_reset().packets_loss_dropped > 0);
        engine.apply(EngineCommand::UpdateRule(
            std::process::id(),
            ProcessRule {
                download_loss_basis_points: Some(0),
                upload_loss_basis_points: Some(0),
                ..ProcessRule::default()
            },
        ));
        drop(connect().expect("0% loss must restore connectivity"));
        engine.stop();
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
        assert!(
            should_drop_global(
                &engine.state,
                Direction::Upload,
                512,
                true,
                &mut None,
                &mut None
            )
            .is_none()
        );
        assert!(
            should_drop_process(
                &engine.state,
                Some(42),
                Direction::Upload,
                512,
                true,
                &mut HashMap::new()
            )
            .is_none()
        );
        engine.apply(EngineCommand::ClearRules);
        assert!(!global_blocks_packet(&engine.state, false));
        assert!(
            should_drop_process(
                &engine.state,
                Some(42),
                Direction::Upload,
                512,
                false,
                &mut HashMap::new()
            )
            .is_none()
        );
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
            assert_eq!(
                should_drop_global(&state, direction, 0, false, &mut None, &mut None),
                Some(DropReason::Block)
            );
            assert_eq!(
                should_drop_process(&state, Some(42), direction, 0, false, &mut HashMap::new()),
                Some(DropReason::Block)
            );
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
            assert!(
                should_drop_global(&state, direction, 0, false, &mut None, &mut None).is_none()
            );
            assert!(
                should_drop_process(&state, Some(42), direction, 0, false, &mut HashMap::new())
                    .is_none()
            );
        }
    }
}
