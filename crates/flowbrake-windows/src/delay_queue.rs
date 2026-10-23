use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::time::Instant;

use flowbrake_core::Direction;

use crate::packet::FlowKey;
use crate::windivert::WinDivertAddress;

pub(crate) struct PendingPacket {
    pub(crate) bytes: Vec<u8>,
    pub(crate) address: WinDivertAddress,
    pub(crate) pid: Option<u32>,
    pub(crate) direction: Direction,
    pub(crate) charge_len: usize,
    pub(crate) flow: FlowKey,
}

struct Entry {
    packet: PendingPacket,
    deadline: Instant,
    sequence: u64,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        (self.deadline, self.sequence) == (other.deadline, other.sequence)
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        (other.deadline, other.sequence).cmp(&(self.deadline, self.sequence))
    }
}

#[derive(Default)]
struct Usage {
    packets: usize,
    bytes: usize,
}

#[derive(Default)]
struct FlowState {
    packets: usize,
    tail: Option<Instant>,
    in_flight: usize,
    in_flight_tail: Option<Instant>,
}

pub(crate) struct DelayQueue {
    heap: BinaryHeap<Entry>,
    flows: HashMap<FlowKey, FlowState>,
    pids: HashMap<Option<u32>, Usage>,
    usage: Usage,
    next_sequence: u64,
    max_bytes: usize,
    max_packets: usize,
    max_pid_bytes: usize,
    max_pid_packets: usize,
}

impl Default for DelayQueue {
    fn default() -> Self {
        Self {
            heap: BinaryHeap::new(),
            flows: HashMap::new(),
            pids: HashMap::new(),
            usage: Usage::default(),
            next_sequence: 0,
            max_bytes: 64 * 1024 * 1024,
            max_packets: 16384,
            max_pid_bytes: 8 * 1024 * 1024,
            max_pid_packets: 4096,
        }
    }
}

impl DelayQueue {
    pub(crate) fn has_flow(&self, flow: &FlowKey) -> bool {
        self.flows.contains_key(flow)
    }

    pub(crate) fn enqueue(&mut self, packet: PendingPacket, deadline: Instant) -> bool {
        let bytes = packet.bytes.len();
        let pid_usage = self.pids.get(&packet.pid);
        if self.usage.packets >= self.max_packets
            || bytes > self.max_bytes.saturating_sub(self.usage.bytes)
            || pid_usage.map_or(0, |usage| usage.packets) >= self.max_pid_packets
            || bytes
                > self
                    .max_pid_bytes
                    .saturating_sub(pid_usage.map_or(0, |usage| usage.bytes))
        {
            return false;
        }

        let flow = self.flows.entry(packet.flow).or_default();
        let deadline = flow.tail.map_or(deadline, |tail| tail.max(deadline));
        flow.tail = Some(deadline);
        flow.packets += 1;
        let pid_usage = self.pids.entry(packet.pid).or_default();
        pid_usage.packets += 1;
        pid_usage.bytes += bytes;
        self.usage.packets += 1;
        self.usage.bytes += bytes;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).expect("packet sequence exhausted");
        self.heap.push(Entry {
            packet,
            deadline,
            sequence,
        });
        true
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.heap.peek().map(|entry| entry.deadline)
    }

    pub(crate) fn pop_due(&mut self, now: Instant) -> Option<PendingPacket> {
        if self.heap.peek()?.deadline > now {
            return None;
        }
        let entry = self.heap.pop()?;
        let flow = self.flows.get_mut(&entry.packet.flow).unwrap();
        flow.in_flight += 1;
        flow.in_flight_tail = Some(entry.deadline);
        Some(entry.packet)
    }

    // The sender calls finish exactly once after sending or discarding a popped packet.
    pub(crate) fn finish(&mut self, packet: &PendingPacket) {
        let bytes = packet.bytes.len();
        self.usage.packets -= 1;
        self.usage.bytes -= bytes;
        let pid_usage = self.pids.get_mut(&packet.pid).unwrap();
        pid_usage.packets -= 1;
        pid_usage.bytes -= bytes;
        if pid_usage.packets == 0 {
            self.pids.remove(&packet.pid);
        }
        let flow = self.flows.get_mut(&packet.flow).unwrap();
        flow.packets -= 1;
        flow.in_flight -= 1;
        if flow.in_flight == 0 {
            flow.in_flight_tail = None;
        }
        if flow.packets == 0 {
            self.flows.remove(&packet.flow);
        }
    }

    pub(crate) fn release_matching(
        &mut self,
        now: Instant,
        mut predicate: impl FnMut(&PendingPacket) -> bool,
    ) {
        let mut entries = std::mem::take(&mut self.heap).into_vec();
        entries.sort_unstable_by_key(|entry| entry.sequence);
        for flow in self.flows.values_mut() {
            flow.tail = flow.in_flight_tail;
        }
        for entry in &mut entries {
            if predicate(&entry.packet) {
                entry.deadline = now;
            }
            let flow = self.flows.get_mut(&entry.packet.flow).unwrap();
            // Rebuild in capture order: clearing a later packet cannot overtake its predecessor.
            entry.deadline = flow
                .tail
                .map_or(entry.deadline, |tail| tail.max(entry.deadline));
            flow.tail = Some(entry.deadline);
        }
        self.heap = BinaryHeap::from(entries);
    }

    pub(crate) fn packet_count(&self) -> usize {
        self.usage.packets
    }

    pub(crate) fn byte_count(&self) -> usize {
        self.usage.bytes
    }

    #[cfg(test)]
    fn with_limits(bytes: usize, packets: usize, pid_bytes: usize, pid_packets: usize) -> Self {
        Self {
            max_bytes: bytes,
            max_packets: packets,
            max_pid_bytes: pid_bytes,
            max_pid_packets: pid_packets,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Protocol;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn packet(id: u8, flow: u16, pid: Option<u32>, size: usize) -> PendingPacket {
        let mut address = WinDivertAddress::default();
        address.timestamp = id as i64;
        PendingPacket {
            bytes: vec![id; size],
            address,
            pid,
            direction: Direction::Upload,
            charge_len: 0,
            flow: FlowKey {
                source: Ipv4Addr::LOCALHOST.into(),
                destination: Ipv4Addr::new(192, 0, 2, 1).into(),
                protocol: Protocol::Tcp,
                source_port: flow,
                destination_port: 443,
            },
        }
    }

    fn take(queue: &mut DelayQueue, now: Instant, id: u8) {
        let packet = queue.pop_due(now).expect("expected due packet");
        assert_eq!(packet.bytes[0], id);
        queue.finish(&packet);
    }

    #[test]
    fn waits_until_deadline_and_preserves_packet_metadata() {
        let now = Instant::now();
        let due = now + Duration::from_millis(100);
        let mut queue = DelayQueue::default();
        assert_eq!(queue.next_deadline(), None);
        assert!(queue.enqueue(packet(1, 1, Some(10), 40), due));
        assert_eq!(queue.next_deadline(), Some(due));
        assert!(queue.pop_due(now).is_none());
        let packet = queue.pop_due(due).unwrap();
        assert_eq!(packet.address.timestamp, 1);
        assert_eq!(packet.direction, Direction::Upload);
        assert_eq!(packet.charge_len, 0);
        assert_eq!(packet.pid, Some(10));
        assert_eq!(queue.packet_count(), 1);
        assert_eq!(queue.byte_count(), 40);
        assert_eq!(queue.next_deadline(), None);
        queue.finish(&packet);
        assert_eq!(queue.packet_count(), 0);
        assert_eq!(queue.byte_count(), 0);
        assert!(queue.flows.is_empty());
        assert!(queue.pids.is_empty());
    }

    #[test]
    fn equal_deadlines_use_capture_order_across_flows() {
        let now = Instant::now();
        let mut queue = DelayQueue::default();
        for id in 1..=3 {
            assert!(queue.enqueue(packet(id, id as u16, None, 1), now));
        }
        for id in 1..=3 {
            take(&mut queue, now, id);
        }
    }

    #[test]
    fn earlier_other_flow_does_not_wait_for_delayed_flow() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut queue = DelayQueue::default();
        assert!(queue.enqueue(packet(1, 1, None, 1), later));
        assert!(queue.enqueue(packet(2, 2, None, 1), now));
        take(&mut queue, now, 2);
        assert!(queue.pop_due(now).is_none());
        take(&mut queue, later, 1);
    }

    #[test]
    fn same_flow_shorter_new_delay_cannot_overtake() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut queue = DelayQueue::default();
        assert!(queue.enqueue(packet(1, 1, None, 1), later));
        assert!(queue.enqueue(packet(2, 1, None, 1), now));
        assert!(queue.pop_due(now).is_none());
        take(&mut queue, later, 1);
        take(&mut queue, later, 2);
    }

    #[test]
    fn popped_packet_keeps_flow_and_all_capacity_until_finish() {
        let now = Instant::now();
        let mut queue = DelayQueue::with_limits(1, 1, 1, 1);
        let first = packet(1, 1, None, 1);
        let flow = first.flow;
        assert!(queue.enqueue(first, now));
        let first = queue.pop_due(now).unwrap();
        assert!(queue.has_flow(&flow));
        assert_eq!((queue.packet_count(), queue.byte_count()), (1, 1));
        assert!(!queue.enqueue(packet(2, 2, Some(2), 1), now));
        queue.finish(&first);
        assert!(!queue.has_flow(&flow));
        assert!(queue.enqueue(packet(3, 2, Some(2), 1), now));
        take(&mut queue, now, 3);
    }

    #[test]
    fn in_flight_flow_remains_present_when_zero_delay_follower_arrives() {
        let now = Instant::now();
        let mut queue = DelayQueue::default();
        let first = packet(1, 1, None, 1);
        let flow = first.flow;
        assert!(queue.enqueue(first, now));
        let first = queue.pop_due(now).unwrap();
        assert!(queue.has_flow(&flow));
        assert!(queue.enqueue(packet(2, 1, None, 1), now));
        queue.finish(&first);
        assert!(queue.has_flow(&flow));
        take(&mut queue, now, 2);
        assert!(!queue.has_flow(&flow));
    }

    #[test]
    fn global_packet_and_byte_limits_are_independent_and_inclusive() {
        let now = Instant::now();
        let mut packets = DelayQueue::with_limits(100, 2, 100, 10);
        assert!(packets.enqueue(packet(1, 1, Some(1), 1), now));
        assert!(packets.enqueue(packet(2, 2, Some(2), 1), now));
        assert!(!packets.enqueue(packet(3, 3, Some(3), 1), now));
        assert_eq!((packets.packet_count(), packets.byte_count()), (2, 2));

        let mut bytes = DelayQueue::with_limits(3, 10, 100, 10);
        assert!(bytes.enqueue(packet(1, 1, Some(1), 2), now));
        assert!(!bytes.enqueue(packet(2, 2, Some(2), 2), now));
        assert!(bytes.enqueue(packet(3, 3, Some(3), 1), now));
        assert!(!bytes.enqueue(packet(4, 4, Some(4), 1), now));
        assert_eq!((bytes.packet_count(), bytes.byte_count()), (2, 3));
        take(&mut bytes, now, 1);
        assert!(bytes.enqueue(packet(5, 5, Some(5), 2), now));
    }

    #[test]
    fn pid_limits_include_in_flight_and_unknown_pid_shares_one_bucket() {
        let now = Instant::now();
        for pid in [Some(1), None] {
            let mut queue = DelayQueue::with_limits(100, 10, 3, 2);
            assert!(queue.enqueue(packet(1, 1, pid, 2), now));
            let first = queue.pop_due(now).unwrap();
            assert!(!queue.enqueue(packet(2, 2, pid, 2), now));
            assert!(queue.enqueue(packet(3, 3, pid, 1), now));
            assert!(!queue.enqueue(packet(4, 4, pid, 0), now));
            assert!(queue.enqueue(packet(5, 5, Some(2), 3), now));
            queue.finish(&first);
            assert!(queue.enqueue(packet(6, 6, pid, 2), now));
        }
    }

    #[test]
    fn zero_limits_reject_without_creating_metadata() {
        let now = Instant::now();
        for mut queue in [
            DelayQueue::with_limits(100, 0, 100, 10),
            DelayQueue::with_limits(100, 10, 100, 0),
            DelayQueue::with_limits(0, 10, 100, 10),
            DelayQueue::with_limits(100, 10, 0, 10),
        ] {
            assert!(!queue.enqueue(packet(1, 1, None, 1), now));
            assert_eq!((queue.packet_count(), queue.byte_count()), (0, 0));
            assert!(queue.flows.is_empty());
            assert!(queue.pids.is_empty());
        }
    }

    #[test]
    fn clear_releases_in_capture_order_and_shortens_tail_for_new_packets() {
        let now = Instant::now();
        let later = now + Duration::from_secs(5);
        let mut queue = DelayQueue::default();
        assert!(queue.enqueue(packet(1, 1, Some(1), 1), later));
        assert!(queue.enqueue(packet(2, 1, Some(1), 1), later));
        queue.release_matching(now, |_| true);
        assert!(queue.enqueue(packet(3, 1, Some(1), 1), now));
        for id in 1..=3 {
            take(&mut queue, now, id);
        }
        assert!(queue.flows.is_empty());
    }

    #[test]
    fn selected_later_packet_still_waits_for_its_unselected_predecessor() {
        let now = Instant::now();
        let later = now + Duration::from_secs(5);
        let mut queue = DelayQueue::default();
        assert!(queue.enqueue(packet(1, 1, Some(1), 1), later));
        assert!(queue.enqueue(packet(2, 1, Some(2), 1), later));
        assert!(queue.enqueue(packet(3, 2, Some(2), 1), later));
        queue.release_matching(now, |packet| packet.pid == Some(2));
        take(&mut queue, now, 3);
        assert!(queue.pop_due(now).is_none());
        take(&mut queue, later, 1);
        take(&mut queue, later, 2);
    }

    #[test]
    fn release_preserves_unselected_deadline_and_other_flows() {
        let now = Instant::now();
        let later = now + Duration::from_secs(5);
        let mut queue = DelayQueue::default();
        assert!(queue.enqueue(packet(1, 1, Some(1), 1), later));
        assert!(queue.enqueue(packet(2, 1, Some(2), 1), later));
        assert!(queue.enqueue(packet(3, 2, Some(3), 1), later));
        queue.release_matching(now, |packet| packet.pid == Some(1));
        take(&mut queue, now, 1);
        assert_eq!(queue.next_deadline(), Some(later));
        assert!(queue.pop_due(now).is_none());
        take(&mut queue, later, 2);
        take(&mut queue, later, 3);
    }

    #[test]
    fn release_with_in_flight_packet_removes_old_queued_tail() {
        let now = Instant::now();
        let later = now + Duration::from_secs(5);
        let mut queue = DelayQueue::default();
        assert!(queue.enqueue(packet(1, 1, None, 1), now));
        let first = queue.pop_due(now).unwrap();
        assert!(queue.enqueue(packet(2, 1, None, 1), later));
        queue.release_matching(now, |_| true);
        assert!(queue.enqueue(packet(3, 1, None, 1), now));
        assert_eq!(queue.next_deadline(), Some(now));
        queue.finish(&first);
        take(&mut queue, now, 2);
        take(&mut queue, now, 3);
        assert!(queue.flows.is_empty());
    }

    #[test]
    fn release_and_finish_handle_multiple_in_flight_packets() {
        let now = Instant::now();
        let mut queue = DelayQueue::default();
        assert!(queue.enqueue(packet(1, 1, None, 1), now));
        assert!(queue.enqueue(packet(2, 1, None, 1), now));
        let first = queue.pop_due(now).unwrap();
        let second = queue.pop_due(now).unwrap();
        queue.release_matching(now, |_| true);
        queue.finish(&second);
        assert!(queue.has_flow(&first.flow));
        assert!(queue.enqueue(packet(3, 1, None, 1), now));
        queue.finish(&first);
        take(&mut queue, now, 3);
        assert!(queue.pids.is_empty());
        assert!(queue.flows.is_empty());
    }
}
