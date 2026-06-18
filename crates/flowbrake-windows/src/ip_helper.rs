use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

use flowbrake_core::ProcessInfo;

use crate::packet::Protocol;
use crate::process::process_name;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        p_tcp_table: *mut c_void,
        pdw_size: *mut u32,
        b_order: i32,
        ul_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        p_udp_table: *mut c_void,
        pdw_size: *mut u32,
        b_order: i32,
        ul_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}

#[derive(Debug, Clone, Default)]
pub struct PortPidMap {
    tcp_v4: HashMap<u16, u32>,
    tcp_v6: HashMap<u16, u32>,
    udp_v4: HashMap<u16, u32>,
    udp_v6: HashMap<u16, u32>,
}

impl PortPidMap {
    pub fn refresh(ipv6_enabled: bool) -> Self {
        Self {
            tcp_v4: build_tcp_port_pid_map(AF_INET),
            tcp_v6: if ipv6_enabled {
                build_tcp_port_pid_map(AF_INET6)
            } else {
                HashMap::new()
            },
            udp_v4: build_udp_port_pid_map(AF_INET),
            udp_v6: if ipv6_enabled {
                build_udp_port_pid_map(AF_INET6)
            } else {
                HashMap::new()
            },
        }
    }

    pub fn pid_for(&self, protocol: Protocol, port: u16, is_ipv6: bool) -> Option<u32> {
        let map = match (protocol, is_ipv6) {
            (Protocol::Tcp, false) => &self.tcp_v4,
            (Protocol::Tcp, true) => &self.tcp_v6,
            (Protocol::Udp, false) => &self.udp_v4,
            (Protocol::Udp, true) => &self.udp_v6,
        };
        map.get(&port).copied()
    }

    pub fn pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.tcp_v4
            .values()
            .chain(self.tcp_v6.values())
            .chain(self.udp_v4.values())
            .chain(self.udp_v6.values())
            .copied()
    }
}

pub fn get_network_processes(
    active_rule_pids: impl IntoIterator<Item = u32>,
    ipv6_enabled: bool,
) -> Vec<ProcessInfo> {
    let map = PortPidMap::refresh(ipv6_enabled);
    let mut pids: HashSet<u32> = map.pids().filter(|pid| *pid > 0).collect();
    pids.extend(active_rule_pids.into_iter().filter(|pid| *pid > 0));

    let mut processes: Vec<ProcessInfo> = pids
        .into_iter()
        .filter_map(|pid| process_name(pid).map(|name| ProcessInfo { pid, name }))
        .collect();

    processes.sort_by_key(|process| process.name.to_lowercase());
    processes
}

fn build_tcp_port_pid_map(af: u32) -> HashMap<u16, u32> {
    let Some((row_size, local_port_offset, owning_pid_offset)) = tcp_row_layout(af) else {
        return HashMap::new();
    };

    let mut size = 0u32;
    let status = unsafe {
        GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            af,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return HashMap::new();
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            af,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != 0 {
        return HashMap::new();
    }
    parse_owner_pid_rows(&buffer, row_size, local_port_offset, owning_pid_offset)
}

fn build_udp_port_pid_map(af: u32) -> HashMap<u16, u32> {
    let Some((row_size, local_port_offset, owning_pid_offset)) = udp_row_layout(af) else {
        return HashMap::new();
    };

    let mut size = 0u32;
    let status =
        unsafe { GetExtendedUdpTable(null_mut(), &mut size, 0, af, UDP_TABLE_OWNER_PID, 0) };
    if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return HashMap::new();
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            af,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if status != 0 {
        return HashMap::new();
    }
    parse_owner_pid_rows(&buffer, row_size, local_port_offset, owning_pid_offset)
}

fn tcp_row_layout(af: u32) -> Option<(usize, usize, usize)> {
    match af {
        AF_INET => Some((24, 8, 20)),
        AF_INET6 => Some((56, 20, 52)),
        _ => None,
    }
}

fn udp_row_layout(af: u32) -> Option<(usize, usize, usize)> {
    match af {
        AF_INET => Some((12, 4, 8)),
        AF_INET6 => Some((28, 20, 24)),
        _ => None,
    }
}

pub fn parse_tcp_owner_pid_table(buffer: &[u8]) -> HashMap<u16, u32> {
    parse_owner_pid_rows(buffer, 24, 8, 20)
}

pub fn parse_tcp6_owner_pid_table(buffer: &[u8]) -> HashMap<u16, u32> {
    parse_owner_pid_rows(buffer, 56, 20, 52)
}

pub fn parse_udp_owner_pid_table(buffer: &[u8]) -> HashMap<u16, u32> {
    parse_owner_pid_rows(buffer, 12, 4, 8)
}

pub fn parse_udp6_owner_pid_table(buffer: &[u8]) -> HashMap<u16, u32> {
    parse_owner_pid_rows(buffer, 28, 20, 24)
}

fn parse_owner_pid_rows(
    buffer: &[u8],
    row_size: usize,
    local_port_offset: usize,
    owning_pid_offset: usize,
) -> HashMap<u16, u32> {
    let mut map = HashMap::new();
    if buffer.len() < size_of::<u32>() {
        return map;
    }

    let count = u32::from_ne_bytes(buffer[0..4].try_into().unwrap()) as usize;
    let mut offset = 4usize;
    for _ in 0..count {
        let end = offset + row_size;
        if end > buffer.len() {
            break;
        }

        let local_port = u32::from_ne_bytes(
            buffer[offset + local_port_offset..offset + local_port_offset + 4]
                .try_into()
                .unwrap(),
        );
        let owning_pid = u32::from_ne_bytes(
            buffer[offset + owning_pid_offset..offset + owning_pid_offset + 4]
                .try_into()
                .unwrap(),
        );
        let port = u16::from_be((local_port & 0xffff) as u16);
        if owning_pid > 0 && port > 0 {
            map.insert(port, owning_pid);
        }
        offset = end;
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_owner_pid_rows_like_csharp_offsets() {
        let mut table = vec![0u8; 4 + 24];
        table[0..4].copy_from_slice(&1u32.to_ne_bytes());
        table[4 + 8..4 + 12].copy_from_slice(&(8080u16.to_be() as u32).to_ne_bytes());
        table[4 + 20..4 + 24].copy_from_slice(&123u32.to_ne_bytes());

        let map = parse_tcp_owner_pid_table(&table);
        assert_eq!(map.get(&8080), Some(&123));
    }

    #[test]
    fn parses_tcp6_owner_pid_rows() {
        let mut table = vec![0u8; 4 + 56];
        table[0..4].copy_from_slice(&1u32.to_ne_bytes());
        table[4 + 20..4 + 24].copy_from_slice(&(8443u16.to_be() as u32).to_ne_bytes());
        table[4 + 52..4 + 56].copy_from_slice(&456u32.to_ne_bytes());

        let map = parse_tcp6_owner_pid_table(&table);
        assert_eq!(map.get(&8443), Some(&456));
    }

    #[test]
    fn parses_udp_owner_pid_rows_like_csharp_offsets() {
        let mut table = vec![0u8; 4 + 12];
        table[0..4].copy_from_slice(&1u32.to_ne_bytes());
        table[4 + 4..4 + 8].copy_from_slice(&(5353u16.to_be() as u32).to_ne_bytes());
        table[4 + 8..4 + 12].copy_from_slice(&456u32.to_ne_bytes());

        let map = parse_udp_owner_pid_table(&table);
        assert_eq!(map.get(&5353), Some(&456));
    }

    #[test]
    fn parses_udp6_owner_pid_rows() {
        let mut table = vec![0u8; 4 + 28];
        table[0..4].copy_from_slice(&1u32.to_ne_bytes());
        table[4 + 20..4 + 24].copy_from_slice(&(5353u16.to_be() as u32).to_ne_bytes());
        table[4 + 24..4 + 28].copy_from_slice(&789u32.to_ne_bytes());

        let map = parse_udp6_owner_pid_table(&table);
        assert_eq!(map.get(&5353), Some(&789));
    }

    #[test]
    fn port_pid_map_keeps_ipv4_and_ipv6_entries_separate() {
        let map = PortPidMap {
            tcp_v4: HashMap::from([(443, 100)]),
            tcp_v6: HashMap::from([(443, 200)]),
            ..PortPidMap::default()
        };

        assert_eq!(map.pid_for(Protocol::Tcp, 443, false), Some(100));
        assert_eq!(map.pid_for(Protocol::Tcp, 443, true), Some(200));
        assert_eq!(map.pids().collect::<HashSet<_>>(), HashSet::from([100, 200]));
    }
}
