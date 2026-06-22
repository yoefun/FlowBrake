use flowbrake_core::{mib_ipv4_addr, mib_port, TcpConnection, TcpConnectionKey};
use thiserror::Error;

const MIB_TCP_STATE_DELETE_TCB: u32 = 12;
const ERROR_ACCESS_DENIED: u32 = 5;

#[repr(C)]
struct MibTcpRow {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
}

#[link(name = "iphlpapi")]
extern "system" {
    fn SetTcpEntry(p_tcp_row: *mut MibTcpRow) -> u32;
}

#[derive(Debug, Error)]
pub enum CloseTcpError {
    #[error("access denied")]
    AccessDenied,
    #[error("IPv6 TCP disconnect is not supported yet")]
    UnsupportedIpv6,
    #[error("Windows API error {0}")]
    OsError(u32),
}

pub fn close_tcp_connection(key: &TcpConnectionKey) -> Result<(), CloseTcpError> {
    if key.ipv6 {
        return Err(CloseTcpError::UnsupportedIpv6);
    }

    let local_addr = match key.local.addr {
        std::net::IpAddr::V4(addr) => mib_ipv4_addr(addr),
        std::net::IpAddr::V6(_) => return Err(CloseTcpError::UnsupportedIpv6),
    };
    let remote_addr = match key.remote.addr {
        std::net::IpAddr::V4(addr) => mib_ipv4_addr(addr),
        std::net::IpAddr::V6(_) => return Err(CloseTcpError::UnsupportedIpv6),
    };

    let mut row = MibTcpRow {
        state: MIB_TCP_STATE_DELETE_TCB,
        local_addr,
        local_port: mib_port(key.local.port),
        remote_addr,
        remote_port: mib_port(key.remote.port),
    };

    let status = unsafe { SetTcpEntry(&mut row) };
    if status == 0 {
        return Ok(());
    }
    if status == ERROR_ACCESS_DENIED {
        return Err(CloseTcpError::AccessDenied);
    }
    Err(CloseTcpError::OsError(status))
}

pub fn close_tcp_connections_for_pid(pid: u32, connections: &[TcpConnection]) -> usize {
    connections
        .iter()
        .filter(|connection| connection.pid == pid && connection.state.is_disconnectable())
        .filter_map(|connection| close_tcp_connection(&connection.key).ok())
        .count()
}

pub fn close_tcp_connections_for_pids(pids: &[u32], connections: &[TcpConnection]) -> usize {
    pids.iter()
        .map(|pid| close_tcp_connections_for_pid(*pid, connections))
        .sum()
}
