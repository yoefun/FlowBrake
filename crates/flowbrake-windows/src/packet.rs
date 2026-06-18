use flowbrake_core::Direction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacket {
    pub protocol: Protocol,
    pub source_port: u16,
    pub destination_port: u16,
    pub total_len: usize,
    pub payload_len: usize,
}

pub type Ipv4Packet = IpPacket;

impl IpPacket {
    pub fn parse(packet: &[u8], is_ipv6: bool) -> Option<Self> {
        if is_ipv6 {
            parse_ipv6(packet)
        } else {
            parse_ipv4(packet)
        }
    }

    pub fn local_port(self, direction: Direction) -> u16 {
        match direction {
            Direction::Upload => self.source_port,
            Direction::Download => self.destination_port,
        }
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<IpPacket> {
    if packet.len() < 24 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl + 4 > packet.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || total_len > packet.len() {
        return None;
    }
    let protocol = match packet[9] {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    let source_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let destination_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let transport_header_len = transport_header_len(protocol, packet, ihl, total_len)?;

    Some(IpPacket {
        protocol,
        source_port,
        destination_port,
        total_len,
        payload_len: total_len.saturating_sub(ihl + transport_header_len),
    })
}

fn parse_ipv6(packet: &[u8]) -> Option<IpPacket> {
    if packet.len() < 40 {
        return None;
    }
    if packet[0] >> 4 != 6 {
        return None;
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = 40usize.saturating_add(payload_len);
    if total_len > packet.len() {
        return None;
    }

    let (transport_offset, next_header) = ipv6_transport_offset(packet, total_len)?;
    let protocol = match next_header {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    if transport_offset + 4 > total_len {
        return None;
    }

    let source_port = u16::from_be_bytes([
        packet[transport_offset],
        packet[transport_offset + 1],
    ]);
    let destination_port = u16::from_be_bytes([
        packet[transport_offset + 2],
        packet[transport_offset + 3],
    ]);
    let transport_header_len = transport_header_len(protocol, packet, transport_offset, total_len)?;

    Some(IpPacket {
        protocol,
        source_port,
        destination_port,
        total_len,
        payload_len: total_len.saturating_sub(transport_offset + transport_header_len),
    })
}

fn ipv6_transport_offset(packet: &[u8], total_len: usize) -> Option<(usize, u8)> {
    let mut next_header = packet[6];
    let mut offset = 40usize;

    loop {
        match next_header {
            6 | 17 => return Some((offset, next_header)),
            0 | 43 | 44 | 60 => {
                if offset + 8 > total_len {
                    return None;
                }
                next_header = packet[offset];
                let header_len = (packet[offset + 1] as usize + 1) * 8;
                offset = offset.checked_add(header_len)?;
            }
            51 => {
                if offset + 8 > total_len {
                    return None;
                }
                next_header = packet[offset];
                let header_len = (packet[offset + 1] as usize + 2) * 4;
                offset = offset.checked_add(header_len)?;
            }
            _ => return None,
        }
    }
}

fn transport_header_len(
    protocol: Protocol,
    packet: &[u8],
    transport_offset: usize,
    total_len: usize,
) -> Option<usize> {
    match protocol {
        Protocol::Tcp => {
            if transport_offset + 20 > total_len {
                return None;
            }
            let tcp_header_len = ((packet[transport_offset + 12] >> 4) as usize) * 4;
            if tcp_header_len < 20 || transport_offset + tcp_header_len > total_len {
                return None;
            }
            Some(tcp_header_len)
        }
        Protocol::Udp => {
            if transport_offset + 8 > total_len {
                return None;
            }
            Some(8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_ports() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 6;
        packet[32] = 0x50;
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());

        let parsed = IpPacket::parse(&packet, false).unwrap();
        assert_eq!(parsed.protocol, Protocol::Tcp);
        assert_eq!(parsed.local_port(Direction::Upload), 1234);
        assert_eq!(parsed.local_port(Direction::Download), 443);
        assert_eq!(parsed.payload_len, 0);
    }

    #[test]
    fn computes_udp_payload_len() {
        let mut packet = vec![0u8; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&32u16.to_be_bytes());
        packet[9] = 17;
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());

        let parsed = IpPacket::parse(&packet, false).unwrap();
        assert_eq!(parsed.protocol, Protocol::Udp);
        assert_eq!(parsed.payload_len, 4);
    }

    #[test]
    fn rejects_non_tcp_udp_and_ipv6_version_mismatch() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        assert!(IpPacket::parse(&packet, false).is_none());

        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 1;
        assert!(IpPacket::parse(&packet, false).is_none());
    }

    #[test]
    fn parses_ipv6_tcp_ports() {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20u16.to_be_bytes());
        packet[6] = 6;
        packet[52] = 0x50;
        packet[40..42].copy_from_slice(&4321u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());

        let parsed = IpPacket::parse(&packet, true).unwrap();
        assert_eq!(parsed.protocol, Protocol::Tcp);
        assert_eq!(parsed.local_port(Direction::Upload), 4321);
        assert_eq!(parsed.local_port(Direction::Download), 443);
        assert_eq!(parsed.payload_len, 0);
    }

    #[test]
    fn parses_ipv6_udp_with_extension_header() {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20u16.to_be_bytes());
        packet[6] = 0;
        packet[40] = 17;
        packet[48..50].copy_from_slice(&2222u16.to_be_bytes());
        packet[50..52].copy_from_slice(&53u16.to_be_bytes());

        let parsed = IpPacket::parse(&packet, true).unwrap();
        assert_eq!(parsed.protocol, Protocol::Udp);
        assert_eq!(parsed.local_port(Direction::Upload), 2222);
        assert_eq!(parsed.payload_len, 4);
    }
}
