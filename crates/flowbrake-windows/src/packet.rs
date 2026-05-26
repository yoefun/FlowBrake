use flowbrake_core::Direction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Packet {
    pub protocol: Protocol,
    pub source_port: u16,
    pub destination_port: u16,
    pub total_len: usize,
    pub payload_len: usize,
}

impl Ipv4Packet {
    pub fn parse(packet: &[u8]) -> Option<Self> {
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
        let transport_header_len = match protocol {
            Protocol::Tcp => {
                if ihl + 20 > total_len {
                    return None;
                }
                let tcp_header_len = ((packet[ihl + 12] >> 4) as usize) * 4;
                if tcp_header_len < 20 || ihl + tcp_header_len > total_len {
                    return None;
                }
                tcp_header_len
            }
            Protocol::Udp => {
                if ihl + 8 > total_len {
                    return None;
                }
                8
            }
        };

        Some(Self {
            protocol,
            source_port,
            destination_port,
            total_len,
            payload_len: total_len.saturating_sub(ihl + transport_header_len),
        })
    }

    pub fn local_port(self, direction: Direction) -> u16 {
        match direction {
            Direction::Upload => self.source_port,
            Direction::Download => self.destination_port,
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

        let parsed = Ipv4Packet::parse(&packet).unwrap();
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

        let parsed = Ipv4Packet::parse(&packet).unwrap();
        assert_eq!(parsed.protocol, Protocol::Udp);
        assert_eq!(parsed.payload_len, 4);
    }

    #[test]
    fn rejects_non_tcp_udp_and_ipv6() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        assert!(Ipv4Packet::parse(&packet).is_none());

        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 1;
        assert!(Ipv4Packet::parse(&packet).is_none());
    }
}
