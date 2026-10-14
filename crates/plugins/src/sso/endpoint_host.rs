//! Literal host admission matching the reference's public-routability policy.
use std::net::{IpAddr, Ipv4Addr};
pub(super) fn public(host: &str) -> bool {
    let normalized = host
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    match normalized.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => public_ipv4(ip),
        Ok(IpAddr::V6(ip)) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_ipv4(mapped);
            }
            let s = ip.segments();
            if ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || s[0] & 0xffc0 == 0xfec0
                || s[..2] == [0x2001, 0xdb8]
                || s[..3] == [0x2001, 2, 0]
                || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
                || s[..3] == [0x64, 0xff9b, 1]
                || s[..2] == [0x2001, 0]
                || s[..4] == [0x100, 0, 0, 0]
                || s[0] == 0x3fff && s[1] & 0xf000 == 0
                || s[0] == 0x5f00
                || s[..6] == [0; 6]
            {
                return false;
            }
            if s[0] == 0x2002 {
                return public_ipv4(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])));
            }
            true
        }
        Err(_) => {
            !normalized.is_empty()
                && normalized != "localhost"
                && !normalized.ends_with(".localhost")
                && ![
                    "metadata.google.internal",
                    "metadata.goog",
                    "metadata",
                    "instance-data",
                    "instance-data.ec2.internal",
                ]
                .contains(&normalized.as_str())
        }
    }
}
fn public_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    ![
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16),
        ([100, 64, 0, 0], 10),
        ([192, 0, 2, 0], 24),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([198, 18, 0, 0], 15),
        ([224, 0, 0, 0], 4),
        ([192, 0, 0, 0], 24),
        ([192, 88, 99, 0], 24),
        ([240, 0, 0, 0], 4),
    ]
    .iter()
    .any(|(prefix, bits)| {
        let mask = u32::MAX << (32 - bits);
        value & mask == u32::from(Ipv4Addr::from(*prefix)) & mask
    })
}
