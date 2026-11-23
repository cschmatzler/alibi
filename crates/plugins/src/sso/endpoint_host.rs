//! Literal host admission matching the reference's public-routability policy.
use std::net::{IpAddr, Ipv4Addr};
pub(crate) fn public(host: &str) -> bool {
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
            {
                return false;
            }
            // The well-known NAT64 prefix 64:ff9b::/96 only represents global
            // IPv4 (RFC 6052), so it takes the class of its embedded address.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return public_ipv4(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])));
            }
            // Only global unicast 2000::/3 is publicly allocated; the rest of
            // the space is IETF-reserved.
            if s[0] & 0xe000 != 0x2000
                || s[..2] == [0x2001, 0xdb8]
                || s[0] == 0x3fff && s[1] & 0xf000 == 0
                || s[..3] == [0x2001, 2, 0]
                || s[..2] == [0x2001, 0]
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

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::public;

    #[test]
    fn ipv6_is_public_only_inside_global_unicast() {
        for host in [
            "2000::1",
            "3ffe::1",
            "3fff:1000::1",
            "[2a00:1450:4001:828::200e]",
            "2002:808:808::1",
        ] {
            assert!(public(host), "{host}");
        }
        for host in [
            "100:0:0:1::1",
            "200::1",
            "4000::1",
            "8000::1",
            "f000::1",
            "fe00::1",
            "fec0::1",
            "5f00::1",
            "0:1::1",
            "1::1",
            "::200:5efe:7f00:1",
            // IPv4-translated (RFC 2765), distinct from IPv4-mapped.
            "::ffff:0:7f00:1",
            // A dotted tail after a non-mapped prefix is not IPv4-mapped.
            "::ffff:808:127.0.0.1",
            "64:ff9b:1::1",
            "2001:db8::1",
            "3fff::1",
            "2001:2::1",
            "2001::1",
            "2002:7f00:1::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!public(host), "{host}");
        }
    }

    #[test]
    fn nat64_takes_the_class_of_its_embedded_ipv4() {
        assert!(public("64:ff9b::808:808"));
        assert!(public("64:ff9b::5db8:d822"));
        assert!(!public("64:ff9b::7f00:1"));
        assert!(!public("64:ff9b::a9fe:a9fe"));
        assert!(!public("64:ff9b::"));
    }
}
// LCOV_EXCL_STOP
