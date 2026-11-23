use super::IpAddressConfig;
use std::{collections::HashMap, net::IpAddr};

impl IpAddressConfig {
    /// Resolve a forwarded client address using the initialized IP policy.
    ///
    /// Trusted proxy matching uses the full address before IPv6 grouping.
    /// A malformed hop fails that header closed; the next configured header
    /// may still resolve an address. Tracking opt-out also disables fallback.
    #[must_use]
    pub fn resolve_ip(&self, headers: &HashMap<String, String>) -> Option<String> {
        if self.disable_ip_tracking {
            return None;
        }
        let proxies = self
            .trusted_proxies
            .iter()
            .filter_map(|value| Network::parse(value))
            .collect::<Vec<_>>();
        self.headers
            .iter()
            .find_map(|name| {
                headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .and_then(|(_, value)| self.resolve_header(value, &proxies))
            })
            .or_else(|| self.localhost_fallback.then(|| "127.0.0.1".to_owned()))
    }

    fn resolve_header(&self, value: &str, proxies: &[Network]) -> Option<String> {
        let hops = value
            .split(',')
            .map(|hop| {
                hop.trim_matches(|character: char| {
                    (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
                })
            })
            .filter(|hop| !hop.is_empty())
            .collect::<Vec<_>>();
        if proxies.is_empty() {
            return if hops.len() == 1 {
                Address::parse(hops.first()?).map(|ip| ip.normalize(self.ipv6_subnet))
            } else {
                None
            };
        }
        for hop in hops.iter().rev() {
            let ip = Address::parse(hop)?;
            if !proxies.iter().any(|proxy| proxy.contains(&ip.bytes)) {
                return Some(ip.normalize(self.ipv6_subnet));
            }
        }
        None
    }
}

struct Address {
    bytes: Vec<u8>,
    ipv6_groups: Option<[u16; 8]>,
}

impl Address {
    fn parse(value: &str) -> Option<Self> {
        match value.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => Some(Self {
                bytes: ip.octets().to_vec(),
                ipv6_groups: None,
            }),
            IpAddr::V6(ip) => {
                // The published parser recognizes hexadecimal mapped addresses
                // only when the marker is spelled `ffff`; dotted mapped
                // addresses are recognized regardless of marker case.
                if let Some(mapped) = ip.to_ipv4_mapped().filter(|_| {
                    value.contains('.') || value.split(':').any(|group| group == "ffff")
                }) {
                    return Some(Self {
                        bytes: mapped.octets().to_vec(),
                        ipv6_groups: None,
                    });
                }
                // The parsed segments include both halves of any dotted tail.
                Some(Self {
                    bytes: ip.octets().to_vec(),
                    ipv6_groups: Some(ip.segments()),
                })
            }
        }
    }

    fn normalize(self, prefix: f64) -> String {
        let Some(groups) = self.ipv6_groups else {
            return self
                .bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".");
        };
        let mut bits = if prefix.is_nan() {
            128.0
        } else {
            prefix.floor().clamp(0.0, 128.0)
        };
        groups
            .into_iter()
            .map(|group| {
                let retained = (0..16_u16)
                    .filter(|bit| f64::from(*bit) < bits)
                    .fold(0_u16, |mask, bit| mask | (1 << (15 - bit)));
                bits -= 16.0;
                format!("{:04x}", group & retained)
            })
            .collect::<Vec<_>>()
            .join(":")
    }
}

struct Network {
    bytes: Vec<u8>,
    prefix: u8,
}

impl Network {
    fn parse(value: &str) -> Option<Self> {
        let (ip, prefix) = value
            .rsplit_once('/')
            .map_or((value, None), |(ip, prefix)| (ip, Some(prefix)));
        let address = Address::parse(ip)?;
        let maximum = u8::try_from(address.bytes.len() * 8).ok()?;
        let prefix = if let Some(prefix) = prefix {
            if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= maximum)?
        } else {
            maximum
        };
        Some(Self {
            bytes: address.bytes,
            prefix,
        })
    }

    fn contains(&self, bytes: &[u8]) -> bool {
        if bytes.len() != self.bytes.len() {
            return false;
        }
        let mut remaining = self.prefix;
        for (ip, network) in bytes.iter().zip(&self.bytes) {
            if remaining == 0 {
                break;
            }
            let mask = u8::MAX << (8 - remaining.min(8));
            if ip & mask != network & mask {
                return false;
            }
            remaining = remaining.saturating_sub(8);
        }
        true
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_chains_select_the_first_untrusted_hop_from_the_right() {
        for (proxies, chain, expected) in [
            (vec![], "198.51.100.7", Some("198.51.100.7")),
            (vec![], "198.51.100.7, 10.0.0.1", None),
            (vec!["invalid"], "198.51.100.7, 10.0.0.1", None),
            (
                vec!["10.0.0.0/8"],
                "203.0.113.99, 198.51.100.7, 10.0.0.1",
                Some("198.51.100.7"),
            ),
            (vec!["10.0.0.0/8"], "10.0.0.2, 10.0.0.1", None),
            (
                vec!["10.0.0.0/8"],
                "198.51.100.7, malformed, 10.0.0.1",
                None,
            ),
        ] {
            let config = IpAddressConfig {
                trusted_proxies: proxies.into_iter().map(str::to_owned).collect(),
                localhost_fallback: false,
                ..Default::default()
            };
            let headers = HashMap::from([("X-Forwarded-For".into(), chain.into())]);
            assert_eq!(config.resolve_ip(&headers).as_deref(), expected, "{chain}");
        }
    }

    #[test]
    fn malformed_header_falls_back_but_tracking_opt_out_never_does() {
        let mut config = IpAddressConfig {
            headers: vec!["x-forwarded-for".into(), "x-real-ip".into()],
            trusted_proxies: vec!["10.0.0.0/8".into()],
            localhost_fallback: true,
            ..Default::default()
        };
        let headers = HashMap::from([
            (
                "x-forwarded-for".into(),
                "198.51.100.7, bad-hop, 10.0.0.1".into(),
            ),
            ("x-real-ip".into(), "203.0.113.8".into()),
        ]);
        assert_eq!(config.resolve_ip(&headers).as_deref(), Some("203.0.113.8"));
        assert_eq!(
            config.resolve_ip(&HashMap::new()).as_deref(),
            Some("127.0.0.1")
        );
        config.disable_ip_tracking = true;
        assert_eq!(config.resolve_ip(&headers), None);
        assert_eq!(config.resolve_ip(&HashMap::new()), None);
    }

    #[test]
    fn ipv6_proxy_trust_is_checked_before_grouping_the_client_address() {
        let config = IpAddressConfig {
            trusted_proxies: vec!["2001:db8:abcd:12::1/128".into()],
            ipv6_subnet: 64.0,
            localhost_fallback: false,
            ..Default::default()
        };
        let headers = HashMap::from([(
            "x-forwarded-for".into(),
            "203.0.113.99, 2001:db8:abcd:12::2, 2001:db8:abcd:12::1".into(),
        )]);
        assert_eq!(
            config.resolve_ip(&headers).as_deref(),
            Some("2001:0db8:abcd:0012:0000:0000:0000:0000")
        );
    }

    #[test]
    fn dotted_ipv4_tails_expand_into_two_hex_groups() {
        let config = IpAddressConfig {
            ipv6_subnet: 128.0,
            localhost_fallback: false,
            ..Default::default()
        };
        for (address, expected) in [
            // Not IPv4-mapped: the dotted tail follows a non-mapped prefix.
            (
                "::ffff:808:127.0.0.1",
                "0000:0000:0000:0000:ffff:0808:7f00:0001",
            ),
            (
                "::ffff:808:7f00:1",
                "0000:0000:0000:0000:ffff:0808:7f00:0001",
            ),
            (
                "64:ff9b::192.0.2.33",
                "0064:ff9b:0000:0000:0000:0000:c000:0221",
            ),
            ("::ffff:192.0.2.1", "192.0.2.1"),
        ] {
            let headers = HashMap::from([("x-forwarded-for".into(), address.into())]);
            assert_eq!(config.resolve_ip(&headers).as_deref(), Some(expected), "{address}");
        }
        // CIDR matching reads the expanded groups too.
        let config = IpAddressConfig {
            trusted_proxies: vec!["64:ff9b::c000:200/120".into()],
            localhost_fallback: false,
            ..Default::default()
        };
        let headers = HashMap::from([(
            "x-forwarded-for".into(),
            "198.51.100.7, 64:ff9b::192.0.2.33".into(),
        )]);
        assert_eq!(config.resolve_ip(&headers).as_deref(), Some("198.51.100.7"));
    }
}
// LCOV_EXCL_STOP
