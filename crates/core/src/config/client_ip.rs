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
            .filter_map(|name| {
                headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .and_then(|(_, value)| self.resolve_header(value, &proxies))
            })
            .next()
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
    ipv6_groups: Option<Vec<String>>,
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
                let groups = expand_ipv6(value);
                let bytes = groups
                    .iter()
                    .flat_map(|group| segment(group).to_be_bytes())
                    .collect();
                Some(Self {
                    bytes,
                    ipv6_groups: Some(groups),
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
        if prefix.is_nan() || prefix >= 128.0 {
            return groups.join(":").to_lowercase();
        }
        let mut bits = prefix.floor().max(0.0);
        groups
            .into_iter()
            .map(|group| {
                let retained = (0..16_u16)
                    .filter(|bit| f64::from(*bit) < bits)
                    .fold(0_u16, |mask, bit| mask | (1 << (15 - bit)));
                bits -= 16.0;
                if retained == u16::MAX {
                    group.to_lowercase()
                } else {
                    format!("{:04x}", segment(&group) & retained)
                }
            })
            .collect::<Vec<_>>()
            .join(":")
    }
}

fn expand_ipv6(value: &str) -> Vec<String> {
    let raw = if let Some((left, right)) = value.split_once("::") {
        let mut left = left
            .split(':')
            .filter(|group| !group.is_empty())
            .collect::<Vec<_>>();
        let right = right
            .split(':')
            .filter(|group| !group.is_empty())
            .collect::<Vec<_>>();
        left.extend(std::iter::repeat_n("0", 8 - left.len() - right.len()));
        left.extend(right);
        left
    } else {
        value.split(':').collect()
    };
    raw.into_iter()
        .map(|group| format!("{group:0>4}"))
        .collect()
}

fn segment(group: &str) -> u16 {
    let prefix = group.split_once('.').map_or(group, |(first, _)| first);
    u16::from_str_radix(prefix, 16).unwrap_or_default()
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
